"""Standalone, local-only network audit alert evaluation and delivery."""

from __future__ import annotations

import argparse
import configparser
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import re
import signal
import time
from typing import Any, Callable, Mapping, Protocol

from .health import ConfigSyncStatus, HealthStatus, read_health_snapshot
from .service import NetworkAuditService, NetworkAuditServiceError
from .validation import AuditValidationError, normalize_utc


DEFAULT_AUDIT_DATABASE_PATH = "db/wgdashboard_audit.db"
DEFAULT_HEALTH_SNAPSHOT_PATH = "/run/wgd-network-audit/health.json"
DEFAULT_POLL_INTERVAL_SECONDS = 60
DEFAULT_HEALTH_TIMEOUT = timedelta(minutes=5)
ALERT_WINDOW = timedelta(minutes=5)
MAX_ERROR_SUMMARY_LENGTH = 512
MAX_POLL_INTERVAL_SECONDS = 3600
_EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_SECRET_PATTERN = re.compile(r"(?i)\b(password|passwd|secret|token|authorization)\s*[:=]\s*[^\s,;]+")


class AlertConfigurationError(ValueError):
    """Raised when alert settings cannot be safely normalized."""


class AlertMailer(Protocol):
    def is_ready(self) -> bool: ...

    def send(self, receiver: str, subject: str, body: str) -> tuple[bool, str | None]: ...


@dataclass(frozen=True)
class AlertConfiguration:
    """Typed, shared interpretation of Dashboard alert configuration values."""

    alerts_enabled: bool = False
    recipient: str | None = None
    denied_threshold: int = 10
    scan_threshold: int = 20
    cooldown_minutes: int = 30
    alert_tested_at: datetime | None = None
    alert_tested_recipient: str | None = None
    alert_tested_smtp_ready: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.alerts_enabled, bool):
            raise AlertConfigurationError("alerts_enabled must be a boolean")
        recipient = _email_or_none(self.recipient, "recipient")
        test_recipient = _email_or_none(self.alert_tested_recipient, "alert_tested_recipient")
        for field in ("denied_threshold", "scan_threshold"):
            value = getattr(self, field)
            if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 100_000:
                raise AlertConfigurationError(f"{field} must be an integer between 1 and 100000")
        if (
            isinstance(self.cooldown_minutes, bool)
            or not isinstance(self.cooldown_minutes, int)
            or not 1 <= self.cooldown_minutes <= 1440
        ):
            raise AlertConfigurationError("cooldown_minutes must be an integer between 1 and 1440")
        if self.alert_tested_at is not None:
            try:
                tested_at = normalize_utc(self.alert_tested_at, "alert_tested_at")
            except AuditValidationError as error:
                raise AlertConfigurationError(str(error)) from error
            object.__setattr__(self, "alert_tested_at", tested_at)
        if not isinstance(self.alert_tested_smtp_ready, bool):
            raise AlertConfigurationError("alert_tested_smtp_ready must be a boolean")
        object.__setattr__(self, "recipient", recipient)
        object.__setattr__(self, "alert_tested_recipient", test_recipient)

    @property
    def cooldown(self) -> timedelta:
        return timedelta(minutes=self.cooldown_minutes)

    @property
    def delivery_enabled(self) -> bool:
        """Require a current recipient/SMTP test before a runner can send."""
        return bool(
            self.alerts_enabled
            and self.recipient
            and self.alert_tested_at
            and self.alert_tested_recipient == self.recipient
            and self.alert_tested_smtp_ready
        )

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "AlertConfiguration":
        if not isinstance(payload, Mapping):
            raise AlertConfigurationError("alert configuration must be an object")
        expected_fields = {
            "alerts_enabled", "recipient", "denied_threshold", "scan_threshold", "cooldown_minutes",
            "alert_tested_at", "alert_tested_recipient", "alert_tested_smtp_ready",
        }
        unknown_fields = set(payload) - expected_fields
        if unknown_fields:
            raise AlertConfigurationError(
                f"unsupported alert configuration fields: {', '.join(sorted(unknown_fields))}"
            )
        return cls(
            alerts_enabled=_as_bool(payload.get("alerts_enabled", False), "alerts_enabled"),
            recipient=payload.get("recipient"),
            denied_threshold=_as_integer(payload.get("denied_threshold", 10), "denied_threshold"),
            scan_threshold=_as_integer(payload.get("scan_threshold", 20), "scan_threshold"),
            cooldown_minutes=_as_integer(payload.get("cooldown_minutes", 30), "cooldown_minutes"),
            alert_tested_at=_as_timestamp(payload.get("alert_tested_at"), "alert_tested_at"),
            alert_tested_recipient=payload.get("alert_tested_recipient"),
            alert_tested_smtp_ready=_as_bool(payload.get("alert_tested_smtp_ready", False), "alert_tested_smtp_ready"),
        )

    @classmethod
    def from_sections(cls, sections: Mapping[str, Mapping[str, Any]]) -> "AlertConfiguration":
        if not isinstance(sections, Mapping):
            raise AlertConfigurationError("configuration sections must be an object")
        email = sections.get("Email", {})
        network_audit = sections.get("NetworkAudit", {})
        if not isinstance(email, Mapping) or not isinstance(network_audit, Mapping):
            raise AlertConfigurationError("Email and NetworkAudit sections must be objects")
        return cls.from_payload({
            "alerts_enabled": network_audit.get("alerts_enabled", False),
            "recipient": email.get("audit_alert_recipient"),
            "denied_threshold": network_audit.get("denied_threshold", 10),
            "scan_threshold": network_audit.get("scan_threshold", 20),
            "cooldown_minutes": network_audit.get("cooldown_minutes", 30),
            "alert_tested_at": network_audit.get("alert_tested_at"),
            "alert_tested_recipient": network_audit.get("alert_tested_recipient"),
            "alert_tested_smtp_ready": network_audit.get("alert_tested_smtp_ready", False),
        })


@dataclass(frozen=True)
class AlertEvent:
    identity: str
    alert_type: str
    observed_value: int
    threshold: int | None
    peer_public_key: str | None = None
    peer_name_snapshot: str | None = None
    tunnel_address: str | None = None
    detail: str | None = None

    def __post_init__(self) -> None:
        if self.alert_type not in {"denied", "scan", "collector_health", "storage_write"}:
            raise ValueError("unsupported alert type")
        if not isinstance(self.identity, str) or not self.identity or len(self.identity) > 96:
            raise ValueError("alert identity must be a non-empty string up to 96 characters")
        if isinstance(self.observed_value, bool) or not isinstance(self.observed_value, int) or self.observed_value < 0:
            raise ValueError("observed_value must be a zero or greater integer")
        if self.threshold is not None and (
            isinstance(self.threshold, bool) or not isinstance(self.threshold, int) or self.threshold < 1
        ):
            raise ValueError("threshold must be null or a positive integer")
        if self.detail is not None:
            object.__setattr__(self, "detail", bounded_error(self.detail))


@dataclass(frozen=True)
class AlertRunResult:
    evaluated_at: datetime
    events_detected: int
    claims_created: int
    deliveries_succeeded: int
    deliveries_failed: int
    error_summary: str | None = None


class _ConfigFileAdapter:
    """Minimal EmailSender config interface without importing the Flask application."""

    def __init__(self, parser: configparser.RawConfigParser):
        self._parser = parser

    def GetConfig(self, section: str, key: str) -> tuple[bool, str | bool | None]:
        if not self._parser.has_option(section, key):
            return False, None
        value = self._parser.get(section, key)
        if value.lower() in {"1", "yes", "true", "on"}:
            return True, True
        if value.lower() in {"0", "no", "false", "off"}:
            return True, False
        return True, value


def load_alert_configuration(path: str | os.PathLike[str] | None = None) -> AlertConfiguration:
    """Read the Dashboard INI directly so the systemd runner never imports Flask."""
    configuration_path = Path(path or _default_configuration_path())
    parser = _read_config_parser(configuration_path)
    sections = {
        "Email": dict(parser.items("Email")) if parser.has_section("Email") else {},
        "NetworkAudit": dict(parser.items("NetworkAudit")) if parser.has_section("NetworkAudit") else {},
    }
    return AlertConfiguration.from_sections(sections)


def create_email_sender(path: str | os.PathLike[str] | None = None) -> AlertMailer:
    """Reuse the established SMTP sender with a read-only INI-backed config facade."""
    from modules.Email import EmailSender

    parser = _read_config_parser(Path(path or _default_configuration_path()))
    return EmailSender(_ConfigFileAdapter(parser))


def evaluate_health_snapshot(
    path: str | os.PathLike[str],
    *,
    now: datetime | None = None,
    timeout: timedelta = DEFAULT_HEALTH_TIMEOUT,
) -> list[AlertEvent]:
    if not isinstance(timeout, timedelta) or timeout <= timedelta(0):
        raise ValueError("timeout must be a positive timedelta")
    current_time = normalize_utc(now or datetime.now(timezone.utc), "now")
    snapshot_path = Path(path)
    try:
        modified_at = datetime.fromtimestamp(snapshot_path.stat().st_mtime, timezone.utc).replace(tzinfo=None)
        snapshot = read_health_snapshot(snapshot_path)
    except FileNotFoundError:
        return [AlertEvent("collector_health", "collector_health", 1, None, detail="health snapshot is missing")]
    except (OSError, ValueError, AuditValidationError) as error:
        return [AlertEvent("collector_health", "collector_health", 1, None, detail=bounded_error(error))]

    events: list[AlertEvent] = []
    if current_time - modified_at > timeout:
        events.append(AlertEvent("collector_health", "collector_health", 1, None, detail="health snapshot is stale"))
    elif snapshot.status in {HealthStatus.DEGRADED, HealthStatus.FAILED}:
        events.append(AlertEvent("collector_health", "collector_health", 1, None, detail=f"collector status is {snapshot.status.value}"))
    elif snapshot.config_sync_status == ConfigSyncStatus.FAILED:
        events.append(AlertEvent("collector_health", "collector_health", 1, None, detail="collector configuration synchronization failed"))
    if snapshot.write_failures > 0:
        events.append(AlertEvent(
            "storage_write", "storage_write", snapshot.write_failures, None,
            detail="collector audit storage writes are failing",
        ))
    return events


class NetworkAuditAlertRunner:
    """Evaluates bounded audit metadata and delivers deduplicated local email alerts."""

    def __init__(
        self,
        service: NetworkAuditService,
        *,
        configuration_provider: Callable[[], AlertConfiguration],
        health_path: str | os.PathLike[str] = DEFAULT_HEALTH_SNAPSHOT_PATH,
        email_sender_factory: Callable[[], AlertMailer] | None = None,
        health_timeout: timedelta = DEFAULT_HEALTH_TIMEOUT,
    ):
        self.service = service
        self.configuration_provider = configuration_provider
        self.health_path = Path(health_path)
        self.email_sender_factory = email_sender_factory
        self.health_timeout = health_timeout

    def run_once(self, now: datetime | None = None) -> AlertRunResult:
        current_time = normalize_utc(now or datetime.now(timezone.utc), "now").replace(tzinfo=timezone.utc)
        try:
            configuration = self.configuration_provider()
            if not isinstance(configuration, AlertConfiguration):
                raise AlertConfigurationError("configuration_provider must return AlertConfiguration")
        except Exception as error:
            summary = bounded_error(error)
            self._record_run(current_time, False, 0, 0, summary)
            return AlertRunResult(current_time, 0, 0, 0, 0, summary)

        events = evaluate_health_snapshot(self.health_path, now=current_time, timeout=self.health_timeout)
        try:
            events.extend(self._activity_events(configuration, current_time))
        except (NetworkAuditServiceError, ValueError) as error:
            summary = bounded_error(error)
            self._record_run(current_time, configuration.delivery_enabled, len(events), 0, summary)
            return AlertRunResult(current_time, len(events), 0, 0, 0, summary)

        if not configuration.delivery_enabled:
            self._record_run(current_time, False, len(events), 0, None)
            return AlertRunResult(current_time, len(events), 0, 0, 0)

        try:
            sender = self._sender()
            if not sender.is_ready():
                summary = "SMTP not configured"
                self._record_run(current_time, True, len(events), 0, summary)
                return AlertRunResult(current_time, len(events), 0, 0, 0, summary)
        except Exception as error:
            summary = bounded_error(error)
            self._record_run(current_time, True, len(events), 0, summary)
            return AlertRunResult(current_time, len(events), 0, 0, 0, summary)

        claims_created = 0
        deliveries_succeeded = 0
        deliveries_failed = 0
        for event in events:
            try:
                delivery_id = self.service.claim_alert(
                    identity=event.identity,
                    alert_type=event.alert_type,
                    cooldown=configuration.cooldown,
                    now=current_time,
                    peer_public_key=event.peer_public_key,
                    peer_name_snapshot=event.peer_name_snapshot,
                    tunnel_address=event.tunnel_address,
                )
            except (NetworkAuditServiceError, ValueError) as error:
                summary = bounded_error(error)
                self._record_run(current_time, True, len(events), claims_created, summary)
                return AlertRunResult(current_time, len(events), claims_created, deliveries_succeeded, deliveries_failed, summary)
            if delivery_id is None:
                continue
            claims_created += 1
            try:
                succeeded, message = sender.send(
                    configuration.recipient or "", _alert_subject(event), _alert_body(event, current_time)
                )
                error_summary = None if succeeded else bounded_error(message or "SMTP delivery failed")
            except Exception as error:
                succeeded = False
                error_summary = bounded_error(error)
            try:
                self.service.complete_alert_delivery(
                    delivery_id, succeeded=succeeded, error_summary=error_summary, now=current_time
                )
            except (NetworkAuditServiceError, ValueError) as error:
                summary = bounded_error(error)
                self._record_run(current_time, True, len(events), claims_created, summary)
                return AlertRunResult(current_time, len(events), claims_created, deliveries_succeeded, deliveries_failed, summary)
            if succeeded:
                deliveries_succeeded += 1
            else:
                deliveries_failed += 1
        self._record_run(current_time, True, len(events), claims_created, None)
        return AlertRunResult(current_time, len(events), claims_created, deliveries_succeeded, deliveries_failed)

    def _activity_events(self, configuration: AlertConfiguration, now: datetime) -> list[AlertEvent]:
        events: list[AlertEvent] = []
        for candidate in self.service.alert_candidates(now=now, window=ALERT_WINDOW):
            observed_value = int(candidate["ObservedValue"])
            alert_type = candidate["alert_type"]
            threshold = configuration.denied_threshold if alert_type == "denied" else configuration.scan_threshold
            if observed_value < threshold:
                continue
            peer_public_key = candidate["PeerPublicKey"]
            events.append(AlertEvent(
                identity=f"{alert_type}:{peer_public_key}",
                alert_type=alert_type,
                observed_value=observed_value,
                threshold=threshold,
                peer_public_key=peer_public_key,
                peer_name_snapshot=candidate["PeerNameSnapshot"],
                tunnel_address=candidate["TunnelAddress"],
            ))
        return events

    def _sender(self) -> AlertMailer:
        if self.email_sender_factory is None:
            raise AlertConfigurationError("email_sender_factory is required")
        return self.email_sender_factory()

    def _record_run(
        self,
        now: datetime,
        enabled: bool,
        events_detected: int,
        claims_created: int,
        error_summary: str | None,
    ) -> None:
        try:
            self.service.record_alert_run(
                alerts_enabled=enabled,
                events_detected=events_detected,
                claims_created=claims_created,
                error_summary=error_summary,
                now=now,
            )
        except (NetworkAuditServiceError, ValueError):
            pass


def bounded_error(error: object, maximum: int = MAX_ERROR_SUMMARY_LENGTH) -> str:
    """Keep operational errors useful without persisting secrets or unbounded text."""
    value = " ".join(str(error).replace("\x00", " ").split())
    value = _SECRET_PATTERN.sub("[redacted]", value)
    if not value:
        value = "unknown error"
    return value[:maximum]


def _alert_subject(event: AlertEvent) -> str:
    return f"[WGDashboard] Network audit alert: {event.alert_type}"


def _alert_body(event: AlertEvent, now: datetime) -> str:
    lines = [
        "WGDashboard network audit alert",
        "",
        f"Detected at (UTC): {now.isoformat()}",
        f"Alert type: {event.alert_type}",
        f"Observed value: {event.observed_value}",
    ]
    if event.threshold is not None:
        lines.append(f"Threshold: {event.threshold}")
    if event.peer_public_key:
        lines.append(f"Peer public key: {event.peer_public_key}")
    if event.peer_name_snapshot:
        lines.append(f"Peer name snapshot: {event.peer_name_snapshot}")
    if event.tunnel_address:
        lines.append(f"Tunnel address: {event.tunnel_address}")
    if event.detail:
        lines.append(f"Detail: {event.detail}")
    lines.extend(("", "Policy verdicts describe gateway observation or policy decisions, not remote application success."))
    return "\n".join(lines)


def _as_bool(value: Any, field: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes", "on"}:
            return True
        if normalized in {"false", "0", "no", "off", ""}:
            return False
    raise AlertConfigurationError(f"{field} must be a boolean")


def _as_integer(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise AlertConfigurationError(f"{field} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    raise AlertConfigurationError(f"{field} must be an integer")


def _as_timestamp(value: Any, field: str) -> datetime | None:
    if value in (None, ""):
        return None
    if isinstance(value, str):
        try:
            return normalize_utc(value, field).replace(tzinfo=timezone.utc)
        except AuditValidationError as error:
            raise AlertConfigurationError(str(error)) from error
    if isinstance(value, datetime):
        return value
    raise AlertConfigurationError(f"{field} must be an ISO-8601 timestamp")


def _email_or_none(value: Any, field: str) -> str | None:
    if value in (None, ""):
        return None
    if not isinstance(value, str) or len(value) > 254 or not _EMAIL_PATTERN.fullmatch(value):
        raise AlertConfigurationError(f"{field} must be a single valid email address")
    return value


def _read_config_parser(path: Path) -> configparser.RawConfigParser:
    parser = configparser.RawConfigParser(strict=False)
    try:
        with path.open(encoding="utf-8") as configuration_file:
            parser.read_file(configuration_file)
    except (OSError, configparser.Error) as error:
        raise AlertConfigurationError(f"unable to read Dashboard configuration: {bounded_error(error)}") from error
    return parser


def _default_configuration_path() -> Path:
    return Path(os.getenv("CONFIGURATION_PATH", ".")) / "wg-dashboard.ini"


def _default_health_snapshot_path() -> str:
    return os.getenv(
        "WGD_NETWORK_AUDIT_HEALTH_PATH",
        os.getenv("WGD_AUDIT_HEALTH_PATH", DEFAULT_HEALTH_SNAPSHOT_PATH),
    )


def _parse_poll_interval(value: str) -> int:
    try:
        interval = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("interval must be an integer") from error
    if not 5 <= interval <= MAX_POLL_INTERVAL_SECONDS:
        raise argparse.ArgumentTypeError(f"interval must be between 5 and {MAX_POLL_INTERVAL_SECONDS} seconds")
    return interval


def main() -> None:
    parser = argparse.ArgumentParser(description="WGDashboard Network Audit Alert Runner")
    parser.add_argument(
        "--database", default=os.getenv("WGD_AUDIT_DATABASE_PATH", DEFAULT_AUDIT_DATABASE_PATH),
        help="audit SQLite path (default: WGD_AUDIT_DATABASE_PATH or db/wgdashboard_audit.db)",
    )
    parser.add_argument(
        "--health", default=_default_health_snapshot_path(),
        help="read-only collector health snapshot path",
    )
    parser.add_argument(
        "--config", default=str(_default_configuration_path()),
        help="Dashboard wg-dashboard.ini path (default: CONFIGURATION_PATH/wg-dashboard.ini)",
    )
    parser.add_argument(
        "--interval-seconds", type=_parse_poll_interval, default=DEFAULT_POLL_INTERVAL_SECONDS,
        help=f"polling interval, 5-{MAX_POLL_INTERVAL_SECONDS} seconds (default: {DEFAULT_POLL_INTERVAL_SECONDS})",
    )
    parser.add_argument("--once", action="store_true", help="evaluate once and exit")
    arguments = parser.parse_args()

    service = NetworkAuditService(arguments.database)
    runner = NetworkAuditAlertRunner(
        service,
        configuration_provider=lambda: load_alert_configuration(arguments.config),
        health_path=arguments.health,
        email_sender_factory=lambda: create_email_sender(arguments.config),
    )
    stop_requested = False

    def request_stop(_signal: int, _frame: Any) -> None:
        nonlocal stop_requested
        stop_requested = True

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)
    try:
        while not stop_requested:
            runner.run_once()
            if arguments.once:
                break
            for _ in range(arguments.interval_seconds):
                if stop_requested:
                    break
                time.sleep(1)
    finally:
        service.engine.dispose()


if __name__ == "__main__":
    main()
