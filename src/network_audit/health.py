"""Atomic, local-only collector health snapshots."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import json
import os
from pathlib import Path
import tempfile
from typing import Any, Mapping

from .validation import AuditValidationError, normalize_utc


class HealthStatus(str, Enum):
    STARTING = "starting"
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"


class ConfigSyncStatus(str, Enum):
    UNKNOWN = "unknown"
    APPLIED = "applied"
    FAILED = "failed"


def _timestamp(value: datetime | None, field: str) -> datetime | None:
    if value is None:
        return None
    return normalize_utc(value, field).replace(tzinfo=timezone.utc)


def _counter(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AuditValidationError(f"{field} must be a zero or greater integer")
    return value


@dataclass(frozen=True)
class HealthSnapshot:
    status: HealthStatus | str
    started_at: datetime
    last_event_at: datetime | None = None
    last_persisted_at: datetime | None = None
    spool_records: int = 0
    spool_bytes: int = 0
    dropped_records: int = 0
    nflog_events: int = 0
    conntrack_events: int = 0
    correlation_timeouts: int = 0
    incomplete_flows: int = 0
    write_failures: int = 0
    last_error: str | None = None
    config_generation: int = 0
    config_sync_status: ConfigSyncStatus | str = ConfigSyncStatus.UNKNOWN
    config_sync_at: datetime | None = None
    config_sync_generation: int = 0
    config_sync_error: str | None = None

    def __post_init__(self) -> None:
        try:
            status = HealthStatus(self.status)
        except ValueError as error:
            raise AuditValidationError("status must be starting, healthy, degraded, or failed") from error
        if self.last_error is not None and (not isinstance(self.last_error, str) or len(self.last_error) > 255):
            raise AuditValidationError("last_error must be null or a string up to 255 characters")
        started_at = _timestamp(self.started_at, "started_at")
        if started_at is None:
            raise AuditValidationError("started_at must be an ISO-8601 timestamp")
        object.__setattr__(self, "status", status)
        object.__setattr__(self, "started_at", started_at)
        object.__setattr__(self, "last_event_at", _timestamp(self.last_event_at, "last_event_at"))
        object.__setattr__(self, "last_persisted_at", _timestamp(self.last_persisted_at, "last_persisted_at"))
        try:
            config_sync_status = ConfigSyncStatus(self.config_sync_status)
        except ValueError as error:
            raise AuditValidationError("config_sync_status must be unknown, applied, or failed") from error
        if self.config_sync_error is not None and (
            not isinstance(self.config_sync_error, str) or len(self.config_sync_error) > 255
        ):
            raise AuditValidationError("config_sync_error must be null or a string up to 255 characters")
        object.__setattr__(self, "config_sync_status", config_sync_status)
        object.__setattr__(self, "config_sync_at", _timestamp(self.config_sync_at, "config_sync_at"))
        object.__setattr__(self, "config_sync_error", self.config_sync_error)
        for field in (
            "spool_records", "spool_bytes", "dropped_records", "nflog_events", "conntrack_events",
            "correlation_timeouts", "incomplete_flows", "write_failures", "config_generation",
            "config_sync_generation",
        ):
            object.__setattr__(self, field, _counter(getattr(self, field), field))

    def to_payload(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "started_at": _isoformat(self.started_at),
            "last_event_at": _isoformat(self.last_event_at),
            "last_persisted_at": _isoformat(self.last_persisted_at),
            "spool_records": self.spool_records,
            "spool_bytes": self.spool_bytes,
            "dropped_records": self.dropped_records,
            "nflog_events": self.nflog_events,
            "conntrack_events": self.conntrack_events,
            "correlation_timeouts": self.correlation_timeouts,
            "incomplete_flows": self.incomplete_flows,
            "write_failures": self.write_failures,
            "last_error": self.last_error,
            "config_generation": self.config_generation,
            "config_sync_status": self.config_sync_status.value,
            "config_sync_at": _isoformat(self.config_sync_at),
            "config_sync_generation": self.config_sync_generation,
            "config_sync_error": self.config_sync_error,
        }

    @classmethod
    def from_payload(cls, payload: Any) -> "HealthSnapshot":
        if not isinstance(payload, Mapping):
            raise AuditValidationError("health snapshot must be an object")
        expected_fields = {
            "status", "started_at", "last_event_at", "last_persisted_at", "spool_records", "spool_bytes",
            "dropped_records", "nflog_events", "conntrack_events", "correlation_timeouts", "incomplete_flows",
            "write_failures", "last_error", "config_generation", "config_sync_status", "config_sync_at",
            "config_sync_generation", "config_sync_error",
        }
        unknown_fields = set(payload) - expected_fields
        if unknown_fields:
            raise AuditValidationError(f"unsupported health snapshot fields: {', '.join(sorted(unknown_fields))}")
        return cls(**{field: payload.get(field) for field in expected_fields if field in payload})


def write_health_snapshot(path: str | Path, snapshot: HealthSnapshot) -> None:
    """Atomically replace a health file without exposing partial JSON to readers."""
    if not isinstance(snapshot, HealthSnapshot):
        raise TypeError("snapshot must be a HealthSnapshot")
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_path = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent, text=True)
    try:
        os.fchmod(descriptor, 0o640)
        with os.fdopen(descriptor, "w", encoding="utf-8") as health_file:
            json.dump(snapshot.to_payload(), health_file, sort_keys=True, separators=(",", ":"))
            health_file.write("\n")
            health_file.flush()
            os.fsync(health_file.fileno())
        os.replace(temporary_path, target)
    finally:
        if os.path.exists(temporary_path):
            os.unlink(temporary_path)


def read_health_snapshot(path: str | Path) -> HealthSnapshot:
    with Path(path).open(encoding="utf-8") as health_file:
        return HealthSnapshot.from_payload(json.load(health_file))


def write_config_sync_snapshot(path: str | Path, snapshot: Mapping[str, Any]) -> None:
    """Atomically publish the Dashboard's latest audit-agent synchronization result."""
    expected_fields = {"status", "updated_at", "generation", "error"}
    if set(snapshot) != expected_fields:
        raise AuditValidationError("config sync snapshot fields are invalid")
    try:
        status = ConfigSyncStatus(snapshot["status"])
    except ValueError as error:
        raise AuditValidationError("config sync status must be unknown, applied, or failed") from error
    updated_at = normalize_utc(snapshot["updated_at"], "updated_at").replace(tzinfo=timezone.utc)
    generation = _counter(snapshot["generation"], "generation")
    error = snapshot["error"]
    if error is not None and (not isinstance(error, str) or len(error) > 255):
        raise AuditValidationError("config sync error must be null or a string up to 255 characters")
    payload = {
        "status": status.value,
        "updated_at": _isoformat(updated_at),
        "generation": generation,
        "error": error,
    }
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_path = tempfile.mkstemp(prefix=f".{target.name}.", dir=target.parent, text=True)
    try:
        os.fchmod(descriptor, 0o640)
        with os.fdopen(descriptor, "w", encoding="utf-8") as sync_file:
            json.dump(payload, sync_file, sort_keys=True, separators=(",", ":"))
            sync_file.write("\n")
            sync_file.flush()
            os.fsync(sync_file.fileno())
        os.replace(temporary_path, target)
    finally:
        if os.path.exists(temporary_path):
            os.unlink(temporary_path)


def read_config_sync_snapshot(path: str | Path) -> dict[str, Any] | None:
    try:
        with Path(path).open(encoding="utf-8") as sync_file:
            payload = json.load(sync_file)
    except FileNotFoundError:
        return None
    expected_fields = {"status", "updated_at", "generation", "error"}
    if not isinstance(payload, Mapping) or set(payload) != expected_fields:
        raise AuditValidationError("config sync snapshot is invalid")
    try:
        status = ConfigSyncStatus(payload["status"])
    except ValueError as error:
        raise AuditValidationError("config sync status must be unknown, applied, or failed") from error
    updated_at = normalize_utc(payload["updated_at"], "updated_at").replace(tzinfo=timezone.utc)
    generation = _counter(payload["generation"], "generation")
    error = payload["error"]
    if error is not None and (not isinstance(error, str) or len(error) > 255):
        raise AuditValidationError("config sync error must be null or a string up to 255 characters")
    return {"status": status, "updated_at": updated_at, "generation": generation, "error": error}


def _isoformat(value: datetime | None) -> str | None:
    if value is None:
        return None
    return value.astimezone(timezone.utc).isoformat()
