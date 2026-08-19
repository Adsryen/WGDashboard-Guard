"""Service boundary for internal audit writes and administrator reads."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from typing import Any

import sqlalchemy as db
from sqlalchemy import event
from sqlalchemy.exc import SQLAlchemyError

from .repository import NetworkAuditRepository
from .validation import AuditObservation, AuditQuery, AuditValidationError, MAX_QUERY_RESULTS, normalize_utc


DETAIL_RETENTION_DAYS = 180
AGGREGATE_RETENTION_MONTHS = 24


class NetworkAuditServiceError(RuntimeError):
    """Raised when the independent audit database is unavailable."""


class NetworkAuditService:
    """Provides validated writes without exposing an HTTP audit-ingest endpoint."""

    def __init__(self, database_path: str | os.PathLike[str] | None = None, engine: db.Engine | None = None):
        if engine is not None and database_path is not None:
            raise ValueError("provide either database_path or engine, not both")
        try:
            self.engine = engine or self._create_engine(database_path)
            self.repository = NetworkAuditRepository(self.engine)
        except (OSError, SQLAlchemyError, RuntimeError) as error:
            raise NetworkAuditServiceError("audit database is unavailable") from error

    @staticmethod
    def _create_engine(database_path: str | os.PathLike[str] | None) -> db.Engine:
        path = Path(database_path or os.getenv("WGD_AUDIT_DATABASE_PATH", "db/wgdashboard_audit.db"))
        path.parent.mkdir(parents=True, exist_ok=True)
        engine = db.create_engine(
            db.URL.create("sqlite", database=str(path)),
            connect_args={"check_same_thread": False},
        )

        @event.listens_for(engine, "connect")
        def configure_sqlite(connection: Any, _connection_record: Any) -> None:
            connection.execute("PRAGMA busy_timeout = 5000")

        return engine

    def record_observation(self, observation: AuditObservation | dict[str, Any]) -> None:
        if not isinstance(observation, AuditObservation):
            observation = AuditObservation.from_payload(observation)
        try:
            self.repository.record_observation(observation)
        except SQLAlchemyError as error:
            raise NetworkAuditServiceError("audit database is unavailable") from error

    def query(self, query: AuditQuery | dict[str, Any]) -> dict[str, Any]:
        if not isinstance(query, AuditQuery):
            query = AuditQuery.from_payload(query)
        try:
            records, total = self.repository.query(query)
        except SQLAlchemyError as error:
            raise NetworkAuditServiceError("audit database is unavailable") from error
        return {
            "records": records,
            "pagination": {
                "page": query.page,
                "page_size": query.page_size,
                "total": min(total, MAX_QUERY_RESULTS),
                "total_capped": total > MAX_QUERY_RESULTS,
            },
        }

    def summary(self, query: AuditQuery | dict[str, Any]) -> dict[str, Any]:
        if not isinstance(query, AuditQuery):
            query = AuditQuery.from_payload(query)
        try:
            summary = self.repository.summary(query)
        except SQLAlchemyError as error:
            raise NetworkAuditServiceError("audit database is unavailable") from error
        return {
            "window_count": summary["WindowCount"],
            "connection_count": summary["ConnectionCount"],
            "bytes_from_peer": summary["BytesFromPeer"],
            "bytes_to_peer": summary["BytesToPeer"],
            "latest_window_started_at": _isoformat(summary["LatestWindowStartedAt"]),
        }

    def cleanup_retention(self, now: datetime | None = None) -> dict[str, int]:
        normalized_now = normalize_utc(now or datetime.now(timezone.utc), "now")
        try:
            return self.repository.cleanup_retention(
                normalized_now, DETAIL_RETENTION_DAYS, AGGREGATE_RETENTION_MONTHS
            )
        except SQLAlchemyError as error:
            raise NetworkAuditServiceError("audit database is unavailable") from error

    def alert_candidates(self, now: datetime | None = None, window: timedelta = timedelta(minutes=5)) -> list[dict[str, Any]]:
        if not isinstance(window, timedelta) or window <= timedelta(0):
            raise ValueError("window must be a positive timedelta")
        normalized_now = normalize_utc(now or datetime.now(timezone.utc), "now")
        try:
            return self.repository.alert_candidates(normalized_now - window, normalized_now)
        except SQLAlchemyError as error:
            raise NetworkAuditServiceError("audit database is unavailable") from error

    def claim_alert(
        self,
        *,
        identity: str,
        alert_type: str,
        cooldown: timedelta,
        now: datetime | None = None,
        peer_public_key: str | None = None,
        peer_name_snapshot: str | None = None,
        tunnel_address: str | None = None,
    ) -> str | None:
        if not isinstance(identity, str) or not identity or len(identity) > 96:
            raise ValueError("identity must be a non-empty string up to 96 characters")
        if not isinstance(alert_type, str) or not alert_type or len(alert_type) > 32:
            raise ValueError("alert_type must be a non-empty string up to 32 characters")
        if not isinstance(cooldown, timedelta) or cooldown < timedelta(0):
            raise ValueError("cooldown must be a zero or greater timedelta")
        normalized_now = normalize_utc(now or datetime.now(timezone.utc), "now")
        try:
            return self.repository.claim_alert(
                identity=identity,
                alert_type=alert_type,
                now=normalized_now,
                cooldown=cooldown,
                peer_public_key=peer_public_key,
                peer_name_snapshot=peer_name_snapshot,
                tunnel_address=tunnel_address,
            )
        except SQLAlchemyError as error:
            raise NetworkAuditServiceError("audit database is unavailable") from error

    def complete_alert_delivery(
        self,
        delivery_id: str,
        *,
        succeeded: bool,
        error_summary: str | None = None,
        now: datetime | None = None,
    ) -> None:
        if not isinstance(delivery_id, str) or not delivery_id:
            raise ValueError("delivery_id must be a non-empty string")
        if not isinstance(succeeded, bool):
            raise ValueError("succeeded must be a boolean")
        if error_summary is not None and (not isinstance(error_summary, str) or len(error_summary) > 512):
            raise ValueError("error_summary must be null or a string up to 512 characters")
        normalized_now = normalize_utc(now or datetime.now(timezone.utc), "now")
        try:
            self.repository.complete_alert_delivery(
                delivery_id,
                delivered_at=normalized_now,
                succeeded=succeeded,
                error_summary=error_summary,
            )
        except SQLAlchemyError as error:
            raise NetworkAuditServiceError("audit database is unavailable") from error

    def record_alert_run(
        self,
        *,
        alerts_enabled: bool,
        events_detected: int,
        claims_created: int,
        error_summary: str | None = None,
        now: datetime | None = None,
    ) -> None:
        if not isinstance(alerts_enabled, bool):
            raise ValueError("alerts_enabled must be a boolean")
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in (events_detected, claims_created)):
            raise ValueError("alert run counts must be zero or greater integers")
        if error_summary is not None and (not isinstance(error_summary, str) or len(error_summary) > 512):
            raise ValueError("error_summary must be null or a string up to 512 characters")
        normalized_now = normalize_utc(now or datetime.now(timezone.utc), "now")
        try:
            self.repository.record_alert_run(
                ran_at=normalized_now,
                alerts_enabled=alerts_enabled,
                events_detected=events_detected,
                claims_created=claims_created,
                error_summary=error_summary,
            )
        except SQLAlchemyError as error:
            raise NetworkAuditServiceError("audit database is unavailable") from error

    def alert_status(self) -> dict[str, Any]:
        try:
            status = self.repository.alert_status()
        except SQLAlchemyError as error:
            raise NetworkAuditServiceError("audit database is unavailable") from error
        latest_run = _serialize_alert_row(status["latest_run"])
        latest_delivery = _serialize_alert_row(status["latest_delivery"])
        return {
            "last_evaluated_at": latest_run["ran_at"] if latest_run else None,
            "last_delivery_at": latest_delivery["delivered_at"] if latest_delivery else None,
            "last_delivery_succeeded": latest_delivery["succeeded"] if latest_delivery else None,
            "last_error_summary": (
                latest_delivery["error_summary"] if latest_delivery and latest_delivery["error_summary"]
                else latest_run["error_summary"] if latest_run else None
            ),
            "latest_run": latest_run,
            "latest_delivery": latest_delivery,
        }


def _isoformat(value: datetime | None) -> str | None:
    return value.replace(tzinfo=None).isoformat(timespec="seconds") + "Z" if value else None


def _serialize_alert_row(row: Any) -> dict[str, Any] | None:
    if row is None:
        return None
    return {
        _snake_case(key): _isoformat(value) if isinstance(value, datetime) else value
        for key, value in dict(row).items()
    }


def _snake_case(value: str) -> str:
    return "".join(
        ("_" if index and character.isupper() and not value[index - 1].isupper() else "") + character.lower()
        for index, character in enumerate(value)
    )
