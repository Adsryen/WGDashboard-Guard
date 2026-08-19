"""Service boundary for internal audit writes and administrator reads."""

from __future__ import annotations

from datetime import datetime, timezone
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


def _isoformat(value: datetime | None) -> str | None:
    return value.replace(tzinfo=None).isoformat(timespec="seconds") + "Z" if value else None
