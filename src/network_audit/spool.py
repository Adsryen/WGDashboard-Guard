"""A bounded SQLite retry spool containing validated audit observations only."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
from typing import Callable

from .validation import AuditObservation


@dataclass(frozen=True)
class SpoolStats:
    records: int
    bytes: int
    dropped_records: int


@dataclass(frozen=True)
class SpoolItem:
    item_id: int
    observation: AuditObservation
    attempts: int
    next_attempt_at: datetime


@dataclass(frozen=True)
class SpoolEnqueueResult:
    item_id: int | None
    dropped_records: int


class AuditSpool:
    """SQLite spool with transactional oldest-first eviction and retry metadata."""

    def __init__(
        self,
        database_path: str | Path,
        *,
        max_records: int = 10_000,
        max_bytes: int = 16 * 1024 * 1024,
        max_payload_bytes: int = 8 * 1024,
    ) -> None:
        if max_records < 1 or max_bytes < 1 or max_payload_bytes < 1:
            raise ValueError("spool limits must be greater than zero")
        if max_payload_bytes > max_bytes:
            raise ValueError("max_payload_bytes cannot exceed max_bytes")
        self.max_records = max_records
        self.max_bytes = max_bytes
        self.max_payload_bytes = max_payload_bytes
        self.database_path = Path(database_path)
        if self.database_path != Path(":memory:"):
            self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._connection = sqlite3.connect(str(self.database_path))
        self._connection.row_factory = sqlite3.Row
        self._initialize()

    def close(self) -> None:
        self._connection.close()

    def enqueue(self, observation: AuditObservation, now: datetime | None = None) -> SpoolEnqueueResult:
        if not isinstance(observation, AuditObservation):
            raise TypeError("spool accepts validated AuditObservation instances only")
        serialized = self._serialize(observation)
        payload_size = len(serialized.encode("utf-8"))
        current_time = self._isoformat(now)
        with self._connection:
            if payload_size > self.max_payload_bytes or payload_size > self.max_bytes:
                self._increment_dropped_records(1)
                return SpoolEnqueueResult(item_id=None, dropped_records=1)

            dropped_records = self._evict_for(payload_size)
            cursor = self._connection.execute(
                """
                INSERT INTO AuditSpoolItems (Payload, PayloadBytes, Attempts, NextAttemptAt)
                VALUES (?, ?, 0, ?)
                """,
                (serialized, payload_size, current_time),
            )
        return SpoolEnqueueResult(item_id=int(cursor.lastrowid), dropped_records=dropped_records)

    def due_items(self, now: datetime | None = None, limit: int = 100) -> list[SpoolItem]:
        if limit < 1:
            raise ValueError("limit must be greater than zero")
        rows = self._connection.execute(
            """
            SELECT SpoolItemID, Payload, Attempts, NextAttemptAt
            FROM AuditSpoolItems
            WHERE NextAttemptAt <= ?
            ORDER BY SpoolItemID ASC
            LIMIT ?
            """,
            (self._isoformat(now), limit),
        ).fetchall()
        return [
            SpoolItem(
                item_id=row["SpoolItemID"],
                observation=AuditObservation.from_payload(json.loads(row["Payload"])),
                attempts=row["Attempts"],
                next_attempt_at=self._parse_timestamp(row["NextAttemptAt"]),
            )
            for row in rows
        ]

    def acknowledge(self, item_id: int) -> None:
        with self._connection:
            self._connection.execute("DELETE FROM AuditSpoolItems WHERE SpoolItemID = ?", (item_id,))

    def retry(self, item_id: int, next_attempt_at: datetime) -> None:
        with self._connection:
            self._connection.execute(
                """
                UPDATE AuditSpoolItems
                SET Attempts = Attempts + 1, NextAttemptAt = ?
                WHERE SpoolItemID = ?
                """,
                (self._isoformat(next_attempt_at), item_id),
            )

    def stats(self) -> SpoolStats:
        row = self._connection.execute(
            "SELECT COUNT(*) AS Records, COALESCE(SUM(PayloadBytes), 0) AS Bytes FROM AuditSpoolItems"
        ).fetchone()
        dropped = self._connection.execute(
            "SELECT Value FROM AuditSpoolState WHERE Name = 'dropped_records'"
        ).fetchone()["Value"]
        return SpoolStats(records=row["Records"], bytes=row["Bytes"], dropped_records=int(dropped))

    def flush(
        self,
        writer: Callable[[AuditObservation], None],
        *,
        now: datetime | None = None,
        limit: int = 100,
        retry_at: datetime | None = None,
    ) -> int:
        persisted = 0
        for item in self.due_items(now=now, limit=limit):
            try:
                writer(item.observation)
            except Exception:
                self.retry(item.item_id, retry_at or now or datetime.now(timezone.utc))
                break
            self.acknowledge(item.item_id)
            persisted += 1
        return persisted

    def _initialize(self) -> None:
        with self._connection:
            self._connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS AuditSpoolItems (
                    SpoolItemID INTEGER PRIMARY KEY,
                    Payload TEXT NOT NULL,
                    PayloadBytes INTEGER NOT NULL,
                    Attempts INTEGER NOT NULL DEFAULT 0,
                    NextAttemptAt TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS AuditSpoolState (
                    Name TEXT PRIMARY KEY,
                    Value INTEGER NOT NULL
                );
                INSERT OR IGNORE INTO AuditSpoolState (Name, Value) VALUES ('dropped_records', 0);
                """
            )

    def _evict_for(self, payload_size: int) -> int:
        dropped_records = 0
        while True:
            row = self._connection.execute(
                "SELECT COUNT(*) AS Records, COALESCE(SUM(PayloadBytes), 0) AS Bytes FROM AuditSpoolItems"
            ).fetchone()
            if row["Records"] < self.max_records and row["Bytes"] + payload_size <= self.max_bytes:
                break
            oldest = self._connection.execute(
                "SELECT SpoolItemID FROM AuditSpoolItems ORDER BY SpoolItemID ASC LIMIT 1"
            ).fetchone()
            if oldest is None:
                break
            self._connection.execute("DELETE FROM AuditSpoolItems WHERE SpoolItemID = ?", (oldest["SpoolItemID"],))
            dropped_records += 1
        if dropped_records:
            self._increment_dropped_records(dropped_records)
        return dropped_records

    def _increment_dropped_records(self, amount: int) -> None:
        self._connection.execute(
            "UPDATE AuditSpoolState SET Value = Value + ? WHERE Name = 'dropped_records'", (amount,)
        )

    @staticmethod
    def _serialize(observation: AuditObservation) -> str:
        payload = {
            "configuration_name": observation.configuration_name,
            "peer_public_key": observation.peer_public_key,
            "peer_name_snapshot": observation.peer_name_snapshot,
            "tunnel_address": observation.tunnel_address,
            "destination_address": observation.destination_address,
            "protocol": observation.protocol,
            "destination_port": observation.destination_port,
            "decision": observation.decision.value,
            "observed_at": observation.observed_at.replace(tzinfo=timezone.utc).isoformat(),
            "connection_increment": observation.connection_increment,
            "bytes_from_peer": observation.bytes_from_peer,
            "bytes_to_peer": observation.bytes_to_peer,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _isoformat(value: datetime | None) -> str:
        current_time = value or datetime.now(timezone.utc)
        if current_time.tzinfo is None or current_time.utcoffset() is None:
            raise ValueError("timestamps must include a timezone")
        return current_time.astimezone(timezone.utc).isoformat()

    @staticmethod
    def _parse_timestamp(value: str) -> datetime:
        return datetime.fromisoformat(value).astimezone(timezone.utc)
