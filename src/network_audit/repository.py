"""Isolated SQLAlchemy persistence for network audit windows and aggregates."""

from __future__ import annotations

import calendar
from datetime import date, datetime, timedelta, timezone
import uuid
from typing import Any

import sqlalchemy as db
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from .validation import AuditObservation, AuditQuery, address_sort_key


SCHEMA_VERSION = 1
WINDOW_DURATION = timedelta(minutes=5)


class NetworkAuditRepository:
    """Owns only the audit database schema and queries, never DashboardConfig.engine."""

    def __init__(self, engine: db.Engine):
        self.engine = engine
        self.metadata = db.MetaData()
        self.schema_versions = db.Table(
            "AuditSchemaVersions", self.metadata,
            db.Column("SchemaVersion", db.Integer, primary_key=True),
            db.Column("AppliedAt", db.DateTime, nullable=False),
        )
        self.activity_windows = db.Table(
            "AuditActivityWindows", self.metadata,
            db.Column("ActivityWindowID", db.String(36), primary_key=True),
            db.Column("ConfigurationName", db.String(63), nullable=False),
            db.Column("PeerPublicKey", db.String(44), nullable=False),
            db.Column("PeerNameSnapshot", db.String(255), nullable=False),
            db.Column("TunnelAddress", db.String(45), nullable=False),
            db.Column("DestinationAddress", db.String(45), nullable=False),
            db.Column("DestinationSortKey", db.LargeBinary(16), nullable=False),
            db.Column("AddressFamily", db.SmallInteger, nullable=False),
            db.Column("Protocol", db.String(16), nullable=False),
            db.Column("DestinationPort", db.Integer, nullable=True),
            db.Column("PortKey", db.String(5), nullable=False),
            db.Column("Decision", db.String(32), nullable=False),
            db.Column("WindowStartedAt", db.DateTime, nullable=False),
            db.Column("FirstSeenAt", db.DateTime, nullable=False),
            db.Column("LastSeenAt", db.DateTime, nullable=False),
            db.Column("ConnectionCount", db.BigInteger, nullable=False),
            db.Column("BytesFromPeer", db.BigInteger, nullable=False),
            db.Column("BytesToPeer", db.BigInteger, nullable=False),
            db.UniqueConstraint(
                "ConfigurationName", "PeerPublicKey", "PeerNameSnapshot", "TunnelAddress",
                "DestinationAddress", "AddressFamily", "Protocol", "PortKey", "Decision", "WindowStartedAt",
                name="uq_AuditActivityWindows_dimension_window",
            ),
            db.Index("ix_AuditActivityWindows_window", "WindowStartedAt", "ActivityWindowID"),
            db.Index("ix_AuditActivityWindows_peer_window", "PeerPublicKey", "WindowStartedAt"),
            db.Index("ix_AuditActivityWindows_destination", "AddressFamily", "DestinationSortKey", "WindowStartedAt"),
        )
        self.daily_aggregates = db.Table(
            "AuditDailyAggregates", self.metadata,
            db.Column("DailyAggregateID", db.String(36), primary_key=True),
            db.Column("AggregateDate", db.Date, nullable=False),
            db.Column("ConfigurationName", db.String(63), nullable=False),
            db.Column("PeerPublicKey", db.String(44), nullable=False),
            db.Column("PeerNameSnapshot", db.String(255), nullable=False),
            db.Column("TunnelAddress", db.String(45), nullable=False),
            db.Column("DestinationAddress", db.String(45), nullable=False),
            db.Column("AddressFamily", db.SmallInteger, nullable=False),
            db.Column("Protocol", db.String(16), nullable=False),
            db.Column("DestinationPort", db.Integer, nullable=True),
            db.Column("PortKey", db.String(5), nullable=False),
            db.Column("Decision", db.String(32), nullable=False),
            db.Column("FirstSeenAt", db.DateTime, nullable=False),
            db.Column("LastSeenAt", db.DateTime, nullable=False),
            db.Column("ConnectionCount", db.BigInteger, nullable=False),
            db.Column("BytesFromPeer", db.BigInteger, nullable=False),
            db.Column("BytesToPeer", db.BigInteger, nullable=False),
            db.UniqueConstraint(
                "AggregateDate", "ConfigurationName", "PeerPublicKey", "PeerNameSnapshot", "TunnelAddress",
                "DestinationAddress", "AddressFamily", "Protocol", "PortKey", "Decision",
                name="uq_AuditDailyAggregates_dimension_day",
            ),
            db.Index("ix_AuditDailyAggregates_date", "AggregateDate"),
        )
        self.retention_runs = db.Table(
            "AuditRetentionRuns", self.metadata,
            db.Column("RetentionRunID", db.String(36), primary_key=True),
            db.Column("RanAt", db.DateTime, nullable=False),
            db.Column("ActivityWindowsDeleted", db.Integer, nullable=False),
            db.Column("DailyAggregatesDeleted", db.Integer, nullable=False),
            db.Column("ErrorSummary", db.String(1024), nullable=True),
        )
        self.initialize()

    def initialize(self) -> None:
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        with self.engine.begin() as connection:
            self.metadata.create_all(connection)
            current_version = connection.scalar(db.select(db.func.max(self.schema_versions.c.SchemaVersion)))
            if current_version is not None and current_version > SCHEMA_VERSION:
                raise RuntimeError("audit database schema is newer than this Dashboard version")
            for schema_version in range((current_version or 0) + 1, SCHEMA_VERSION + 1):
                connection.execute(self.schema_versions.insert().values(SchemaVersion=schema_version, AppliedAt=now))

    @staticmethod
    def _port_key(destination_port: int | None) -> str:
        return "" if destination_port is None else str(destination_port)

    @classmethod
    def _observation_values(cls, observation: AuditObservation) -> dict[str, Any]:
        return {
            "ConfigurationName": observation.configuration_name,
            "PeerPublicKey": observation.peer_public_key,
            "PeerNameSnapshot": observation.peer_name_snapshot,
            "TunnelAddress": observation.tunnel_address,
            "DestinationAddress": observation.destination_address,
            "DestinationSortKey": observation.destination_sort_key,
            "AddressFamily": observation.address_family,
            "Protocol": observation.protocol,
            "DestinationPort": observation.destination_port,
            "PortKey": cls._port_key(observation.destination_port),
            "Decision": observation.decision.value,
            "FirstSeenAt": observation.observed_at,
            "LastSeenAt": observation.observed_at,
            "ConnectionCount": observation.connection_increment,
            "BytesFromPeer": observation.bytes_from_peer,
            "BytesToPeer": observation.bytes_to_peer,
        }

    def record_observation(self, observation: AuditObservation) -> None:
        values = self._observation_values(observation)
        window_values = {
            **values,
            "ActivityWindowID": str(uuid.uuid4()),
            "WindowStartedAt": observation.window_started_at,
        }
        daily_values = {
            key: value for key, value in values.items() if key != "DestinationSortKey"
        }
        daily_values.update({
            "DailyAggregateID": str(uuid.uuid4()),
            "AggregateDate": observation.observed_at.date(),
        })
        with self.engine.begin() as connection:
            self._upsert_window(connection, window_values)
            self._upsert_daily_aggregate(connection, daily_values)

    def _upsert_window(self, connection: db.Connection, values: dict[str, Any]) -> None:
        statement = sqlite_insert(self.activity_windows).values(**values)
        excluded = statement.excluded
        update_values = {
            "FirstSeenAt": db.case((excluded.FirstSeenAt < self.activity_windows.c.FirstSeenAt, excluded.FirstSeenAt), else_=self.activity_windows.c.FirstSeenAt),
            "LastSeenAt": db.case((excluded.LastSeenAt > self.activity_windows.c.LastSeenAt, excluded.LastSeenAt), else_=self.activity_windows.c.LastSeenAt),
            "ConnectionCount": self.activity_windows.c.ConnectionCount + excluded.ConnectionCount,
            "BytesFromPeer": self.activity_windows.c.BytesFromPeer + excluded.BytesFromPeer,
            "BytesToPeer": self.activity_windows.c.BytesToPeer + excluded.BytesToPeer,
        }
        connection.execute(statement.on_conflict_do_update(
            index_elements=[
                self.activity_windows.c.ConfigurationName, self.activity_windows.c.PeerPublicKey,
                self.activity_windows.c.PeerNameSnapshot, self.activity_windows.c.TunnelAddress,
                self.activity_windows.c.DestinationAddress, self.activity_windows.c.AddressFamily,
                self.activity_windows.c.Protocol, self.activity_windows.c.PortKey,
                self.activity_windows.c.Decision, self.activity_windows.c.WindowStartedAt,
            ],
            set_=update_values,
        ))

    def _upsert_daily_aggregate(self, connection: db.Connection, values: dict[str, Any]) -> None:
        statement = sqlite_insert(self.daily_aggregates).values(**values)
        excluded = statement.excluded
        update_values = {
            "FirstSeenAt": db.case((excluded.FirstSeenAt < self.daily_aggregates.c.FirstSeenAt, excluded.FirstSeenAt), else_=self.daily_aggregates.c.FirstSeenAt),
            "LastSeenAt": db.case((excluded.LastSeenAt > self.daily_aggregates.c.LastSeenAt, excluded.LastSeenAt), else_=self.daily_aggregates.c.LastSeenAt),
            "ConnectionCount": self.daily_aggregates.c.ConnectionCount + excluded.ConnectionCount,
            "BytesFromPeer": self.daily_aggregates.c.BytesFromPeer + excluded.BytesFromPeer,
            "BytesToPeer": self.daily_aggregates.c.BytesToPeer + excluded.BytesToPeer,
        }
        connection.execute(statement.on_conflict_do_update(
            index_elements=[
                self.daily_aggregates.c.AggregateDate, self.daily_aggregates.c.ConfigurationName,
                self.daily_aggregates.c.PeerPublicKey, self.daily_aggregates.c.PeerNameSnapshot,
                self.daily_aggregates.c.TunnelAddress, self.daily_aggregates.c.DestinationAddress,
                self.daily_aggregates.c.AddressFamily, self.daily_aggregates.c.Protocol,
                self.daily_aggregates.c.PortKey, self.daily_aggregates.c.Decision,
            ],
            set_=update_values,
        ))

    def _filtered_statement(self, query: AuditQuery) -> db.Select:
        conditions = [
            self.activity_windows.c.WindowStartedAt >= query.start_time,
            self.activity_windows.c.WindowStartedAt <= query.end_time,
        ]
        equality_filters = {
            "configuration_name": self.activity_windows.c.ConfigurationName,
            "peer_public_key": self.activity_windows.c.PeerPublicKey,
            "peer_name": self.activity_windows.c.PeerNameSnapshot,
            "tunnel_address": self.activity_windows.c.TunnelAddress,
            "protocol": self.activity_windows.c.Protocol,
            "destination_port": self.activity_windows.c.DestinationPort,
        }
        for field, column in equality_filters.items():
            value = getattr(query, field)
            if value is not None:
                conditions.append(column == value)
        if query.decision is not None:
            conditions.append(self.activity_windows.c.Decision == query.decision.value)
        if query.destination is not None:
            start_key = address_sort_key(query.destination.network_address)
            end_key = address_sort_key(query.destination.broadcast_address)
            conditions.extend((
                self.activity_windows.c.AddressFamily == query.destination.version,
                self.activity_windows.c.DestinationSortKey >= start_key,
                self.activity_windows.c.DestinationSortKey <= end_key,
            ))
        return db.select(self.activity_windows).where(*conditions)

    def query(self, query: AuditQuery) -> tuple[list[dict[str, Any]], int]:
        statement = self._filtered_statement(query)
        count_statement = db.select(db.func.count()).select_from(statement.subquery())
        ordered_statement = statement.order_by(
            self.activity_windows.c.WindowStartedAt.desc(), self.activity_windows.c.ActivityWindowID.desc()
        ).offset((query.page - 1) * query.page_size).limit(query.page_size)
        with self.engine.connect() as connection:
            total = connection.scalar(count_statement) or 0
            rows = connection.execute(ordered_statement).mappings().all()
        return [self._serialize_window(row) for row in rows], total

    def summary(self, query: AuditQuery) -> dict[str, Any]:
        statement = self._filtered_statement(query).subquery()
        summary_statement = db.select(
            db.func.count().label("WindowCount"),
            db.func.coalesce(db.func.sum(statement.c.ConnectionCount), 0).label("ConnectionCount"),
            db.func.coalesce(db.func.sum(statement.c.BytesFromPeer), 0).label("BytesFromPeer"),
            db.func.coalesce(db.func.sum(statement.c.BytesToPeer), 0).label("BytesToPeer"),
            db.func.max(statement.c.WindowStartedAt).label("LatestWindowStartedAt"),
        )
        with self.engine.connect() as connection:
            return dict(connection.execute(summary_statement).mappings().one())

    def cleanup_retention(self, now: datetime, detail_days: int, aggregate_months: int) -> dict[str, int]:
        detail_boundary = now - timedelta(days=detail_days)
        aggregate_boundary = _subtract_months(now.date(), aggregate_months)
        with self.engine.begin() as connection:
            activity_result = connection.execute(
                self.activity_windows.delete().where(
                    self.activity_windows.c.WindowStartedAt < detail_boundary - WINDOW_DURATION
                )
            )
            aggregate_result = connection.execute(
                self.daily_aggregates.delete().where(self.daily_aggregates.c.AggregateDate < aggregate_boundary)
            )
            result = {
                "activity_windows_deleted": activity_result.rowcount or 0,
                "daily_aggregates_deleted": aggregate_result.rowcount or 0,
            }
            connection.execute(self.retention_runs.insert().values(
                RetentionRunID=str(uuid.uuid4()),
                RanAt=now,
                ActivityWindowsDeleted=result["activity_windows_deleted"],
                DailyAggregatesDeleted=result["daily_aggregates_deleted"],
                ErrorSummary=None,
            ))
        return result

    @staticmethod
    def _serialize_window(row: db.RowMapping) -> dict[str, Any]:
        return {
            "configuration_name": row["ConfigurationName"],
            "peer_public_key": row["PeerPublicKey"],
            "peer_name_snapshot": row["PeerNameSnapshot"],
            "tunnel_address": row["TunnelAddress"],
            "destination_address": row["DestinationAddress"],
            "address_family": row["AddressFamily"],
            "protocol": row["Protocol"],
            "destination_port": row["DestinationPort"],
            "decision": row["Decision"],
            "window_started_at": _isoformat(row["WindowStartedAt"]),
            "first_seen_at": _isoformat(row["FirstSeenAt"]),
            "last_seen_at": _isoformat(row["LastSeenAt"]),
            "connection_count": row["ConnectionCount"],
            "bytes_from_peer": row["BytesFromPeer"],
            "bytes_to_peer": row["BytesToPeer"],
        }


def _isoformat(value: datetime | None) -> str | None:
    return value.replace(tzinfo=None).isoformat(timespec="seconds") + "Z" if value else None


def _subtract_months(value: date, months: int) -> date:
    month_index = value.year * 12 + value.month - 1 - months
    year, month_index = divmod(month_index, 12)
    month = month_index + 1
    return date(year, month, min(value.day, calendar.monthrange(year, month)[1]))
