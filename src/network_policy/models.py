"""Dashboard-side persistence for policy state, revisions, and apply audits."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
from typing import Any
from uuid import uuid4

import sqlalchemy as db

from .compiler import policy_hash
from .validation import NetworkPolicy


def utcnow() -> datetime:
    """Return a naive UTC timestamp compatible with the existing Dashboard schema."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


@dataclass(frozen=True)
class PolicyCandidate:
    policy_id: str
    revision_id: str
    version: int
    policy: NetworkPolicy


class NetworkPolicyRepository:
    """Owns policy tables without touching existing WireGuard peer tables."""

    def __init__(self, engine: db.Engine):
        self.engine = engine
        self.metadata = db.MetaData()
        self.policies = db.Table(
            "NetworkPolicies",
            self.metadata,
            db.Column("PolicyID", db.String(36), primary_key=True),
            db.Column("ConfigurationName", db.String(63), nullable=False),
            db.Column("InterfaceName", db.String(15), nullable=False),
            db.Column("PeerPublicKey", db.String(44), nullable=False),
            db.Column("TunnelAddress", db.String(45), nullable=False),
            db.Column("Managed", db.Boolean, nullable=False, default=False),
            db.Column("Version", db.Integer, nullable=False, default=0),
            db.Column("PolicyJson", db.Text, nullable=False),
            db.Column("PolicyHash", db.String(64), nullable=False),
            db.Column("LastRevisionID", db.String(36)),
            db.Column("LastApplyStatus", db.String(32), nullable=False, default="never_applied"),
            db.Column("BindingStatus", db.String(32), nullable=False, default="bound"),
            db.Column("LastApplyAt", db.DateTime),
            db.Column("CreatedAt", db.DateTime, nullable=False, default=utcnow),
            db.Column("UpdatedAt", db.DateTime, nullable=False, default=utcnow),
            db.UniqueConstraint("ConfigurationName", "PeerPublicKey", "TunnelAddress", name="uq_network_policy_peer"),
        )
        self.revisions = db.Table(
            "NetworkPolicyRevisions",
            self.metadata,
            db.Column("RevisionID", db.String(36), primary_key=True),
            db.Column("PolicyID", db.String(36), nullable=False),
            db.Column("Version", db.Integer, nullable=False),
            db.Column("PolicyJson", db.Text, nullable=False),
            db.Column("PolicyHash", db.String(64), nullable=False),
            db.Column("Actor", db.String(128), nullable=False),
            db.Column("Action", db.String(32), nullable=False),
            db.Column("ApplyStatus", db.String(32), nullable=False),
            db.Column("PreviousRevisionID", db.String(36)),
            db.Column("ErrorSummary", db.Text),
            db.Column("CreatedAt", db.DateTime, nullable=False, default=utcnow),
        )
        self.applies = db.Table(
            "NetworkPolicyApplies",
            self.metadata,
            db.Column("ApplyID", db.String(36), primary_key=True),
            db.Column("RevisionID", db.String(36), nullable=False),
            db.Column("Action", db.String(32), nullable=False),
            db.Column("Result", db.String(32), nullable=False),
            db.Column("RulesetHash", db.String(64)),
            db.Column("ErrorSummary", db.Text),
            db.Column("CreatedAt", db.DateTime, nullable=False, default=utcnow),
        )
        self.metadata.create_all(self.engine)

    @staticmethod
    def _serialize(policy: NetworkPolicy) -> str:
        return json.dumps(policy.to_payload(), sort_keys=True, separators=(",", ":"))

    @staticmethod
    def _deserialize(raw: str) -> NetworkPolicy:
        return NetworkPolicy.from_payload(json.loads(raw))

    def _find_policy_row(self, connection, policy: NetworkPolicy):
        return connection.execute(
            self.policies.select().where(
                self.policies.c.ConfigurationName == policy.configuration_name,
                self.policies.c.PeerPublicKey == policy.peer_public_key,
                self.policies.c.TunnelAddress == policy.tunnel_address,
            )
        ).mappings().fetchone()

    def create_candidate(self, policy: NetworkPolicy, actor: str, action: str = "apply") -> PolicyCandidate:
        """Record a candidate revision. Current policy state changes only after Agent success."""
        if action not in {"apply", "rollback", "deactivate", "suspend"}:
            raise ValueError("unsupported policy revision action")
        with self.engine.begin() as connection:
            current = self._find_policy_row(connection, policy)
            policy_id = current["PolicyID"] if current else str(uuid4())
            version = (current["Version"] if current else 0) + 1
            revision_id = str(uuid4())
            connection.execute(
                self.revisions.insert().values(
                    RevisionID=revision_id,
                    PolicyID=policy_id,
                    Version=version,
                    PolicyJson=self._serialize(policy),
                    PolicyHash=policy_hash([policy]),
                    Actor=actor,
                    Action=action,
                    ApplyStatus="pending",
                    PreviousRevisionID=current["LastRevisionID"] if current else None,
                )
            )
        return PolicyCandidate(policy_id, revision_id, version, policy)

    def get_current(
        self, configuration_name: str, peer_public_key: str, tunnel_address: str
    ) -> tuple[str, NetworkPolicy, str] | None:
        with self.engine.connect() as connection:
            row = connection.execute(
                self.policies.select().where(
                    self.policies.c.ConfigurationName == configuration_name,
                    self.policies.c.PeerPublicKey == peer_public_key,
                    self.policies.c.TunnelAddress == tunnel_address,
                )
            ).mappings().fetchone()
        if row is None:
            return None
        return row["PolicyID"], self._deserialize(row["PolicyJson"]), row["BindingStatus"]

    def active_except(self, policy_ids: set[str] | None = None) -> list[NetworkPolicy]:
        statement = self.policies.select().where(self.policies.c.Managed.is_(True))
        if policy_ids:
            statement = statement.where(self.policies.c.PolicyID.not_in(policy_ids))
        with self.engine.connect() as connection:
            rows = connection.execute(statement).mappings().fetchall()
        return [self._deserialize(row["PolicyJson"]) for row in rows]

    def mark_applied(
        self,
        candidate: PolicyCandidate,
        action: str,
        ruleset_hash: str | None,
        binding_status: str = "bound",
    ) -> None:
        now = utcnow()
        serialized = self._serialize(candidate.policy)
        digest = policy_hash([candidate.policy])
        with self.engine.begin() as connection:
            current = connection.execute(
                self.policies.select().where(self.policies.c.PolicyID == candidate.policy_id)
            ).mappings().fetchone()
            values = {
                "ConfigurationName": candidate.policy.configuration_name,
                "InterfaceName": candidate.policy.interface_name,
                "PeerPublicKey": candidate.policy.peer_public_key,
                "TunnelAddress": candidate.policy.tunnel_address,
                "Managed": candidate.policy.managed,
                "Version": candidate.version,
                "PolicyJson": serialized,
                "PolicyHash": digest,
                "LastRevisionID": candidate.revision_id,
                "LastApplyStatus": "applied",
                "BindingStatus": binding_status,
                "LastApplyAt": now,
                "UpdatedAt": now,
            }
            if current is None:
                values["PolicyID"] = candidate.policy_id
                values["CreatedAt"] = now
                connection.execute(self.policies.insert().values(**values))
            else:
                connection.execute(
                    self.policies.update().where(self.policies.c.PolicyID == candidate.policy_id).values(**values)
                )
            connection.execute(
                self.revisions.update()
                .where(self.revisions.c.RevisionID == candidate.revision_id)
                .values(ApplyStatus="applied", ErrorSummary=None)
            )
            connection.execute(
                self.applies.insert().values(
                    ApplyID=str(uuid4()),
                    RevisionID=candidate.revision_id,
                    Action=action,
                    Result="applied",
                    RulesetHash=ruleset_hash,
                )
            )

    def mark_failed(self, candidate: PolicyCandidate, action: str, error: str) -> None:
        summary = error[:1024]
        with self.engine.begin() as connection:
            connection.execute(
                self.revisions.update()
                .where(self.revisions.c.RevisionID == candidate.revision_id)
                .values(ApplyStatus="failed", ErrorSummary=summary)
            )
            connection.execute(
                self.applies.insert().values(
                    ApplyID=str(uuid4()),
                    RevisionID=candidate.revision_id,
                    Action=action,
                    Result="failed",
                    ErrorSummary=summary,
                )
            )

    def details(self, configuration_name: str, peer_public_key: str, tunnel_address: str) -> dict[str, Any]:
        current = self.get_current(configuration_name, peer_public_key, tunnel_address)
        if current is None:
            return {"policy": None, "revisions": []}
        policy_id, policy, binding_status = current
        with self.engine.connect() as connection:
            revisions = connection.execute(
                self.revisions.select()
                .where(self.revisions.c.PolicyID == policy_id)
                .order_by(self.revisions.c.CreatedAt.desc())
            ).mappings().fetchall()
        return {
            "policy": policy.to_payload(),
            "binding_status": binding_status,
            "revisions": [
                {
                    "revision_id": row["RevisionID"],
                    "version": row["Version"],
                    "action": row["Action"],
                    "status": row["ApplyStatus"],
                    "hash": row["PolicyHash"],
                    "created_at": row["CreatedAt"],
                    "error": row["ErrorSummary"],
                }
                for row in revisions
            ],
        }

    def revision_policy(self, revision_id: str) -> NetworkPolicy | None:
        with self.engine.connect() as connection:
            row = connection.execute(
                self.revisions.select().where(self.revisions.c.RevisionID == revision_id)
            ).mappings().fetchone()
        return self._deserialize(row["PolicyJson"]) if row else None

    def current_managed_for_peers(self, configuration_name: str, peer_public_keys: list[str]) -> list[tuple[str, NetworkPolicy]]:
        if not peer_public_keys:
            return []
        with self.engine.connect() as connection:
            rows = connection.execute(
                self.policies.select().where(
                    self.policies.c.ConfigurationName == configuration_name,
                    self.policies.c.PeerPublicKey.in_(peer_public_keys),
                    self.policies.c.Managed.is_(True),
                )
            ).mappings().fetchall()
        return [(row["PolicyID"], self._deserialize(row["PolicyJson"])) for row in rows]
