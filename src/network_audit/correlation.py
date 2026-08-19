"""Short-lived, metadata-only correlation of conntrack and NFLOG events."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .agent_protocol import AuditAgentConfig, AuditPeerSnapshot
from .models import ConntrackEvent, ConntrackEventType, FlowKey, NflogEvent
from .validation import AuditDecision, AuditObservation


DECISION_PRECEDENCE = {
    AuditDecision.FORWARD_OBSERVED: 0,
    AuditDecision.POLICY_ALLOWED: 1,
    AuditDecision.POLICY_DENIED: 2,
}


@dataclass
class CorrelationStats:
    correlation_timeouts: int = 0
    incomplete_flows: int = 0
    discarded_orphan_decisions: int = 0


@dataclass
class _PendingFlow:
    flow: FlowKey
    peer: AuditPeerSnapshot
    observed_at: datetime
    deadline: datetime
    decision: AuditDecision = AuditDecision.FORWARD_OBSERVED
    bytes_from_peer: int = 0
    bytes_to_peer: int = 0
    destroy_seen: bool = False


@dataclass
class _OrphanDecision:
    decision: AuditDecision
    observed_at: datetime


class FlowCorrelator:
    """Buffers a flow until its decision window closes, then emits one observation."""

    def __init__(self, decision_ttl: timedelta = timedelta(seconds=5)) -> None:
        if decision_ttl <= timedelta(0):
            raise ValueError("decision_ttl must be greater than zero")
        self.decision_ttl = decision_ttl
        self.stats = CorrelationStats()
        self._pending: dict[tuple[object, ...], _PendingFlow] = {}
        self._orphan_decisions: dict[tuple[object, ...], _OrphanDecision] = {}

    def consume_conntrack(self, event: ConntrackEvent, config: AuditAgentConfig) -> list[AuditObservation]:
        key = event.flow.correlation_key
        pending = self._pending.get(key)
        if event.event_type == ConntrackEventType.NEW:
            if pending is None:
                peer = config.peer_for_tunnel(event.flow.source_address)
                if peer is None or not config.should_collect(peer.tunnel_address):
                    return []
                pending = _PendingFlow(
                    flow=event.flow,
                    peer=peer,
                    observed_at=event.observed_at,
                    deadline=event.observed_at + self.decision_ttl,
                )
                orphan = self._orphan_decisions.pop(key, None)
                if orphan is not None:
                    pending.decision = orphan.decision
                self._pending[key] = pending
            self._update_counters(pending, event)
            return []

        if pending is not None:
            self._update_counters(pending, event)
            if event.event_type == ConntrackEventType.DESTROY:
                pending.destroy_seen = True
        return []

    def consume_nflog(self, event: NflogEvent) -> list[AuditObservation]:
        key = event.flow.correlation_key
        pending = self._pending.get(key)
        if pending is not None:
            pending.decision = self._preferred_decision(pending.decision, event.decision)
            return []

        orphan = self._orphan_decisions.get(key)
        if orphan is None:
            self._orphan_decisions[key] = _OrphanDecision(event.decision, event.observed_at)
        else:
            orphan.decision = self._preferred_decision(orphan.decision, event.decision)
            orphan.observed_at = min(orphan.observed_at, event.observed_at)
        return []

    def expire(self, now: datetime | None = None) -> list[AuditObservation]:
        current_time = self._normalize_now(now)
        observations: list[AuditObservation] = []
        for key, pending in list(self._pending.items()):
            if pending.deadline > current_time:
                continue
            observations.append(self._to_observation(pending))
            if not pending.destroy_seen:
                self.stats.incomplete_flows += 1
            self.stats.correlation_timeouts += 1
            del self._pending[key]

        for key, orphan in list(self._orphan_decisions.items()):
            if orphan.observed_at + self.decision_ttl <= current_time:
                self.stats.discarded_orphan_decisions += 1
                del self._orphan_decisions[key]
        return observations

    @staticmethod
    def _preferred_decision(current: AuditDecision, candidate: AuditDecision) -> AuditDecision:
        if DECISION_PRECEDENCE[candidate] > DECISION_PRECEDENCE[current]:
            return candidate
        return current

    @staticmethod
    def _update_counters(pending: _PendingFlow, event: ConntrackEvent) -> None:
        pending.bytes_from_peer = max(pending.bytes_from_peer, event.bytes_original)
        pending.bytes_to_peer = max(pending.bytes_to_peer, event.bytes_reply)

    @staticmethod
    def _to_observation(pending: _PendingFlow) -> AuditObservation:
        return AuditObservation(
            configuration_name=pending.peer.configuration_name,
            peer_public_key=pending.peer.public_key,
            peer_name_snapshot=pending.peer.peer_name,
            tunnel_address=pending.peer.tunnel_address,
            destination_address=pending.flow.destination_address,
            protocol=pending.flow.protocol,
            destination_port=pending.flow.destination_port,
            decision=pending.decision,
            observed_at=pending.observed_at,
            connection_increment=1,
            bytes_from_peer=pending.bytes_from_peer,
            bytes_to_peer=pending.bytes_to_peer,
        )

    @staticmethod
    def _normalize_now(value: datetime | None) -> datetime:
        if value is None:
            return datetime.now(timezone.utc)
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("now must include a timezone")
        return value.astimezone(timezone.utc)
