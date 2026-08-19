"""Metadata-only event models accepted by the audit collector."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
import ipaddress
from typing import Any

from .validation import AuditDecision, AuditValidationError, SUPPORTED_PROTOCOLS, normalize_utc


def _event_timestamp(value: Any, field: str) -> datetime:
    return normalize_utc(value, field).replace(tzinfo=timezone.utc)


def _flow_address(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise AuditValidationError(f"{field} must be a non-empty IPv4 or IPv6 address")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise AuditValidationError(f"{field} must be an IPv4 or IPv6 address") from error
    if address.is_unspecified or address.is_multicast:
        raise AuditValidationError(f"{field} cannot be unspecified or multicast")
    return str(address)


def _flow_port(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise AuditValidationError(f"{field} must be an integer between 1 and 65535")
    return value


def _counter(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise AuditValidationError(f"{field} must be a zero or greater integer")
    return value


@dataclass(frozen=True)
class FlowKey:
    """A direction-preserving five-tuple and conntrack zone without packet data."""

    source_address: str
    destination_address: str
    protocol: str
    source_port: int | None
    destination_port: int | None
    zone: int = 0

    def __post_init__(self) -> None:
        source_address = _flow_address(self.source_address, "source_address")
        destination_address = _flow_address(self.destination_address, "destination_address")
        source = ipaddress.ip_address(source_address)
        destination = ipaddress.ip_address(destination_address)
        if source.version != destination.version:
            raise AuditValidationError("flow addresses must use the same address family")
        if not isinstance(self.protocol, str):
            raise AuditValidationError("protocol must be tcp, udp, or icmp")
        protocol = self.protocol.lower()
        if protocol not in SUPPORTED_PROTOCOLS:
            raise AuditValidationError("protocol must be tcp, udp, or icmp")
        if protocol == "icmp":
            if self.source_port is not None or self.destination_port is not None:
                raise AuditValidationError("ICMP flow ports must be null")
            source_port = None
            destination_port = None
        else:
            source_port = _flow_port(self.source_port, "source_port")
            destination_port = _flow_port(self.destination_port, "destination_port")
        if isinstance(self.zone, bool) or not isinstance(self.zone, int) or not 0 <= self.zone <= 65535:
            raise AuditValidationError("zone must be an integer between 0 and 65535")

        object.__setattr__(self, "source_address", source_address)
        object.__setattr__(self, "destination_address", destination_address)
        object.__setattr__(self, "protocol", protocol)
        object.__setattr__(self, "source_port", source_port)
        object.__setattr__(self, "destination_port", destination_port)

    @property
    def family(self) -> int:
        return ipaddress.ip_address(self.source_address).version

    def reverse(self) -> "FlowKey":
        return FlowKey(
            source_address=self.destination_address,
            destination_address=self.source_address,
            protocol=self.protocol,
            source_port=self.destination_port,
            destination_port=self.source_port,
            zone=self.zone,
        )

    @property
    def correlation_key(self) -> tuple[int, str, tuple[tuple[str, int | None], tuple[str, int | None]], int]:
        endpoints = tuple(sorted(((self.source_address, self.source_port), (self.destination_address, self.destination_port))))
        return self.family, self.protocol, endpoints, self.zone


class ConntrackEventType(str, Enum):
    NEW = "new"
    UPDATE = "update"
    DESTROY = "destroy"


@dataclass(frozen=True)
class ConntrackEvent:
    """Normalized conntrack lifecycle metadata with no raw netlink message."""

    event_type: ConntrackEventType | str
    flow: FlowKey
    observed_at: datetime
    bytes_original: int = 0
    bytes_reply: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.flow, FlowKey):
            raise AuditValidationError("flow must be a FlowKey")
        try:
            event_type = ConntrackEventType(self.event_type)
        except ValueError as error:
            raise AuditValidationError("event_type must be new, update, or destroy") from error
        object.__setattr__(self, "event_type", event_type)
        object.__setattr__(self, "observed_at", _event_timestamp(self.observed_at, "observed_at"))
        object.__setattr__(self, "bytes_original", _counter(self.bytes_original, "bytes_original"))
        object.__setattr__(self, "bytes_reply", _counter(self.bytes_reply, "bytes_reply"))


@dataclass(frozen=True)
class NflogEvent:
    """A parsed NFLOG decision tag and five-tuple, never a packet payload."""

    flow: FlowKey
    decision: AuditDecision | str
    observed_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.flow, FlowKey):
            raise AuditValidationError("flow must be a FlowKey")
        try:
            decision = AuditDecision(self.decision)
        except ValueError as error:
            raise AuditValidationError("decision must be a supported audit decision") from error
        object.__setattr__(self, "decision", decision)
        object.__setattr__(self, "observed_at", _event_timestamp(self.observed_at, "observed_at"))
