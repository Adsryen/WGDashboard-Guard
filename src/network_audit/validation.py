"""Runtime validation and canonicalization for internal network audit data."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
import ipaddress
import re
from typing import Any, Mapping


WINDOW_MINUTES = 5
MAX_QUERY_RANGE_DAYS = 31
MAX_PAGE_SIZE = 100
DEFAULT_PAGE_SIZE = 50
MAX_PAGE = 100
MAX_QUERY_RESULTS = 5_000

PUBLIC_KEY_PATTERN = re.compile(r"^[A-Za-z0-9+/]{43}=$")
CONFIGURATION_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,63}$")
SUPPORTED_PROTOCOLS = {"tcp", "udp", "icmp"}


class AuditValidationError(ValueError):
    """Raised when audit input falls outside the persisted data contract."""


class AuditDecision(str, Enum):
    FORWARD_OBSERVED = "forward_observed"
    POLICY_ALLOWED = "policy_allowed"
    POLICY_DENIED = "policy_denied"


def normalize_utc(value: Any, field: str) -> datetime:
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise AuditValidationError(f"{field} must be an ISO-8601 timestamp") from error
    if not isinstance(value, datetime):
        raise AuditValidationError(f"{field} must be an ISO-8601 timestamp")
    if value.tzinfo is None or value.utcoffset() is None:
        raise AuditValidationError(f"{field} must include a timezone")
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def window_started_at(observed_at: datetime) -> datetime:
    return observed_at.replace(
        minute=observed_at.minute - (observed_at.minute % WINDOW_MINUTES),
        second=0,
        microsecond=0,
    )


def _required_string(value: Any, field: str, *, allow_empty: bool = False, maximum: int = 255) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise AuditValidationError(f"{field} must be a {'string' if allow_empty else 'non-empty string'}")
    if len(value) > maximum:
        raise AuditValidationError(f"{field} cannot exceed {maximum} characters")
    return value


def _address(value: Any, field: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    raw_value = _required_string(value, field)
    try:
        address = ipaddress.ip_address(raw_value)
    except ValueError as error:
        raise AuditValidationError(f"{field} must be an IPv4 or IPv6 address") from error
    if address.is_unspecified or address.is_multicast:
        raise AuditValidationError(f"{field} cannot be unspecified or multicast")
    return address


def _network(value: Any, field: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    raw_value = _required_string(value, field)
    try:
        network = ipaddress.ip_network(raw_value, strict=False)
    except ValueError as error:
        raise AuditValidationError(f"{field} must be an IPv4 or IPv6 address/CIDR") from error
    if network.network_address.is_unspecified or network.network_address.is_multicast:
        raise AuditValidationError(f"{field} cannot be unspecified or multicast")
    return network


def _port(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise AuditValidationError(f"{field} must be an integer between 1 and 65535")
    return value


def _positive_integer(value: Any, field: str, *, allow_zero: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < (0 if allow_zero else 1):
        comparator = "zero or greater" if allow_zero else "greater than zero"
        raise AuditValidationError(f"{field} must be an integer {comparator}")
    return value


def address_sort_key(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bytes:
    """Return a fixed-width key so CIDR filtering remains indexed in SQLite."""
    if address.version == 4:
        return b"\x00" * 12 + address.packed
    return address.packed


@dataclass(frozen=True)
class AuditObservation:
    configuration_name: str
    peer_public_key: str
    peer_name_snapshot: str
    tunnel_address: str
    destination_address: str
    protocol: str
    destination_port: int | None
    decision: AuditDecision | str
    observed_at: datetime
    connection_increment: int = 1
    bytes_from_peer: int = 0
    bytes_to_peer: int = 0

    def __post_init__(self) -> None:
        configuration_name = _required_string(self.configuration_name, "configuration_name", maximum=63)
        if not CONFIGURATION_PATTERN.fullmatch(configuration_name):
            raise AuditValidationError("configuration_name contains unsupported characters")

        peer_public_key = _required_string(self.peer_public_key, "peer_public_key", maximum=44)
        if not PUBLIC_KEY_PATTERN.fullmatch(peer_public_key):
            raise AuditValidationError("peer_public_key is not a WireGuard public key")

        peer_name_snapshot = _required_string(
            self.peer_name_snapshot, "peer_name_snapshot", allow_empty=True, maximum=255
        )
        tunnel_address = _address(self.tunnel_address, "tunnel_address")
        destination_address = _address(self.destination_address, "destination_address")
        protocol = _required_string(self.protocol, "protocol", maximum=16).lower()
        if protocol not in SUPPORTED_PROTOCOLS:
            raise AuditValidationError("protocol must be tcp, udp, or icmp")

        if protocol == "icmp":
            if self.destination_port is not None:
                raise AuditValidationError("destination_port must be null for icmp")
            destination_port = None
        else:
            destination_port = _port(self.destination_port, "destination_port")

        try:
            decision = AuditDecision(self.decision)
        except ValueError as error:
            raise AuditValidationError("decision must be forward_observed, policy_allowed, or policy_denied") from error

        object.__setattr__(self, "configuration_name", configuration_name)
        object.__setattr__(self, "peer_public_key", peer_public_key)
        object.__setattr__(self, "peer_name_snapshot", peer_name_snapshot)
        object.__setattr__(self, "tunnel_address", str(tunnel_address))
        object.__setattr__(self, "destination_address", str(destination_address))
        object.__setattr__(self, "protocol", protocol)
        object.__setattr__(self, "destination_port", destination_port)
        object.__setattr__(self, "decision", decision)
        object.__setattr__(self, "observed_at", normalize_utc(self.observed_at, "observed_at"))
        object.__setattr__(self, "connection_increment", _positive_integer(self.connection_increment, "connection_increment"))
        object.__setattr__(self, "bytes_from_peer", _positive_integer(self.bytes_from_peer, "bytes_from_peer", allow_zero=True))
        object.__setattr__(self, "bytes_to_peer", _positive_integer(self.bytes_to_peer, "bytes_to_peer", allow_zero=True))

    @classmethod
    def from_payload(cls, payload: Any) -> "AuditObservation":
        if not isinstance(payload, Mapping):
            raise AuditValidationError("audit observation must be an object")
        expected_fields = {
            "configuration_name", "peer_public_key", "peer_name_snapshot", "tunnel_address",
            "destination_address", "protocol", "destination_port", "decision", "observed_at",
            "connection_increment", "bytes_from_peer", "bytes_to_peer",
        }
        unknown_fields = set(payload) - expected_fields
        if unknown_fields:
            raise AuditValidationError(f"unsupported audit observation fields: {', '.join(sorted(unknown_fields))}")
        return cls(
            configuration_name=payload.get("configuration_name"),
            peer_public_key=payload.get("peer_public_key"),
            peer_name_snapshot=payload.get("peer_name_snapshot"),
            tunnel_address=payload.get("tunnel_address"),
            destination_address=payload.get("destination_address"),
            protocol=payload.get("protocol"),
            destination_port=payload.get("destination_port"),
            decision=payload.get("decision"),
            observed_at=payload.get("observed_at"),
            connection_increment=payload.get("connection_increment", 1),
            bytes_from_peer=payload.get("bytes_from_peer", 0),
            bytes_to_peer=payload.get("bytes_to_peer", 0),
        )

    @property
    def window_started_at(self) -> datetime:
        return window_started_at(self.observed_at)

    @property
    def destination_sort_key(self) -> bytes:
        return address_sort_key(ipaddress.ip_address(self.destination_address))

    @property
    def address_family(self) -> int:
        return ipaddress.ip_address(self.destination_address).version


@dataclass(frozen=True)
class AuditQuery:
    start_time: datetime
    end_time: datetime
    configuration_name: str | None = None
    peer_public_key: str | None = None
    peer_name: str | None = None
    tunnel_address: str | None = None
    destination: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None
    protocol: str | None = None
    destination_port: int | None = None
    decision: AuditDecision | None = None
    page: int = 1
    page_size: int = DEFAULT_PAGE_SIZE

    def __post_init__(self) -> None:
        start_time = normalize_utc(self.start_time, "start_time")
        end_time = normalize_utc(self.end_time, "end_time")
        if start_time > end_time:
            raise AuditValidationError("start_time cannot be after end_time")
        if end_time - start_time > timedelta(days=MAX_QUERY_RANGE_DAYS):
            raise AuditValidationError(f"time range cannot exceed {MAX_QUERY_RANGE_DAYS} days")

        if self.configuration_name is not None:
            configuration_name = _required_string(self.configuration_name, "configuration_name", maximum=63)
            if not CONFIGURATION_PATTERN.fullmatch(configuration_name):
                raise AuditValidationError("configuration_name contains unsupported characters")
            object.__setattr__(self, "configuration_name", configuration_name)
        if self.peer_public_key is not None:
            peer_public_key = _required_string(self.peer_public_key, "peer_public_key", maximum=44)
            if not PUBLIC_KEY_PATTERN.fullmatch(peer_public_key):
                raise AuditValidationError("peer_public_key is not a WireGuard public key")
            object.__setattr__(self, "peer_public_key", peer_public_key)
        if self.peer_name is not None:
            object.__setattr__(self, "peer_name", _required_string(self.peer_name, "peer_name", allow_empty=True))
        if self.tunnel_address is not None:
            object.__setattr__(self, "tunnel_address", str(_address(self.tunnel_address, "tunnel_address")))
        if self.destination is not None and not isinstance(self.destination, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            object.__setattr__(self, "destination", _network(self.destination, "destination"))
        if self.protocol is not None:
            protocol = _required_string(self.protocol, "protocol", maximum=16).lower()
            if protocol not in SUPPORTED_PROTOCOLS:
                raise AuditValidationError("protocol must be tcp, udp, or icmp")
            object.__setattr__(self, "protocol", protocol)
        if self.destination_port is not None:
            object.__setattr__(self, "destination_port", _port(self.destination_port, "destination_port"))
        if self.decision is not None:
            try:
                object.__setattr__(self, "decision", AuditDecision(self.decision))
            except ValueError as error:
                raise AuditValidationError("decision must be forward_observed, policy_allowed, or policy_denied") from error

        page = _positive_integer(self.page, "page")
        page_size = _positive_integer(self.page_size, "page_size")
        if page > MAX_PAGE:
            raise AuditValidationError(f"page cannot exceed {MAX_PAGE}")
        if page_size > MAX_PAGE_SIZE:
            raise AuditValidationError(f"page_size cannot exceed {MAX_PAGE_SIZE}")
        if page * page_size > MAX_QUERY_RESULTS:
            raise AuditValidationError(f"page and page_size cannot request beyond {MAX_QUERY_RESULTS} results")

        object.__setattr__(self, "start_time", start_time)
        object.__setattr__(self, "end_time", end_time)
        object.__setattr__(self, "page", page)
        object.__setattr__(self, "page_size", page_size)

    @classmethod
    def from_payload(cls, payload: Any) -> "AuditQuery":
        if not isinstance(payload, Mapping):
            raise AuditValidationError("audit query must be an object")
        expected_fields = {
            "start_time", "end_time", "configuration_name", "peer_public_key", "peer_name",
            "tunnel_address", "destination", "protocol", "destination_port", "decision", "page", "page_size",
        }
        unknown_fields = set(payload) - expected_fields
        if unknown_fields:
            raise AuditValidationError(f"unsupported audit query fields: {', '.join(sorted(unknown_fields))}")
        return cls(
            start_time=payload.get("start_time"),
            end_time=payload.get("end_time"),
            configuration_name=payload.get("configuration_name"),
            peer_public_key=payload.get("peer_public_key"),
            peer_name=payload.get("peer_name"),
            tunnel_address=payload.get("tunnel_address"),
            destination=payload.get("destination"),
            protocol=payload.get("protocol"),
            destination_port=payload.get("destination_port"),
            decision=payload.get("decision"),
            page=payload.get("page", 1),
            page_size=payload.get("page_size", DEFAULT_PAGE_SIZE),
        )
