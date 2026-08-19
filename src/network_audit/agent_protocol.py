"""Validated configuration exchanged with the local audit agent."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import ipaddress
import json
import re
from typing import Any, Mapping

from .validation import AuditValidationError, CONFIGURATION_PATTERN, PUBLIC_KEY_PATTERN


AUDIT_CONFIG_VERSION = 1
AGENT_PROTOCOL_VERSION = 1
MAX_MESSAGE_BYTES = 1_048_576
INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
CONFIG_ACTIONS = {"dry_run", "apply"}
ALL_ACTIONS = CONFIG_ACTIONS | {"capabilities", "status", "remove"}


class AuditAgentProtocolError(ValueError):
    """The request did not conform to the fixed audit-agent protocol."""


class AuditMode(str, Enum):
    """Controls whether generic observations include every known peer."""

    ALL = "all"
    MANAGED = "managed"


def _tunnel_address(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise AuditValidationError(f"{field} must be a non-empty IPv4 or IPv6 address")
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise AuditValidationError(f"{field} must be an IPv4 or IPv6 address") from error
    if address.is_unspecified or address.is_multicast:
        raise AuditValidationError(f"{field} cannot be unspecified or multicast")
    return str(address)


def _positive_group(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise AuditValidationError(f"{field} must be an integer between 1 and 65535")
    return value


@dataclass(frozen=True)
class AuditPeerSnapshot:
    """The minimum identity snapshot needed to write an audit observation."""

    configuration_name: str
    public_key: str
    peer_name: str
    tunnel_address: str

    def __post_init__(self) -> None:
        if (
            not isinstance(self.configuration_name, str)
            or not CONFIGURATION_PATTERN.fullmatch(self.configuration_name)
        ):
            raise AuditValidationError("configuration_name contains unsupported characters")
        if not isinstance(self.public_key, str) or not PUBLIC_KEY_PATTERN.fullmatch(self.public_key):
            raise AuditValidationError("public_key is not a WireGuard public key")
        if not isinstance(self.peer_name, str) or len(self.peer_name) > 255:
            raise AuditValidationError("peer_name must be a string up to 255 characters")

        object.__setattr__(self, "tunnel_address", _tunnel_address(self.tunnel_address, "tunnel_address"))

    @classmethod
    def from_payload(cls, payload: Any) -> "AuditPeerSnapshot":
        if not isinstance(payload, Mapping):
            raise AuditValidationError("peer snapshot must be an object")
        expected_fields = {"configuration_name", "public_key", "peer_name", "tunnel_address"}
        unknown_fields = set(payload) - expected_fields
        if unknown_fields:
            raise AuditValidationError(f"unsupported peer snapshot fields: {', '.join(sorted(unknown_fields))}")
        return cls(
            configuration_name=payload.get("configuration_name"),
            public_key=payload.get("public_key"),
            peer_name=payload.get("peer_name"),
            tunnel_address=payload.get("tunnel_address"),
        )

    def to_payload(self) -> dict[str, str]:
        return {
            "configuration_name": self.configuration_name,
            "public_key": self.public_key,
            "peer_name": self.peer_name,
            "tunnel_address": self.tunnel_address,
        }


@dataclass(frozen=True)
class AuditAgentConfig:
    """A complete, strictly validated audit-agent configuration generation."""

    version: int
    generation: int
    interface_name: str
    mode: AuditMode | str
    peers: tuple[AuditPeerSnapshot, ...]
    managed_tunnel_addresses: tuple[str, ...]
    observation_nflog_group: int
    policy_allowed_nflog_group: int
    policy_denied_nflog_group: int

    def __post_init__(self) -> None:
        if self.version != AUDIT_CONFIG_VERSION:
            raise AuditValidationError(f"version must be {AUDIT_CONFIG_VERSION}")
        if isinstance(self.generation, bool) or not isinstance(self.generation, int) or self.generation < 0:
            raise AuditValidationError("generation must be a zero or greater integer")
        if not isinstance(self.interface_name, str) or not INTERFACE_PATTERN.fullmatch(self.interface_name):
            raise AuditValidationError("interface_name contains unsupported characters")
        try:
            mode = AuditMode(self.mode)
        except ValueError as error:
            raise AuditValidationError("mode must be all or managed") from error

        peers = tuple(self.peers)
        if not all(isinstance(peer, AuditPeerSnapshot) for peer in peers):
            raise AuditValidationError("peers must contain peer snapshots")
        peer_addresses = [peer.tunnel_address for peer in peers]
        if len(peer_addresses) != len(set(peer_addresses)):
            raise AuditValidationError("peers cannot reuse tunnel_address values")

        managed_addresses = tuple(
            _tunnel_address(address, "managed_tunnel_addresses") for address in self.managed_tunnel_addresses
        )
        if len(managed_addresses) != len(set(managed_addresses)):
            raise AuditValidationError("managed_tunnel_addresses cannot contain duplicates")
        if not set(managed_addresses).issubset(set(peer_addresses)):
            raise AuditValidationError("managed_tunnel_addresses must reference configured peers")

        groups = (
            _positive_group(self.observation_nflog_group, "observation_nflog_group"),
            _positive_group(self.policy_allowed_nflog_group, "policy_allowed_nflog_group"),
            _positive_group(self.policy_denied_nflog_group, "policy_denied_nflog_group"),
        )
        if groups[0] in groups[1:]:
            raise AuditValidationError("observation_nflog_group must not reuse a policy verdict group")

        object.__setattr__(self, "mode", mode)
        object.__setattr__(self, "peers", peers)
        object.__setattr__(self, "managed_tunnel_addresses", managed_addresses)
        object.__setattr__(self, "observation_nflog_group", groups[0])
        object.__setattr__(self, "policy_allowed_nflog_group", groups[1])
        object.__setattr__(self, "policy_denied_nflog_group", groups[2])

    @classmethod
    def from_payload(cls, payload: Any) -> "AuditAgentConfig":
        if not isinstance(payload, Mapping):
            raise AuditValidationError("audit configuration must be an object")
        expected_fields = {
            "version", "generation", "interface_name", "mode", "peers", "managed_tunnel_addresses",
            "observation_nflog_group", "policy_allowed_nflog_group", "policy_denied_nflog_group",
        }
        unknown_fields = set(payload) - expected_fields
        if unknown_fields:
            raise AuditValidationError(f"unsupported audit configuration fields: {', '.join(sorted(unknown_fields))}")
        peers = payload.get("peers")
        addresses = payload.get("managed_tunnel_addresses")
        if not isinstance(peers, list) or not isinstance(addresses, list):
            raise AuditValidationError("peers and managed_tunnel_addresses must be arrays")
        return cls(
            version=payload.get("version"),
            generation=payload.get("generation"),
            interface_name=payload.get("interface_name"),
            mode=payload.get("mode"),
            peers=tuple(AuditPeerSnapshot.from_payload(peer) for peer in peers),
            managed_tunnel_addresses=tuple(addresses),
            observation_nflog_group=payload.get("observation_nflog_group"),
            policy_allowed_nflog_group=payload.get("policy_allowed_nflog_group"),
            policy_denied_nflog_group=payload.get("policy_denied_nflog_group"),
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "generation": self.generation,
            "interface_name": self.interface_name,
            "mode": self.mode.value,
            "peers": [peer.to_payload() for peer in self.peers],
            "managed_tunnel_addresses": list(self.managed_tunnel_addresses),
            "observation_nflog_group": self.observation_nflog_group,
            "policy_allowed_nflog_group": self.policy_allowed_nflog_group,
            "policy_denied_nflog_group": self.policy_denied_nflog_group,
        }

    def peer_for_tunnel(self, tunnel_address: str) -> AuditPeerSnapshot | None:
        return next((peer for peer in self.peers if peer.tunnel_address == tunnel_address), None)

    def should_collect(self, tunnel_address: str) -> bool:
        if self.peer_for_tunnel(tunnel_address) is None:
            return False
        return self.mode == AuditMode.ALL or tunnel_address in self.managed_tunnel_addresses


@dataclass(frozen=True)
class AuditAgentRequest:
    """A versioned local control request with no nftables program input."""

    action: str
    config: AuditAgentConfig | None = None

    def __post_init__(self) -> None:
        if self.action not in ALL_ACTIONS:
            raise AuditAgentProtocolError("unsupported action")
        if self.action in CONFIG_ACTIONS and not isinstance(self.config, AuditAgentConfig):
            raise AuditAgentProtocolError("action requires an audit configuration")
        if self.action not in CONFIG_ACTIONS and self.config is not None:
            raise AuditAgentProtocolError("action does not accept an audit configuration")

    @classmethod
    def from_payload(cls, payload: Any) -> "AuditAgentRequest":
        if not isinstance(payload, Mapping):
            raise AuditAgentProtocolError("request must be an object")
        expected_fields = {"version", "action", "config"}
        unknown_fields = set(payload) - expected_fields
        if unknown_fields:
            raise AuditAgentProtocolError(f"unsupported request fields: {', '.join(sorted(unknown_fields))}")
        if payload.get("version") != AGENT_PROTOCOL_VERSION:
            raise AuditAgentProtocolError("unsupported protocol version")
        action = payload.get("action")
        if action not in ALL_ACTIONS:
            raise AuditAgentProtocolError("unsupported action")
        if action in CONFIG_ACTIONS:
            try:
                config = AuditAgentConfig.from_payload(payload.get("config"))
            except AuditValidationError as error:
                raise AuditAgentProtocolError(str(error)) from error
        elif "config" in payload:
            raise AuditAgentProtocolError("action does not accept an audit configuration")
        else:
            config = None
        return cls(action=action, config=config)

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"version": AGENT_PROTOCOL_VERSION, "action": self.action}
        if self.config is not None:
            payload["config"] = self.config.to_payload()
        return payload


def encode_message(payload: Mapping[str, Any]) -> bytes:
    encoded = json.dumps(dict(payload), sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(encoded) > MAX_MESSAGE_BYTES:
        raise AuditAgentProtocolError("message exceeds size limit")
    return encoded


def decode_message(raw: bytes) -> dict[str, Any]:
    if not raw or len(raw) > MAX_MESSAGE_BYTES:
        raise AuditAgentProtocolError("invalid message size")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AuditAgentProtocolError("invalid JSON message") from error
    if not isinstance(payload, dict):
        raise AuditAgentProtocolError("message must be an object")
    return payload
