"""Validation and canonicalization for untrusted network-policy payloads."""

from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import re
from typing import Any


PUBLIC_KEY_PATTERN = re.compile(r"^[A-Za-z0-9+/]{43}=$")
INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")
CONFIGURATION_PATTERN = re.compile(r"^[A-Za-z0-9_.-]{1,63}$")
SUPPORTED_PROTOCOLS = {"tcp", "udp", "icmp"}


class PolicyValidationError(ValueError):
    """Raised when a policy cannot be safely compiled for nftables."""


def _require_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise PolicyValidationError(f"{field} must be a non-empty string")
    return value


def _network(value: Any) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    destination = _require_string(value, "destination")
    try:
        parsed = ipaddress.ip_network(destination, strict=False)
    except ValueError as error:
        raise PolicyValidationError("destination must be an IPv4 or IPv6 address/CIDR") from error
    if parsed.is_unspecified or parsed.is_multicast:
        raise PolicyValidationError("destination cannot be unspecified or multicast")
    return parsed


def _address(value: Any) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    tunnel_address = _require_string(value, "tunnel_address")
    try:
        parsed = ipaddress.ip_address(tunnel_address)
    except ValueError as error:
        raise PolicyValidationError("tunnel_address must be an IPv4 or IPv6 address") from error
    if parsed.is_unspecified or parsed.is_multicast:
        raise PolicyValidationError("tunnel_address cannot be unspecified or multicast")
    return parsed


def _port(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise PolicyValidationError(f"{field} must be an integer between 1 and 65535")
    return value


@dataclass(frozen=True)
class NetworkPolicyRule:
    destination: str
    protocol: str
    port_from: int | None = None
    port_to: int | None = None

    @classmethod
    def from_payload(cls, payload: Any) -> "NetworkPolicyRule":
        if not isinstance(payload, dict):
            raise PolicyValidationError("rule must be an object")

        destination = _network(payload.get("destination"))
        protocol = payload.get("protocol")
        if protocol not in SUPPORTED_PROTOCOLS:
            raise PolicyValidationError("protocol must be tcp, udp, or icmp")

        ports = payload.get("ports")
        if ports is None:
            port_from = None
            port_to = None
        else:
            if protocol == "icmp":
                raise PolicyValidationError("icmp rules cannot contain ports")
            if not isinstance(ports, dict):
                raise PolicyValidationError("ports must be null or an object")
            port_from = _port(ports.get("from"), "ports.from")
            port_to = _port(ports.get("to"), "ports.to")
            if port_from > port_to:
                raise PolicyValidationError("ports.from cannot be greater than ports.to")

        return cls(str(destination), protocol, port_from, port_to)

    def to_payload(self) -> dict[str, Any]:
        ports = None
        if self.port_from is not None:
            ports = {"from": self.port_from, "to": self.port_to}
        return {"destination": self.destination, "protocol": self.protocol, "ports": ports}


@dataclass(frozen=True)
class NetworkPolicy:
    configuration_name: str
    interface_name: str
    peer_public_key: str
    tunnel_address: str
    managed: bool
    rules: tuple[NetworkPolicyRule, ...]

    @classmethod
    def from_payload(cls, payload: Any) -> "NetworkPolicy":
        if not isinstance(payload, dict):
            raise PolicyValidationError("policy must be an object")

        configuration_name = _require_string(payload.get("configuration_name"), "configuration_name")
        if not CONFIGURATION_PATTERN.fullmatch(configuration_name):
            raise PolicyValidationError("configuration_name contains unsupported characters")

        interface_name = _require_string(payload.get("interface_name"), "interface_name")
        if not INTERFACE_PATTERN.fullmatch(interface_name):
            raise PolicyValidationError("interface_name contains unsupported characters")

        peer_public_key = _require_string(payload.get("peer_public_key"), "peer_public_key")
        if not PUBLIC_KEY_PATTERN.fullmatch(peer_public_key):
            raise PolicyValidationError("peer_public_key is not a WireGuard public key")

        tunnel_address = _address(payload.get("tunnel_address"))
        managed = payload.get("managed", True)
        if not isinstance(managed, bool):
            raise PolicyValidationError("managed must be a boolean")

        raw_rules = payload.get("rules", [])
        if not isinstance(raw_rules, list):
            raise PolicyValidationError("rules must be an array")
        rules = tuple(NetworkPolicyRule.from_payload(rule) for rule in raw_rules)
        if not managed and rules:
            raise PolicyValidationError("unmanaged policies cannot contain rules")

        return cls(
            configuration_name=configuration_name,
            interface_name=interface_name,
            peer_public_key=peer_public_key,
            tunnel_address=str(tunnel_address),
            managed=managed,
            rules=rules,
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "configuration_name": self.configuration_name,
            "interface_name": self.interface_name,
            "peer_public_key": self.peer_public_key,
            "tunnel_address": self.tunnel_address,
            "managed": self.managed,
            "rules": [rule.to_payload() for rule in self.rules],
        }


def validate_policy(payload: Any) -> NetworkPolicy:
    """Validate and canonicalize one Dashboard/Agent policy payload."""
    return NetworkPolicy.from_payload(payload)


def validate_policies(payload: Any) -> tuple[NetworkPolicy, ...]:
    if not isinstance(payload, list):
        raise PolicyValidationError("policies must be an array")
    policies = tuple(validate_policy(policy) for policy in payload)
    bindings = {(p.interface_name, p.tunnel_address) for p in policies if p.managed}
    if len(bindings) != sum(policy.managed for policy in policies):
        raise PolicyValidationError("a managed tunnel address can only belong to one policy per interface")
    return policies
