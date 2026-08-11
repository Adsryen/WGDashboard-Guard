"""Deterministic nftables renderer. This module never executes nft."""

from __future__ import annotations

from hashlib import sha256
import ipaddress
import json
from typing import Iterable

from .validation import NetworkPolicy, NetworkPolicyRule, validate_policies


TABLE_FAMILY = "inet"
TABLE_NAME = "wgd_network_policy"
CHAIN_NAME = "forward"
CHAIN_PRIORITY = "filter - 10"


def canonical_policy_payload(policies: Iterable[NetworkPolicy]) -> list[dict]:
    canonical = []
    for policy in sorted(
        (policy for policy in policies if policy.managed),
        key=lambda policy: (policy.interface_name, policy.tunnel_address, policy.peer_public_key),
    ):
        payload = policy.to_payload()
        payload["rules"] = [rule.to_payload() for rule in sorted(policy.rules, key=_rule_sort_key)]
        canonical.append(payload)
    return canonical


def policy_hash(policies: Iterable[NetworkPolicy]) -> str:
    payload = json.dumps(canonical_policy_payload(policies), sort_keys=True, separators=(",", ":"))
    return sha256(payload.encode("utf-8")).hexdigest()


def _address_family(address: str) -> str:
    return "ip6" if ipaddress.ip_address(address).version == 6 else "ip"


def _rule_sort_key(rule: NetworkPolicyRule) -> tuple:
    return (rule.destination, rule.protocol, rule.port_from or 0, rule.port_to or 0)


def _rule_expression(policy: NetworkPolicy, rule: NetworkPolicyRule) -> str:
    family = _address_family(policy.tunnel_address)
    destination = ipaddress.ip_network(rule.destination)
    if destination.version != ipaddress.ip_address(policy.tunnel_address).version:
        raise ValueError("rule destination address family does not match the peer tunnel address")

    expression = (
        f'iifname "{policy.interface_name}" {family} saddr {policy.tunnel_address} '
        f'{family} daddr {rule.destination} {rule.protocol}'
    )
    if rule.port_from is not None:
        port_range = str(rule.port_from) if rule.port_from == rule.port_to else f"{rule.port_from}-{rule.port_to}"
        expression += f" dport {port_range}"
    return expression


def compile_ruleset(policies: Iterable[NetworkPolicy], table_name: str = TABLE_NAME) -> tuple[str, str]:
    """Compile validated policies into an idempotent body for an existing table."""
    if table_name != TABLE_NAME and not table_name.endswith("_check"):
        raise ValueError("unsupported nftables table name")

    policies = validate_policies([policy.to_payload() for policy in policies])
    digest = policy_hash(policies)
    lines = [
        f"flush table {TABLE_FAMILY} {table_name}",
        (
            f"add chain {TABLE_FAMILY} {table_name} {CHAIN_NAME} "
            f"{{ type filter hook forward priority {CHAIN_PRIORITY}; policy accept; }}"
        ),
    ]

    for policy in canonical_policy_payload(policies):
        validated = NetworkPolicy.from_payload(policy)
        for rule in sorted(validated.rules, key=_rule_sort_key):
            lines.append(
                f"add rule {TABLE_FAMILY} {table_name} {CHAIN_NAME} "
                f"{_rule_expression(validated, rule)} accept comment \"wgd-policy:{digest}\""
            )
        family = _address_family(validated.tunnel_address)
        lines.append(
            f"add rule {TABLE_FAMILY} {table_name} {CHAIN_NAME} "
            f'iifname "{validated.interface_name}" {family} saddr {validated.tunnel_address} '
            f'counter drop comment "wgd-policy:{digest}"'
        )
    return "\n".join(lines) + "\n", digest


def compile_check_ruleset(policies: Iterable[NetworkPolicy]) -> tuple[str, str]:
    """Return a standalone ruleset suitable for `nft --check` without mutation."""
    body, digest = compile_ruleset(policies, f"{TABLE_NAME}_check")
    return f"add table {TABLE_FAMILY} {TABLE_NAME}_check\n{body}", digest
