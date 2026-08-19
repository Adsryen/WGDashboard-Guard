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
INPUT_CHAIN_NAME = "input"
DENIAL_NAT_CHAIN_NAME = "denial_prerouting"
DENIAL_RESPONSE_PORT = 61573
POLICY_RENDERER_VERSION = 2
NFLOG_POLICY_DECISION_GROUP = 11501
NFLOG_POLICY_ALLOWED_PREFIX = "wgd-audit:policy_allowed"
NFLOG_POLICY_DENIED_PREFIX = "wgd-audit:policy_denied"


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
    payload = json.dumps(
        {"renderer_version": POLICY_RENDERER_VERSION, "policies": canonical_policy_payload(policies)},
        sort_keys=True,
        separators=(",", ":"),
    )
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
        f'{family} daddr {rule.destination}'
    )
    if rule.protocol == "icmp":
        expression += " meta l4proto icmp" if family == "ip" else " meta l4proto ipv6-icmp"
    elif rule.port_from is not None:
        port_range = str(rule.port_from) if rule.port_from == rule.port_to else f"{rule.port_from}-{rule.port_to}"
        expression += f" {rule.protocol} dport {port_range}"
    else:
        expression += f" meta l4proto {rule.protocol}"
    return expression


def _deny_expression(policy: NetworkPolicy) -> str:
    family = _address_family(policy.tunnel_address)
    return f'iifname "{policy.interface_name}" {family} saddr {policy.tunnel_address}'


def _decision_log_expression(decision: str) -> str:
    prefix = NFLOG_POLICY_ALLOWED_PREFIX if decision == "policy_allowed" else NFLOG_POLICY_DENIED_PREFIX
    return f'log prefix "{prefix}" group {NFLOG_POLICY_DECISION_GROUP}'


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
        (
            f"add chain {TABLE_FAMILY} {table_name} {INPUT_CHAIN_NAME} "
            f"{{ type filter hook input priority {CHAIN_PRIORITY}; policy accept; }}"
        ),
        (
            f"add chain {TABLE_FAMILY} {table_name} {DENIAL_NAT_CHAIN_NAME} "
            "{ type nat hook prerouting priority dstnat; policy accept; }"
        ),
    ]

    for policy in canonical_policy_payload(policies):
        validated = NetworkPolicy.from_payload(policy)
        deny_expression = _deny_expression(validated)
        family = _address_family(validated.tunnel_address)
        if family == "ip":
            for rule in sorted(validated.rules, key=_rule_sort_key):
                if rule.protocol != "tcp":
                    continue
                lines.append(
                    f"add rule {TABLE_FAMILY} {table_name} {DENIAL_NAT_CHAIN_NAME} "
                    f"{_rule_expression(validated, rule)} accept "
                    f"comment \"wgd-policy:{digest}\""
                )
            lines.append(
                f"add rule {TABLE_FAMILY} {table_name} {DENIAL_NAT_CHAIN_NAME} "
                f"{deny_expression} tcp dport {DENIAL_RESPONSE_PORT} accept "
                f"comment \"wgd-denial-guard\""
            )
            lines.append(
                f"add rule {TABLE_FAMILY} {table_name} {DENIAL_NAT_CHAIN_NAME} "
                f"{deny_expression} meta l4proto tcp {_decision_log_expression('policy_denied')} "
                f"redirect to :{DENIAL_RESPONSE_PORT} "
                f"comment \"wgd-policy:{digest}\""
            )
            lines.append(
                f"add rule {TABLE_FAMILY} {table_name} {INPUT_CHAIN_NAME} "
                f"{deny_expression} ct status dnat tcp dport {DENIAL_RESPONSE_PORT} accept "
                f"comment \"wgd-policy:{digest}\""
            )
        for rule in sorted(validated.rules, key=_rule_sort_key):
            if rule.protocol == "icmp":
                continue
            lines.append(
                f"add rule {TABLE_FAMILY} {table_name} {CHAIN_NAME} "
                f"{_rule_expression(validated, rule)} {_decision_log_expression('policy_allowed')} "
                f"accept comment \"wgd-policy:{digest}\""
            )
        protocol = "icmp" if family == "ip" else "ipv6-icmp"
        destinations = sorted({rule.destination for rule in validated.rules})
        for destination in destinations:
            lines.append(
                f"add rule {TABLE_FAMILY} {table_name} {CHAIN_NAME} "
                f'iifname "{validated.interface_name}" {family} saddr {validated.tunnel_address} '
                f"{family} daddr {destination} meta l4proto {protocol} "
                f"{_decision_log_expression('policy_allowed')} accept "
                f"comment \"wgd-policy:{digest}\""
            )
        lines.append(
            f"add rule {TABLE_FAMILY} {table_name} {CHAIN_NAME} "
            f"{deny_expression} meta l4proto tcp {_decision_log_expression('policy_denied')} "
            f"reject with tcp reset "
            f"comment \"wgd-policy:{digest}\""
        )
        reject_type = "icmp port-unreachable" if family == "ip" else "icmpv6 type admin-prohibited"
        lines.append(
            f"add rule {TABLE_FAMILY} {table_name} {CHAIN_NAME} "
            f"{deny_expression} meta l4proto udp {_decision_log_expression('policy_denied')} "
            f"reject with {reject_type} "
            f"comment \"wgd-policy:{digest}\""
        )
        lines.append(
            f"add rule {TABLE_FAMILY} {table_name} {CHAIN_NAME} "
            f"{deny_expression} {_decision_log_expression('policy_denied')} "
            f"reject with {reject_type} comment \"wgd-policy:{digest}\""
        )
    lines.append(
        f"add rule {TABLE_FAMILY} {table_name} {INPUT_CHAIN_NAME} "
        f"tcp dport {DENIAL_RESPONSE_PORT} reject with tcp reset comment \"wgd-denial-guard\""
    )
    return "\n".join(lines) + "\n", digest


def compile_check_ruleset(policies: Iterable[NetworkPolicy]) -> tuple[str, str]:
    """Return a standalone ruleset suitable for `nft --check` without mutation."""
    body, digest = compile_ruleset(policies, f"{TABLE_NAME}_check")
    return f"add table {TABLE_FAMILY} {TABLE_NAME}_check\n{body}", digest
