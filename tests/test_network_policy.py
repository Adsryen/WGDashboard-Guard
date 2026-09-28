from __future__ import annotations

import pathlib
import json
import re
import sys
import tempfile
import threading
import unittest
from http.client import HTTPConnection
from subprocess import CompletedProcess

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "src"))

try:
    import sqlalchemy as db
    from network_policy.reconcile import EXIT_DRIFT, EXIT_FAILED, EXIT_IN_SYNC, reconcile
    from network_policy.service import (
        NetworkPolicyService,
        NetworkPolicyServiceError,
        desired_fingerprint,
        runtime_is_in_sync,
    )
except ModuleNotFoundError:
    db = None
    NetworkPolicyService = None
    NetworkPolicyServiceError = RuntimeError
    EXIT_DRIFT = EXIT_FAILED = EXIT_IN_SYNC = None
    reconcile = None
    desired_fingerprint = runtime_is_in_sync = None


from network_policy.agent_protocol import AgentProtocolError, AgentRequest
from network_policy.agent import NftablesExecutor
import network_policy.compiler as policy_compiler
from network_policy.compiler import (
    DENIAL_RESPONSE_PORT,
    POLICY_RENDERER_VERSION,
    NFLOG_POLICY_ALLOWED_PREFIX,
    NFLOG_POLICY_DECISION_GROUP,
    NFLOG_POLICY_DENIED_PREFIX,
    TABLE_NAME,
    compile_check_ruleset,
    compile_ruleset,
    policy_hash,
)
from network_policy.denial_responder import DenialRequestHandler, ThreadingHTTPServer
from network_policy.validation import PolicyValidationError, validate_policy


PUBLIC_KEY = "a" * 43 + "="
NETWORK_POLICY_LOCALE_DYNAMIC_KEYS = {
    "Applied",
    "Apply only after reviewing the generated rules.",
    "Apply reviewed changes",
    "Changes not applied",
	"Disabled",
    "Forwarded access control disabled",
    "Forwarded access control enabled",
    "Forwarding access control is off. This Peer keeps the gateway's existing forwarding behavior.",
    "Loading policy state",
    "Not configured",
    "Only the destinations below are allowed. All other forwarded traffic from this Peer is denied after application.",
    "Preview ready - confirm to apply",
    "Review changes",
    "Review changes to generate the exact nftables rules.",
    "Add destination group",
    "Remove destination group",
    "Add port",
    "Add port range",
    "Remove port",
    "Use specific ports",
    "Enter a destination IP or CIDR.",
    "Add at least one port.",
    "All ports cannot be combined with specific ports.",
    "This port overlaps another port in this group.",
    "Port group summary",
    "flattened rules",
}


def policy_payload(**overrides):
    payload = {
        "configuration_name": "wg0",
        "interface_name": "wg0",
        "peer_public_key": PUBLIC_KEY,
        "tunnel_address": "10.8.0.2",
        "managed": True,
        "rules": [
            {"destination": "192.168.0.170", "protocol": "tcp", "ports": None},
            {"destination": "192.168.0.170", "protocol": "udp", "ports": None},
            {
                "destination": "192.168.10.117/32",
                "protocol": "tcp",
                "ports": {"from": 8118, "to": 8118},
            },
        ],
    }
    payload.update(overrides)
    return payload


FORWARD_SNAPSHOT = [
    'add chain inet wgd_network_policy forward { type filter hook forward priority filter - 10; policy accept; }',
    'add rule inet wgd_network_policy forward iifname "wg0" ip saddr 10.253.157.2 ip daddr 192.168.0.117/32 meta l4proto tcp log prefix "wgd-audit:policy_allowed" group 11501 accept comment "wgd-policy:@DIGEST@"',
    'add rule inet wgd_network_policy forward iifname "wg0" ip saddr 10.253.157.2 ip daddr 192.168.0.134/32 tcp dport 8096 log prefix "wgd-audit:policy_allowed" group 11501 accept comment "wgd-policy:@DIGEST@"',
    'add rule inet wgd_network_policy forward iifname "wg0" ip saddr 10.253.157.2 ip daddr 192.168.0.117/32 meta l4proto icmp log prefix "wgd-audit:policy_allowed" group 11501 accept comment "wgd-policy:@DIGEST@"',
    'add rule inet wgd_network_policy forward iifname "wg0" ip saddr 10.253.157.2 ip daddr 192.168.0.134/32 meta l4proto icmp log prefix "wgd-audit:policy_allowed" group 11501 accept comment "wgd-policy:@DIGEST@"',
    'add rule inet wgd_network_policy forward iifname "wg0" ip saddr 10.253.157.2 meta l4proto tcp log prefix "wgd-audit:policy_denied" group 11501 reject with tcp reset comment "wgd-policy:@DIGEST@"',
    'add rule inet wgd_network_policy forward iifname "wg0" ip saddr 10.253.157.2 meta l4proto udp log prefix "wgd-audit:policy_denied" group 11501 reject with icmp port-unreachable comment "wgd-policy:@DIGEST@"',
    'add rule inet wgd_network_policy forward iifname "wg0" ip saddr 10.253.157.2 log prefix "wgd-audit:policy_denied" group 11501 reject with icmp port-unreachable comment "wgd-policy:@DIGEST@"',
    'add rule inet wgd_network_policy forward iifname "wg0" ip saddr 10.253.157.49 ip daddr 192.168.0.175/32 tcp dport 3000 log prefix "wgd-audit:policy_allowed" group 11501 accept comment "wgd-policy:@DIGEST@"',
    'add rule inet wgd_network_policy forward iifname "wg0" ip saddr 10.253.157.49 ip daddr 192.168.0.175/32 tcp dport 5432 log prefix "wgd-audit:policy_allowed" group 11501 accept comment "wgd-policy:@DIGEST@"',
    'add rule inet wgd_network_policy forward iifname "wg0" ip saddr 10.253.157.49 ip daddr 192.168.0.175/32 tcp dport 5435 log prefix "wgd-audit:policy_allowed" group 11501 accept comment "wgd-policy:@DIGEST@"',
    'add rule inet wgd_network_policy forward iifname "wg0" ip saddr 10.253.157.49 ip daddr 192.168.0.175/32 tcp dport 6379 log prefix "wgd-audit:policy_allowed" group 11501 accept comment "wgd-policy:@DIGEST@"',
    'add rule inet wgd_network_policy forward iifname "wg0" ip saddr 10.253.157.49 ip daddr 192.168.0.175/32 tcp dport 8080 log prefix "wgd-audit:policy_allowed" group 11501 accept comment "wgd-policy:@DIGEST@"',
    'add rule inet wgd_network_policy forward iifname "wg0" ip saddr 10.253.157.49 ip daddr 192.168.0.175/32 tcp dport 8888 log prefix "wgd-audit:policy_allowed" group 11501 accept comment "wgd-policy:@DIGEST@"',
    'add rule inet wgd_network_policy forward iifname "wg0" ip saddr 10.253.157.49 ip daddr 192.168.0.175/32 tcp dport 9090 log prefix "wgd-audit:policy_allowed" group 11501 accept comment "wgd-policy:@DIGEST@"',
    'add rule inet wgd_network_policy forward iifname "wg0" ip saddr 10.253.157.49 ip daddr 192.168.0.175/32 tcp dport 19100 log prefix "wgd-audit:policy_allowed" group 11501 accept comment "wgd-policy:@DIGEST@"',
    'add rule inet wgd_network_policy forward iifname "wg0" ip saddr 10.253.157.49 ip daddr 192.168.0.175/32 tcp dport 19256 log prefix "wgd-audit:policy_allowed" group 11501 accept comment "wgd-policy:@DIGEST@"',
    'add rule inet wgd_network_policy forward iifname "wg0" ip saddr 10.253.157.49 ip daddr 192.168.0.175/32 meta l4proto icmp log prefix "wgd-audit:policy_allowed" group 11501 accept comment "wgd-policy:@DIGEST@"',
    'add rule inet wgd_network_policy forward iifname "wg0" ip saddr 10.253.157.49 meta l4proto tcp log prefix "wgd-audit:policy_denied" group 11501 reject with tcp reset comment "wgd-policy:@DIGEST@"',
    'add rule inet wgd_network_policy forward iifname "wg0" ip saddr 10.253.157.49 meta l4proto udp log prefix "wgd-audit:policy_denied" group 11501 reject with icmp port-unreachable comment "wgd-policy:@DIGEST@"',
    'add rule inet wgd_network_policy forward iifname "wg0" ip saddr 10.253.157.49 log prefix "wgd-audit:policy_denied" group 11501 reject with icmp port-unreachable comment "wgd-policy:@DIGEST@"',
]


DENIAL_PREROUTING_SNAPSHOT = [
    'add chain inet wgd_network_policy denial_prerouting { type nat hook prerouting priority dstnat; policy accept; }',
    'add rule inet wgd_network_policy denial_prerouting iifname "wg0" ip saddr 10.253.157.2 ip daddr 192.168.0.117/32 meta l4proto tcp accept comment "wgd-policy:@DIGEST@"',
    'add rule inet wgd_network_policy denial_prerouting iifname "wg0" ip saddr 10.253.157.2 ip daddr 192.168.0.134/32 tcp dport 8096 accept comment "wgd-policy:@DIGEST@"',
    'add rule inet wgd_network_policy denial_prerouting iifname "wg0" ip saddr 10.253.157.2 tcp dport 61573 accept comment "wgd-denial-guard"',
    'add rule inet wgd_network_policy denial_prerouting iifname "wg0" ip saddr 10.253.157.2 meta l4proto tcp log prefix "wgd-audit:policy_denied" group 11501 redirect to :61573 comment "wgd-policy:@DIGEST@"',
    'add rule inet wgd_network_policy denial_prerouting iifname "wg0" ip saddr 10.253.157.49 ip daddr 192.168.0.175/32 tcp dport 3000 accept comment "wgd-policy:@DIGEST@"',
    'add rule inet wgd_network_policy denial_prerouting iifname "wg0" ip saddr 10.253.157.49 ip daddr 192.168.0.175/32 tcp dport 5432 accept comment "wgd-policy:@DIGEST@"',
    'add rule inet wgd_network_policy denial_prerouting iifname "wg0" ip saddr 10.253.157.49 ip daddr 192.168.0.175/32 tcp dport 5435 accept comment "wgd-policy:@DIGEST@"',
    'add rule inet wgd_network_policy denial_prerouting iifname "wg0" ip saddr 10.253.157.49 ip daddr 192.168.0.175/32 tcp dport 6379 accept comment "wgd-policy:@DIGEST@"',
    'add rule inet wgd_network_policy denial_prerouting iifname "wg0" ip saddr 10.253.157.49 ip daddr 192.168.0.175/32 tcp dport 8080 accept comment "wgd-policy:@DIGEST@"',
    'add rule inet wgd_network_policy denial_prerouting iifname "wg0" ip saddr 10.253.157.49 ip daddr 192.168.0.175/32 tcp dport 8888 accept comment "wgd-policy:@DIGEST@"',
    'add rule inet wgd_network_policy denial_prerouting iifname "wg0" ip saddr 10.253.157.49 ip daddr 192.168.0.175/32 tcp dport 9090 accept comment "wgd-policy:@DIGEST@"',
    'add rule inet wgd_network_policy denial_prerouting iifname "wg0" ip saddr 10.253.157.49 ip daddr 192.168.0.175/32 tcp dport 19100 accept comment "wgd-policy:@DIGEST@"',
    'add rule inet wgd_network_policy denial_prerouting iifname "wg0" ip saddr 10.253.157.49 ip daddr 192.168.0.175/32 tcp dport 19256 accept comment "wgd-policy:@DIGEST@"',
    'add rule inet wgd_network_policy denial_prerouting iifname "wg0" ip saddr 10.253.157.49 tcp dport 61573 accept comment "wgd-denial-guard"',
    'add rule inet wgd_network_policy denial_prerouting iifname "wg0" ip saddr 10.253.157.49 meta l4proto tcp log prefix "wgd-audit:policy_denied" group 11501 redirect to :61573 comment "wgd-policy:@DIGEST@"',
]

class NetworkPolicyValidationTest(unittest.TestCase):
    def test_canonicalizes_addresses_and_keeps_all_ports_explicit(self):
        policy = validate_policy(policy_payload(tunnel_address="10.8.0.2"))
        self.assertEqual("192.168.0.170/32", policy.rules[0].destination)
        self.assertIsNone(policy.rules[0].port_from)
        self.assertEqual("10.8.0.2", policy.tunnel_address)

    def test_rejects_injected_interface_and_non_wireguard_key(self):
        with self.assertRaises(PolicyValidationError):
            validate_policy(policy_payload(interface_name='wg0"; drop table inet filter; #'))
        with self.assertRaises(PolicyValidationError):
            validate_policy(policy_payload(peer_public_key="not-a-key"))

    def test_rejects_invalid_ports_and_mixed_address_families(self):
        with self.assertRaises(PolicyValidationError):
            validate_policy(policy_payload(rules=[{"destination": "192.168.0.170", "protocol": "tcp", "ports": {"from": 0, "to": 22}}]))

        policy = validate_policy(policy_payload(rules=[{"destination": "2001:db8::1", "protocol": "tcp", "ports": None}]))
        with self.assertRaises(ValueError):
            compile_ruleset([policy])

    def test_accepts_icmp_without_ports_and_rejects_icmp_port_ranges(self):
        policy = validate_policy(policy_payload(rules=[{
            "destination": "192.168.0.170",
            "protocol": "icmp",
            "ports": None,
        }]))
        self.assertEqual("icmp", policy.rules[0].protocol)

        with self.assertRaises(PolicyValidationError):
            validate_policy(policy_payload(rules=[{
                "destination": "192.168.0.170",
                "protocol": "icmp",
                "ports": {"from": 8, "to": 8},
            }]))

    def test_unmanaged_policies_cannot_carry_rules(self):
        # The UI sends managed=false together with an emptied rule set when the
        # operator turns forwarded access control off. Rules surviving that
        # switch would silently keep the Peer restricted, so the API refuses it.
        with self.assertRaisesRegex(PolicyValidationError, "unmanaged policies cannot contain rules"):
            validate_policy(policy_payload(managed=False))

        self.assertEqual((), validate_policy(policy_payload(managed=False, rules=[])).rules)


class NetworkPolicyLocaleTest(unittest.TestCase):
    def test_chinese_translates_every_network_policy_ui_key(self):
        root = pathlib.Path(__file__).resolve().parents[1]
        source = (root / "src/static/app/src/components/networkPolicy/networkPolicyModal.vue").read_text(encoding="utf-8")
        locale = json.loads((root / "src/static/locales/zh-CN.json").read_text(encoding="utf-8"))
        template = json.loads((root / "src/static/locales/locale_template.json").read_text(encoding="utf-8"))
        keys = {match[1] for match in re.findall(r"<LocaleText\s+t=([\"'])(.*?)\1", source)}
        keys.update(match[1] for match in re.findall(r"GetLocale\(([\"'])(.*?)\1\)", source))
        keys.update(NETWORK_POLICY_LOCALE_DYNAMIC_KEYS)

        self.assertGreater(len(keys), len(NETWORK_POLICY_LOCALE_DYNAMIC_KEYS))

        missing_template = sorted(key for key in keys if key not in template)
        missing_chinese = sorted(key for key in keys if not locale.get(key, "").strip())

        self.assertEqual([], missing_template, f"Missing locale template keys: {missing_template}")
        self.assertEqual([], missing_chinese, f"Missing zh-CN translations: {missing_chinese}")


class NetworkPolicyCompilerTest(unittest.TestCase):
    def test_compiles_each_discontinuous_tcp_port_as_a_distinct_allow_rule(self):
        ports = [3000, 5435, 6379, 8848, 9000, 9001, 19530, 27017]
        policy = validate_policy(policy_payload(rules=[
            {
                "destination": "192.168.0.175/32",
                "protocol": "tcp",
                "ports": {"from": port, "to": port},
            }
            for port in ports
        ]))
        ruleset, _ = compile_ruleset([policy])

        for port in ports:
            self.assertIn(
                f"ip daddr 192.168.0.175/32 tcp dport {port} "
                f'log prefix "{NFLOG_POLICY_ALLOWED_PREFIX}" group {NFLOG_POLICY_DECISION_GROUP} accept',
                ruleset,
            )

    def test_compiles_allow_before_per_peer_default_drop(self):
        policy = validate_policy(policy_payload())
        ruleset, digest = compile_ruleset([policy])

        self.assertIn(f"flush table inet {TABLE_NAME}", ruleset)
        self.assertIn(
            'iifname "wg0" ip saddr 10.8.0.2 ip daddr 192.168.0.170/32 '
            f'meta l4proto tcp log prefix "{NFLOG_POLICY_ALLOWED_PREFIX}" '
            f'group {NFLOG_POLICY_DECISION_GROUP} accept',
            ruleset,
        )
        self.assertIn(
            f'tcp dport 8118 log prefix "{NFLOG_POLICY_ALLOWED_PREFIX}" '
            f'group {NFLOG_POLICY_DECISION_GROUP} accept',
            ruleset,
        )
        self.assertIn(
            f'ip daddr 192.168.0.170/32 meta l4proto icmp '
            f'log prefix "{NFLOG_POLICY_ALLOWED_PREFIX}" group {NFLOG_POLICY_DECISION_GROUP} accept',
            ruleset,
        )
        self.assertIn(
            f'ip daddr 192.168.10.117/32 meta l4proto icmp '
            f'log prefix "{NFLOG_POLICY_ALLOWED_PREFIX}" group {NFLOG_POLICY_DECISION_GROUP} accept',
            ruleset,
        )
        self.assertNotIn('ip saddr 10.8.0.2 meta l4proto icmp accept', ruleset)
        self.assertIn(
            f'meta l4proto tcp log prefix "{NFLOG_POLICY_DENIED_PREFIX}" '
            f'group {NFLOG_POLICY_DECISION_GROUP} redirect to :61573',
            ruleset,
        )
        self.assertIn(f'ct status dnat tcp dport {DENIAL_RESPONSE_PORT} accept', ruleset)
        self.assertIn(
            f'meta l4proto tcp log prefix "{NFLOG_POLICY_DENIED_PREFIX}" '
            f'group {NFLOG_POLICY_DECISION_GROUP} reject with tcp reset',
            ruleset,
        )
        self.assertIn(
            f'meta l4proto udp log prefix "{NFLOG_POLICY_DENIED_PREFIX}" '
            f'group {NFLOG_POLICY_DECISION_GROUP} reject with icmp port-unreachable',
            ruleset,
        )
        self.assertIn(f'tcp dport {DENIAL_RESPONSE_PORT} reject with tcp reset', ruleset)
        self.assertLess(
            ruleset.index(
                f'tcp dport 8118 log prefix "{NFLOG_POLICY_ALLOWED_PREFIX}" '
                f'group {NFLOG_POLICY_DECISION_GROUP} accept'
            ),
            ruleset.rindex('meta l4proto tcp log prefix'),
        )
        self.assertIn(f'log prefix "{NFLOG_POLICY_ALLOWED_PREFIX}" group {NFLOG_POLICY_DECISION_GROUP}', ruleset)
        self.assertIn(f'log prefix "{NFLOG_POLICY_DENIED_PREFIX}" group {NFLOG_POLICY_DECISION_GROUP}', ruleset)
        self.assertIn(f'wgd-policy:{digest}', ruleset)
        self.assertNotIn("dport 22", ruleset)

    def test_icmp_is_allowed_only_for_configured_destinations(self):
        policy = validate_policy(policy_payload(rules=[
            {"destination": "192.168.0.170", "protocol": "tcp", "ports": None},
            {"destination": "192.168.0.170", "protocol": "udp", "ports": None},
            {"destination": "192.168.10.117", "protocol": "icmp", "ports": None},
        ]))
        ruleset, _ = compile_ruleset([policy])

        allowed_icmp = (
            f'meta l4proto icmp log prefix "{NFLOG_POLICY_ALLOWED_PREFIX}" '
            f'group {NFLOG_POLICY_DECISION_GROUP} accept'
        )
        self.assertEqual(2, ruleset.count(allowed_icmp))
        self.assertIn(f'ip daddr 192.168.0.170/32 {allowed_icmp}', ruleset)
        self.assertIn(f'ip daddr 192.168.10.117/32 {allowed_icmp}', ruleset)
        self.assertLess(
            ruleset.index(f'ip daddr 192.168.10.117/32 {allowed_icmp}'),
            ruleset.rindex('meta l4proto tcp log prefix'),
        )

    def test_allowed_http_destination_bypasses_denial_redirect(self):
        policy = validate_policy(policy_payload(rules=[
            {"destination": "192.168.0.170", "protocol": "tcp", "ports": {"from": 80, "to": 80}},
            {"destination": "192.168.10.117", "protocol": "tcp", "ports": {"from": 443, "to": 443}},
        ]))
        ruleset, _ = compile_ruleset([policy])

        bypass = 'ip daddr 192.168.0.170/32 tcp dport 80 accept'
        redirect = (
            f'meta l4proto tcp log prefix "{NFLOG_POLICY_DENIED_PREFIX}" '
            f'group {NFLOG_POLICY_DECISION_GROUP} redirect to :{DENIAL_RESPONSE_PORT}'
        )
        self.assertIn(bypass, ruleset)
        self.assertIn(redirect, ruleset)
        self.assertLess(ruleset.index(bypass), ruleset.index(redirect))

    def test_allowed_nonstandard_tcp_destination_bypasses_denial_redirect(self):
        policy = validate_policy(policy_payload(rules=[
            {"destination": "192.168.0.170", "protocol": "tcp", "ports": {"from": 8096, "to": 8096}},
        ]))
        ruleset, _ = compile_ruleset([policy])

        bypass = 'ip daddr 192.168.0.170/32 tcp dport 8096 accept'
        redirect = (
            f'meta l4proto tcp log prefix "{NFLOG_POLICY_DENIED_PREFIX}" '
            f'group {NFLOG_POLICY_DECISION_GROUP} redirect to :{DENIAL_RESPONSE_PORT}'
        )
        self.assertIn(bypass, ruleset)
        self.assertIn(redirect, ruleset)
        self.assertLess(ruleset.index(bypass), ruleset.index(redirect))

    def test_ipv6_policy_does_not_redirect_http_to_ipv4_only_responder(self):
        policy = validate_policy(policy_payload(
            tunnel_address="2001:db8::2",
            rules=[{"destination": "2001:db8:1::1", "protocol": "tcp", "ports": None}],
        ))
        ruleset, _ = compile_ruleset([policy])
        self.assertNotIn(f'redirect to :{DENIAL_RESPONSE_PORT}', ruleset)
        self.assertIn('reject with icmpv6 type admin-prohibited', ruleset)

    def test_ipv6_icmp_uses_the_ipv6_protocol_name(self):
        policy = validate_policy(policy_payload(
            tunnel_address="2001:db8::2",
            rules=[{"destination": "2001:db8:1::1", "protocol": "icmp", "ports": None}],
        ))
        ruleset, _ = compile_ruleset([policy])
        self.assertIn(
            f'meta l4proto ipv6-icmp log prefix "{NFLOG_POLICY_ALLOWED_PREFIX}" '
            f'group {NFLOG_POLICY_DECISION_GROUP} accept',
            ruleset,
        )

    def test_hash_is_stable_for_rule_order(self):
        original = validate_policy(policy_payload())
        reversed_rules = validate_policy(policy_payload(rules=list(reversed(policy_payload()["rules"]))))
        self.assertEqual(policy_hash([original]), policy_hash([reversed_rules]))

    def test_check_ruleset_uses_only_a_temporary_table(self):
        policy = validate_policy(policy_payload())
        ruleset, _ = compile_check_ruleset([policy])
        self.assertIn("add table inet wgd_network_policy_check", ruleset)
        self.assertNotIn("flush table inet wgd_network_policy\n", ruleset)

    def test_input_chain_catchall_rules_for_managed_v4_peer(self):
        policy = validate_policy(policy_payload(tunnel_address="10.8.0.2"))
        ruleset, digest = compile_ruleset([policy])

        expected = [
            f'add rule inet {TABLE_NAME} input iifname "wg0" ip saddr 10.8.0.2 '
            f"ct status dnat tcp dport {DENIAL_RESPONSE_PORT} accept "
            f'comment "wgd-policy:{digest}"',
            f'add rule inet {TABLE_NAME} input iifname "wg0" ip saddr 10.8.0.2 '
            f"ct state established,related accept "
            f'comment "wgd-policy:{digest}"',
            f'add rule inet {TABLE_NAME} input iifname "wg0" ip saddr 10.8.0.2 '
            f'meta l4proto udp log prefix "{NFLOG_POLICY_DENIED_PREFIX}" '
            f"group {NFLOG_POLICY_DECISION_GROUP} reject with icmp port-unreachable "
            f'comment "wgd-policy:{digest}"',
            f'add rule inet {TABLE_NAME} input iifname "wg0" ip saddr 10.8.0.2 '
            f"meta l4proto != tcp meta l4proto != udp meta l4proto != icmp "
            f'log prefix "{NFLOG_POLICY_DENIED_PREFIX}" group {NFLOG_POLICY_DECISION_GROUP} '
            f"reject with icmp port-unreachable "
            f'comment "wgd-policy:{digest}"',
            f"add rule inet {TABLE_NAME} input tcp dport {DENIAL_RESPONSE_PORT} "
            'reject with tcp reset comment "wgd-denial-guard"',
        ]
        input_rules = [line for line in ruleset.splitlines() if line.startswith(f"add rule inet {TABLE_NAME} input ")]
        self.assertEqual(expected, input_rules)

    def test_input_chain_catchall_rules_for_managed_v6_peer(self):
        policy = validate_policy(policy_payload(
            tunnel_address="2001:db8::2",
            rules=[
                {"destination": "2001:db8:1::1", "protocol": "tcp", "ports": None},
                {"destination": "2001:db8:1::1", "protocol": "icmp", "ports": None},
            ],
        ))
        ruleset, digest = compile_ruleset([policy])

        expected = [
            f'add rule inet {TABLE_NAME} input iifname "wg0" ip6 saddr 2001:db8::2 '
            f"ct state established,related accept "
            f'comment "wgd-policy:{digest}"',
            f'add rule inet {TABLE_NAME} input iifname "wg0" ip6 saddr 2001:db8::2 '
            f'meta l4proto udp log prefix "{NFLOG_POLICY_DENIED_PREFIX}" '
            f"group {NFLOG_POLICY_DECISION_GROUP} reject with icmpv6 type admin-prohibited "
            f'comment "wgd-policy:{digest}"',
            f'add rule inet {TABLE_NAME} input iifname "wg0" ip6 saddr 2001:db8::2 '
            f"meta l4proto != tcp meta l4proto != udp meta l4proto != ipv6-icmp "
            f'log prefix "{NFLOG_POLICY_DENIED_PREFIX}" group {NFLOG_POLICY_DECISION_GROUP} '
            f"reject with icmpv6 type admin-prohibited "
            f'comment "wgd-policy:{digest}"',
            f"add rule inet {TABLE_NAME} input tcp dport {DENIAL_RESPONSE_PORT} "
            'reject with tcp reset comment "wgd-denial-guard"',
        ]
        input_rules = [line for line in ruleset.splitlines() if line.startswith(f"add rule inet {TABLE_NAME} input ")]
        self.assertEqual(expected, input_rules)
        self.assertNotIn("ct status dnat", ruleset)

    def test_renderer_version_is_three_and_hash_differs_from_v2(self):
        self.assertEqual(3, POLICY_RENDERER_VERSION)
        policies = [validate_policy(policy_payload())]
        current_hash = policy_hash(policies)
        original_version = policy_compiler.POLICY_RENDERER_VERSION
        try:
            policy_compiler.POLICY_RENDERER_VERSION = 2
            legacy_hash = policy_hash(policies)
        finally:
            policy_compiler.POLICY_RENDERER_VERSION = original_version
        self.assertNotEqual(legacy_hash, current_hash)
        self.assertEqual(current_hash, policy_hash(policies))

    def test_forward_and_denial_prerouting_output_matches_pre_change_snapshot(self):
        phone = validate_policy(policy_payload(
            tunnel_address="10.253.157.2",
            rules=[
                {"destination": "192.168.0.117", "protocol": "tcp", "ports": None},
                {"destination": "192.168.0.134", "protocol": "tcp", "ports": {"from": 8096, "to": 8096}},
                {"destination": "192.168.0.117", "protocol": "icmp", "ports": None},
                {"destination": "192.168.0.134", "protocol": "icmp", "ports": None},
            ],
        ))
        beijing = validate_policy(policy_payload(
            tunnel_address="10.253.157.49",
            rules=[
                {"destination": "192.168.0.175", "protocol": "tcp", "ports": {"from": port, "to": port}}
                for port in [3000, 5432, 5435, 6379, 8080, 8888, 9090, 19100, 19256]
            ] + [{"destination": "192.168.0.175", "protocol": "icmp", "ports": None}],
        ))
        ruleset, digest = compile_ruleset([phone, beijing])

        def snapshot_lines(chain):
            return [
                line for line in ruleset.splitlines()
                if line.startswith(f"add chain inet {TABLE_NAME} {chain} ")
                or line.startswith(f"add rule inet {TABLE_NAME} {chain} ")
            ]

        self.assertEqual(
            [line.replace("@DIGEST@", digest) for line in FORWARD_SNAPSHOT],
            snapshot_lines("forward"),
        )
        self.assertEqual(
            [line.replace("@DIGEST@", digest) for line in DENIAL_PREROUTING_SNAPSHOT],
            snapshot_lines("denial_prerouting"),
        )


class NetworkPolicyProtocolTest(unittest.TestCase):
    def test_agent_accepts_only_versioned_declarative_policy_requests(self):
        request = AgentRequest.from_payload({"version": 1, "action": "dry_run", "policies": [policy_payload()]})
        self.assertEqual("dry_run", request.action)
        self.assertEqual(1, len(request.policies))

        with self.assertRaises(AgentProtocolError):
            AgentRequest.from_payload({"version": 1, "action": "shell", "command": "nft flush ruleset"})

        with self.assertRaises(AgentProtocolError):
            AgentRequest.from_payload({"version": 1, "action": "status", "policies": []})


class NetworkPolicyDenialResponderTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), DenialRequestHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def request(self, path: str, headers: dict[str, str]):
        connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        body = response.read().decode("utf-8")
        connection.close()
        return response, body

    def test_html_response_defaults_to_english_and_supports_chinese(self):
        response, body = self.request("/", {"Accept": "text/html", "Accept-Language": "zh-CN"})
        self.assertEqual(403, response.status)
        self.assertEqual("text/html; charset=utf-8", response.getheader("Content-Type"))
        self.assertIn("VPN 访问被拒绝", body)
        self.assertNotIn("10.8.0.2", body)

    def test_json_response_uses_accept_or_api_path(self):
        response, body = self.request("/api/status", {"Accept": "application/json", "Accept-Language": "en"})
        self.assertEqual(403, response.status)
        self.assertEqual("application/json; charset=utf-8", response.getheader("Content-Type"))
        self.assertEqual(
            {"error": "vpn_access_denied", "message": "This VPN endpoint is not authorized to access this resource. Contact an administrator."},
            __import__("json").loads(body),
        )

    def test_non_http_request_is_closed_without_a_response(self):
        connection = __import__("socket").create_connection(("127.0.0.1", self.server.server_port), timeout=2)
        try:
            connection.sendall(b"\x16\x03\x01\x00\x00")
            self.assertEqual(b"", connection.recv(1))
        finally:
            connection.close()


@unittest.skipIf(db is None, "SQLAlchemy is required for Dashboard persistence tests")
class NetworkPolicyOverviewTest(unittest.TestCase):
    def test_unmanaged_peer_stays_unmanaged_and_orphan_is_visible(self):
        managed = validate_policy(policy_payload())

        class Repository:
            def current_records(self):
                return [{
                    "policy_id": "known-policy",
                    "policy": managed,
                    "managed": True,
                    "version": 1,
                    "last_apply_status": "applied",
                    "binding_status": "bound",
                    "last_apply_at": None,
                    "updated_at": None,
                }]

        service = NetworkPolicyService.__new__(NetworkPolicyService)
        service.repository = Repository()
        service.agent_client = FakePolicyAgent()
        overview = service.overview([
            {
                "configuration_name": "wg0",
                "peer_public_key": PUBLIC_KEY,
                "peer_name": "managed-peer",
                "peer_status": "running",
                "allowed_ip": "10.8.0.2/32",
                "tunnel_address": "10.8.0.2",
                "eligible": True,
                "peer_present": True,
            },
            {
                "configuration_name": "wg0",
                "peer_public_key": "b" * 43 + "=",
                "peer_name": "unmanaged-peer",
                "peer_status": "running",
                "allowed_ip": "10.8.0.3/32",
                "tunnel_address": "10.8.0.3",
                "eligible": True,
                "peer_present": True,
            },
        ])

        self.assertEqual(["managed", "unmanaged"], [row["policy_status"] for row in overview["rows"]])
        self.assertEqual([], overview["rows"][1]["rules"])
        self.assertEqual("out_of_sync", overview["runtime"]["status"])


class FakeNftRunner:
    def __init__(self):
        self.calls = []
        self.loaded_hash = None
        self.loaded_rule_count = 1

    def __call__(self, command, input_text):
        self.calls.append((list(command), input_text))
        if "-f" in command and "--check" not in command and input_text:
            match = re.search(r"wgd-policy:([a-f0-9]{64})", input_text)
            self.loaded_hash = match.group(1) if match else None
        if command[1:4] == ["list", "table", "inet"]:
            tags = " ".join(
                f'comment "wgd-policy:{self.loaded_hash}"' for _ in range(self.loaded_rule_count)
            )
            stdout = f"table inet wgd_network_policy {{ {tags} }}" if self.loaded_hash else ""
            return CompletedProcess(command, 0 if self.loaded_hash else 1, stdout, "")
        return CompletedProcess(command, 0, "nftables v1.0", "")


class NftablesExecutorTest(unittest.TestCase):
    def test_dry_run_and_apply_use_fixed_nft_argument_lists(self):
        runner = FakeNftRunner()
        executor = NftablesExecutor(runner=runner)
        executor.nft_path = "nft"
        policy = validate_policy(policy_payload())

        preview = executor.dry_run([policy])
        applied = executor.apply([policy])

        self.assertFalse(preview["applied"])
        self.assertTrue(applied["applied"])
        self.assertEqual(preview["hash"], applied["hash"])
        self.assertTrue(all(command[0] == "nft" for command, _ in runner.calls))
        self.assertFalse(any("shell" in command for command, _ in runner.calls))

    def test_status_counts_the_digest_tagged_rules_in_the_table(self):
        runner = FakeNftRunner()
        executor = NftablesExecutor(runner=runner)
        executor.nft_path = "nft"
        _, digest = compile_ruleset([validate_policy(policy_payload())])
        runner.loaded_hash = digest
        runner.loaded_rule_count = 4

        status = executor.status()

        self.assertTrue(status["table_present"])
        self.assertEqual(digest, status["ruleset_hash"])
        self.assertEqual(4, status["rule_count"])

    def test_status_of_an_absent_table_reports_zero_rules(self):
        runner = FakeNftRunner()
        executor = NftablesExecutor(runner=runner)
        executor.nft_path = "nft"

        status = executor.status()

        self.assertFalse(status["table_present"])
        self.assertEqual(0, status["rule_count"])
        self.assertIsNone(status["ruleset_hash"])

    def test_status_returns_the_loaded_policy_hash(self):
        runner = FakeNftRunner()
        executor = NftablesExecutor(runner=runner)
        executor.nft_path = "nft"
        policy = validate_policy(policy_payload())
        executor.apply([policy])

        self.assertEqual(policy_hash([policy]), executor.status()["ruleset_hash"])


class FakePolicyAgent:
    def __init__(self):
        self.fail = False
        self.fail_status = False
        self.status_hash = None
        self.status_hash_override = None
        self.status_rule_count = None
        self.status_table_present = True
        self.requests = []

    def request(self, action, policies=None):
        self.requests.append((action, policies))
        if self.fail and action == "apply":
            raise NetworkPolicyServiceError("simulated nftables failure")
        if self.fail_status and action == "status":
            raise NetworkPolicyServiceError("simulated status failure")
        if action == "dry_run":
            return {"ruleset": "checked", "hash": "a" * 64, "applied": False}
        if action == "capabilities":
            return {"capabilities": {"supported": True}}
        if action == "status":
            loaded = self.status_hash_override or self.status_hash
            status = {"ruleset_hash": loaded, "table_present": self.status_table_present}
            if self.status_rule_count is not None:
                status["rule_count"] = self.status_rule_count
            return status
        self.status_hash = policy_hash(policies) if policies else None
        return {"hash": self.status_hash, "applied": True}


@unittest.skipIf(db is None, "SQLAlchemy is required for Dashboard persistence tests")
class NetworkPolicyServiceTest(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.engine = db.create_engine(f"sqlite:///{pathlib.Path(self.temporary_directory.name) / 'policy.db'}")
        self.agent = FakePolicyAgent()
        self.service = NetworkPolicyService(self.engine, self.agent)

    def tearDown(self):
        self.engine.dispose()
        self.temporary_directory.cleanup()

    def test_failed_candidate_preserves_previously_applied_policy(self):
        original = policy_payload()
        self.service.apply(original, "test-actor")
        changed = policy_payload(rules=[{"destination": "192.168.10.117", "protocol": "tcp", "ports": {"from": 443, "to": 443}}])
        self.agent.fail = True

        with self.assertRaises(NetworkPolicyServiceError):
            self.service.apply(changed, "test-actor")

        details = self.service.details("wg0", PUBLIC_KEY, "10.8.0.2")
        self.assertEqual(validate_policy(original).to_payload()["rules"], details["policy"]["rules"])
        self.assertEqual("failed", details["revisions"][0]["status"])

    def test_deactivation_removes_only_the_target_from_agent_desired_state(self):
        original = policy_payload()
        self.service.apply(original, "test-actor")
        self.service.deactivate(original, "test-actor")

        action, policies = self.agent.requests[-1]
        self.assertEqual("apply", action)
        self.assertEqual([], policies)

    def test_saving_an_unmanaged_policy_clears_the_peer_from_the_desired_state(self):
        # deactivate() is only a wrapper around apply(managed=false); the modal
        # save path talks to apply() directly, so both must converge on the same
        # agent payload: the target Peer leaves the desired set and every other
        # managed Peer is re-sent untouched.
        original = policy_payload()
        other = policy_payload(
            configuration_name="wg1",
            interface_name="wg1",
            peer_public_key="b" * 43 + "=",
            tunnel_address="10.9.0.2",
        )
        self.service.apply(original, "test-actor")
        self.service.apply(other, "test-actor")

        result = self.service.apply(policy_payload(managed=False, rules=[]), "test-actor")

        action, desired = self.agent.requests[-1]
        self.assertEqual("apply", action)
        self.assertEqual([other["peer_public_key"]], [policy.peer_public_key for policy in desired])
        self.assertIs(False, result["policy"]["managed"])
        self.assertEqual([], result["policy"]["rules"])

    def test_unmanaged_save_is_recorded_as_deactivate_not_apply(self):
        # The switch-off save posts managed=false to /apply and the history panel
        # renders GetLocale(revision.action) - "应用" vs "停用". Labelling the
        # off-transition "apply" tells the operator the opposite of what happened,
        # so both ways of reaching managed=false must share one label, while an
        # explicit action must never be relabelled by that normalisation.
        original = policy_payload(rules=[{
            "destination": "192.168.10.117", "protocol": "tcp", "ports": {"from": 443, "to": 443}
        }])
        actions = lambda: {
            row["version"]: row["action"]
            for row in self.service.details("wg0", PUBLIC_KEY, "10.8.0.2")["revisions"]
        }

        self.service.apply(original, "test-actor")
        self.service.apply(policy_payload(managed=False, rules=[]), "test-actor")
        self.assertEqual({1: "apply", 2: "deactivate"}, actions())

        self.service.apply(original, "test-actor")
        self.service.deactivate(original, "test-actor")
        self.assertEqual({1: "apply", 2: "deactivate", 3: "apply", 4: "deactivate"}, actions())

        self.service.rollback(
            next(row["revision_id"]
                 for row in self.service.details("wg0", PUBLIC_KEY, "10.8.0.2")["revisions"]
                 if row["version"] == 4),
            "test-actor",
        )
        self.assertEqual("rollback", actions()[5])
        self.assertIs(False, self.service.details("wg0", PUBLIC_KEY, "10.8.0.2")["policy"]["managed"])

    def test_details_include_the_policy_snapshot_for_each_revision(self):
        original = policy_payload(rules=[{
            "destination": "192.168.10.117", "protocol": "tcp", "ports": {"from": 443, "to": 443}
        }])
        self.service.apply(original, "test-actor")

        details = self.service.details("wg0", PUBLIC_KEY, "10.8.0.2")

        self.assertEqual(validate_policy(original).to_payload(), details["revisions"][0]["policy"])

    def test_runtime_sync_applies_only_complete_managed_bound_policy_set(self):
        first = policy_payload()
        second = policy_payload(
            configuration_name="wg1",
            interface_name="wg1",
            peer_public_key="b" * 43 + "=",
            tunnel_address="10.9.0.2",
        )
        self.service.apply(first, "test-actor")
        self.service.apply(second, "test-actor")
        with self.engine.begin() as connection:
            connection.execute(
                self.service.repository.policies.update()
                .where(self.service.repository.policies.c.PeerPublicKey == second["peer_public_key"])
                .values(BindingStatus="orphaned")
            )

        self.agent.requests.clear()
        result = self.service.synchronize_runtime()

        self.assertEqual("in_sync", result["status"])
        self.assertEqual(result["expected_hash"], result["loaded_hash"])
        self.assertEqual(["apply", "status"], [action for action, _ in self.agent.requests])
        self.assertEqual([PUBLIC_KEY], [policy.peer_public_key for policy in self.agent.requests[0][1]])

    def test_runtime_sync_supports_empty_target_set_and_does_not_create_revisions(self):
        before_records = self.service.repository.current_records()
        before_revision_count = self._count(self.service.repository.revisions)
        before_apply_count = self._count(self.service.repository.applies)

        result = self.service.synchronize_runtime()

        self.assertEqual("in_sync", result["status"])
        self.assertEqual([], self.agent.requests[0][1])
        self.assertEqual(before_records, self.service.repository.current_records())
        self.assertEqual(before_revision_count, self._count(self.service.repository.revisions))
        self.assertEqual(before_apply_count, self._count(self.service.repository.applies))

    def test_runtime_check_flags_a_missing_table_without_reapplying(self):
        self.service.apply(policy_payload(), "test-actor")
        self.agent.status_hash = None
        self.agent.status_rule_count = 0
        self.agent.status_table_present = False
        self.agent.requests.clear()

        report = self.service.runtime_check()

        self.assertEqual("out_of_sync", report["status"])
        self.assertFalse(report["table_present"])
        self.assertEqual(1, report["managed_policies"])
        self.assertEqual(["status"], [action for action, _ in self.agent.requests])

    def test_runtime_check_accepts_matching_digest_and_rule_count(self):
        policy = validate_policy(policy_payload())
        self.service.apply(policy.to_payload(), "test-actor")
        expected_hash, expected_count = desired_fingerprint([policy])
        self.assertGreater(expected_count, 0)
        self.agent.status_hash = expected_hash
        self.agent.status_rule_count = expected_count
        self.agent.requests.clear()

        report = self.service.runtime_check()

        self.assertEqual("in_sync", report["status"])
        self.assertEqual(expected_count, report["loaded_rule_count"])
        self.assertEqual(["status"], [action for action, _ in self.agent.requests])

    def test_runtime_check_detects_a_partially_deleted_table(self):
        policy = validate_policy(policy_payload())
        self.service.apply(policy.to_payload(), "test-actor")
        expected_hash, expected_count = desired_fingerprint([policy])
        self.agent.status_hash = expected_hash
        self.agent.status_rule_count = expected_count - 1

        self.assertEqual("out_of_sync", self.service.runtime_check()["status"])
        self.assertFalse(runtime_is_in_sync(
            {"table_present": True, "ruleset_hash": expected_hash, "rule_count": expected_count - 1},
            expected_hash,
            expected_count,
        ))

    def test_non_forced_sync_short_circuits_when_the_runtime_already_matches(self):
        policy = validate_policy(policy_payload())
        self.service.apply(policy.to_payload(), "test-actor")
        expected_hash, expected_count = desired_fingerprint([policy])
        self.agent.status_hash = expected_hash
        self.agent.status_rule_count = expected_count
        self.agent.requests.clear()

        result = self.service.synchronize_runtime(force=False)

        self.assertEqual("in_sync", result["status"])
        self.assertFalse(result["applied"])
        self.assertEqual(["status"], [action for action, _ in self.agent.requests])

    def test_non_forced_sync_still_applies_when_the_agent_cannot_prove_rule_count(self):
        self.service.apply(policy_payload(), "test-actor")
        self.agent.requests.clear()

        result = self.service.synchronize_runtime(force=False)

        self.assertEqual(["status", "apply", "status"], [action for action, _ in self.agent.requests])
        self.assertTrue(result["applied"])

    def test_runtime_sync_maps_apply_and_status_failures_without_database_mutation(self):
        self.service.apply(policy_payload(), "test-actor")
        before_records = self.service.repository.current_records()
        before_revision_count = self._count(self.service.repository.revisions)
        before_apply_count = self._count(self.service.repository.applies)

        self.agent.fail = True
        with self.assertRaises(NetworkPolicyServiceError):
            self.service.synchronize_runtime()
        self.assertEqual(before_records, self.service.repository.current_records())
        self.assertEqual(before_revision_count, self._count(self.service.repository.revisions))
        self.assertEqual(before_apply_count, self._count(self.service.repository.applies))

        self.agent.fail = False
        self.agent.fail_status = True
        with self.assertRaises(NetworkPolicyServiceError):
            self.service.synchronize_runtime()
        self.assertEqual(before_records, self.service.repository.current_records())
        self.assertEqual(before_revision_count, self._count(self.service.repository.revisions))
        self.assertEqual(before_apply_count, self._count(self.service.repository.applies))

    def test_runtime_sync_rejects_unverified_loaded_hash(self):
        self.service.apply(policy_payload(), "test-actor")
        self.agent.status_hash_override = "0" * 64

        with self.assertRaises(NetworkPolicyServiceError):
            self.service.synchronize_runtime()

    def _count(self, table):
        with self.engine.connect() as connection:
            return connection.scalar(db.select(db.func.count()).select_from(table))


class FakeReconcileService:
    def __init__(self, check_status="in_sync", sync_status="in_sync"):
        self.check_status = check_status
        self.sync_status = sync_status
        self.calls = []

    def runtime_check(self):
        self.calls.append("runtime_check")
        return {"status": self.check_status}

    def synchronize_runtime(self, force=True):
        self.calls.append(("synchronize_runtime", force))
        return {"status": self.sync_status, "applied": force}


class NetworkPolicyReconcileTest(unittest.TestCase):
    def test_check_only_never_mutates_and_exits_two_on_drift(self):
        service = FakeReconcileService(check_status="out_of_sync")

        report, exit_code = reconcile(service, check_only=True)

        self.assertEqual(["runtime_check"], service.calls)
        self.assertEqual("out_of_sync", report["status"])
        self.assertEqual(EXIT_DRIFT, exit_code)

    def test_reconcile_uses_the_idempotent_path_and_exits_zero(self):
        service = FakeReconcileService()

        report, exit_code = reconcile(service, check_only=False)

        self.assertEqual([("synchronize_runtime", False)], service.calls)
        self.assertEqual("in_sync", report["status"])
        self.assertEqual(EXIT_IN_SYNC, exit_code)


if __name__ == "__main__":
    unittest.main()
