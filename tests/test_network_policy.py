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
    from network_policy.service import NetworkPolicyService, NetworkPolicyServiceError
except ModuleNotFoundError:
    db = None
    NetworkPolicyService = None
    NetworkPolicyServiceError = RuntimeError


from network_policy.agent_protocol import AgentProtocolError, AgentRequest
from network_policy.agent import NftablesExecutor
from network_policy.compiler import DENIAL_RESPONSE_PORT, TABLE_NAME, compile_check_ruleset, compile_ruleset, policy_hash
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
            self.assertIn(f"ip daddr 192.168.0.175/32 tcp dport {port} accept", ruleset)

    def test_compiles_allow_before_per_peer_default_drop(self):
        policy = validate_policy(policy_payload())
        ruleset, digest = compile_ruleset([policy])

        self.assertIn(f"flush table inet {TABLE_NAME}", ruleset)
        self.assertIn(
            'iifname "wg0" ip saddr 10.8.0.2 ip daddr 192.168.0.170/32 meta l4proto tcp accept',
            ruleset,
        )
        self.assertIn('tcp dport 8118 accept', ruleset)
        self.assertIn('ip daddr 192.168.0.170/32 meta l4proto icmp accept', ruleset)
        self.assertIn('ip daddr 192.168.10.117/32 meta l4proto icmp accept', ruleset)
        self.assertNotIn('ip saddr 10.8.0.2 meta l4proto icmp accept', ruleset)
        self.assertIn('meta l4proto tcp redirect to :61573', ruleset)
        self.assertIn(f'ct status dnat tcp dport {DENIAL_RESPONSE_PORT} accept', ruleset)
        self.assertIn('meta l4proto tcp reject with tcp reset', ruleset)
        self.assertIn('meta l4proto udp reject with icmp port-unreachable', ruleset)
        self.assertIn(f'tcp dport {DENIAL_RESPONSE_PORT} reject with tcp reset', ruleset)
        self.assertLess(ruleset.index('tcp dport 8118 accept'), ruleset.index('meta l4proto tcp reject'))
        self.assertIn(f'wgd-policy:{digest}', ruleset)
        self.assertNotIn("dport 22", ruleset)

    def test_icmp_is_allowed_only_for_configured_destinations(self):
        policy = validate_policy(policy_payload(rules=[
            {"destination": "192.168.0.170", "protocol": "tcp", "ports": None},
            {"destination": "192.168.0.170", "protocol": "udp", "ports": None},
            {"destination": "192.168.10.117", "protocol": "icmp", "ports": None},
        ]))
        ruleset, _ = compile_ruleset([policy])

        self.assertEqual(2, ruleset.count('meta l4proto icmp accept'))
        self.assertIn('ip daddr 192.168.0.170/32 meta l4proto icmp accept', ruleset)
        self.assertIn('ip daddr 192.168.10.117/32 meta l4proto icmp accept', ruleset)
        self.assertLess(ruleset.index('ip daddr 192.168.10.117/32 meta l4proto icmp accept'), ruleset.index('meta l4proto tcp reject'))

    def test_allowed_http_destination_bypasses_denial_redirect(self):
        policy = validate_policy(policy_payload(rules=[
            {"destination": "192.168.0.170", "protocol": "tcp", "ports": {"from": 80, "to": 80}},
            {"destination": "192.168.10.117", "protocol": "tcp", "ports": {"from": 443, "to": 443}},
        ]))
        ruleset, _ = compile_ruleset([policy])

        bypass = 'ip daddr 192.168.0.170/32 tcp dport 80 accept'
        redirect = f'meta l4proto tcp redirect to :{DENIAL_RESPONSE_PORT}'
        self.assertIn(bypass, ruleset)
        self.assertIn(redirect, ruleset)
        self.assertLess(ruleset.index(bypass), ruleset.index(redirect))

    def test_allowed_nonstandard_tcp_destination_bypasses_denial_redirect(self):
        policy = validate_policy(policy_payload(rules=[
            {"destination": "192.168.0.170", "protocol": "tcp", "ports": {"from": 8096, "to": 8096}},
        ]))
        ruleset, _ = compile_ruleset([policy])

        bypass = 'ip daddr 192.168.0.170/32 tcp dport 8096 accept'
        redirect = f'meta l4proto tcp redirect to :{DENIAL_RESPONSE_PORT}'
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
        self.assertIn('meta l4proto ipv6-icmp accept', ruleset)

    def test_hash_is_stable_for_rule_order(self):
        original = validate_policy(policy_payload())
        reversed_rules = validate_policy(policy_payload(rules=list(reversed(policy_payload()["rules"]))))
        self.assertEqual(policy_hash([original]), policy_hash([reversed_rules]))

    def test_check_ruleset_uses_only_a_temporary_table(self):
        policy = validate_policy(policy_payload())
        ruleset, _ = compile_check_ruleset([policy])
        self.assertIn("add table inet wgd_network_policy_check", ruleset)
        self.assertNotIn("flush table inet wgd_network_policy\n", ruleset)


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

    def __call__(self, command, input_text):
        self.calls.append((list(command), input_text))
        if "-f" in command and "--check" not in command and input_text:
            match = re.search(r"wgd-policy:([a-f0-9]{64})", input_text)
            self.loaded_hash = match.group(1) if match else None
        if command[1:4] == ["list", "table", "inet"]:
            stdout = f'table inet wgd_network_policy {{ comment "wgd-policy:{self.loaded_hash}" }}' if self.loaded_hash else ""
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
        self.requests = []

    def request(self, action, policies=None):
        self.requests.append((action, policies))
        if self.fail and action == "apply":
            raise NetworkPolicyServiceError("simulated nftables failure")
        if action == "dry_run":
            return {"ruleset": "checked", "hash": "a" * 64, "applied": False}
        if action == "capabilities":
            return {"capabilities": {"supported": True}}
        return {"hash": "b" * 64, "applied": True}


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

    def test_details_include_the_policy_snapshot_for_each_revision(self):
        original = policy_payload(rules=[{
            "destination": "192.168.10.117", "protocol": "tcp", "ports": {"from": 443, "to": 443}
        }])
        self.service.apply(original, "test-actor")

        details = self.service.details("wg0", PUBLIC_KEY, "10.8.0.2")

        self.assertEqual(validate_policy(original).to_payload(), details["revisions"][0]["policy"])


if __name__ == "__main__":
    unittest.main()
