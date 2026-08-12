from __future__ import annotations

import pathlib
import re
import sys
import tempfile
import unittest
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
from network_policy.compiler import TABLE_NAME, compile_check_ruleset, compile_ruleset, policy_hash
from network_policy.validation import PolicyValidationError, validate_policy


PUBLIC_KEY = "a" * 43 + "="


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


class NetworkPolicyCompilerTest(unittest.TestCase):
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
        self.assertLess(ruleset.index('tcp dport 8118 accept'), ruleset.index('counter drop'))
        self.assertIn(f'wgd-policy:{digest}', ruleset)
        self.assertNotIn("input", ruleset)
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
        self.assertLess(ruleset.index('ip daddr 192.168.10.117/32 meta l4proto icmp accept'), ruleset.index('counter drop'))

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
