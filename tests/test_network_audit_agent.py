import pathlib
import re
import sys
import tempfile
import unittest
from subprocess import CompletedProcess


PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from network_audit.agent_protocol import (
    AUDIT_CONFIG_VERSION,
    AuditAgentConfig,
    AuditAgentRequest,
    AuditMode,
    AuditPeerSnapshot,
)
from network_audit.validation import AuditValidationError
from network_policy.compiler import NFLOG_POLICY_DECISION_GROUP
from network_policy.validation import NetworkPolicy


PUBLIC_KEY = "A" * 43 + "="


def peer(**overrides):
    payload = {
        "configuration_name": "office",
        "public_key": PUBLIC_KEY,
        "peer_name": "alice",
        "tunnel_address": "10.10.0.2",
    }
    payload.update(overrides)
    return AuditPeerSnapshot(**payload)


def config(**overrides):
    payload = {
        "version": AUDIT_CONFIG_VERSION,
        "generation": 4,
        "interface_name": "wg0",
        "mode": "all",
        "peers": (peer(),),
        "managed_tunnel_addresses": ("10.10.0.2",),
        "observation_nflog_group": 100,
        "policy_allowed_nflog_group": NFLOG_POLICY_DECISION_GROUP,
        "policy_denied_nflog_group": NFLOG_POLICY_DECISION_GROUP,
    }
    payload.update(overrides)
    return AuditAgentConfig(**payload)


class AuditAgentProtocolTest(unittest.TestCase):
    def test_request_round_trip_validates_only_audit_configuration(self):
        request = AuditAgentRequest("apply", config())

        restored = AuditAgentRequest.from_payload(request.to_payload())

        self.assertEqual(request, restored)
        with self.assertRaises(ValueError):
            AuditAgentRequest.from_payload({**request.to_payload(), "raw_ruleset": "flush table inet other"})

    def test_round_trip_config_keeps_only_supported_snapshot_fields(self):
        audit_config = config()

        restored = AuditAgentConfig.from_payload(audit_config.to_payload())

        self.assertEqual(audit_config, restored)
        self.assertEqual(AuditMode.ALL, restored.mode)
        self.assertTrue(restored.should_collect("10.10.0.2"))
        self.assertFalse(restored.should_collect("10.10.0.3"))
        self.assertNotIn("private_key", restored.to_payload()["peers"][0])

    def test_config_rejects_unknown_fields_and_unsafe_peer_relationships(self):
        payload = config().to_payload()
        payload["raw_ruleset"] = "table inet other {}"
        with self.assertRaises(AuditValidationError):
            AuditAgentConfig.from_payload(payload)

        with self.assertRaises(AuditValidationError):
            config(managed_tunnel_addresses=("10.10.0.9",))

        with self.assertRaises(AuditValidationError):
            config(observation_nflog_group=NFLOG_POLICY_DECISION_GROUP)

    def test_config_allows_shared_policy_verdict_group(self):
        audit_config = config()

        self.assertEqual(audit_config.policy_allowed_nflog_group, audit_config.policy_denied_nflog_group)

    def test_managed_mode_excludes_unmanaged_known_peers(self):
        bob = peer(public_key="B" * 43 + "=", peer_name="bob", tunnel_address="10.10.0.3")
        audit_config = config(mode="managed", peers=(peer(), bob))

        self.assertTrue(audit_config.should_collect("10.10.0.2"))
        self.assertFalse(audit_config.should_collect("10.10.0.3"))


class AuditConfigSynchronizerTest(unittest.TestCase):
    def test_sync_uses_only_live_eligible_wg_peers_and_applied_managed_policies(self):
        from network_audit.sync import AuditConfigSynchronizer

        class FakeAgentClient:
            def __init__(self):
                self.requests = []

            def request(self, action, config=None):
                self.requests.append((action, config))
                return {"applied": True}

        client = FakeAgentClient()
        synchronizer = AuditConfigSynchronizer(client, interface_name="wg0", mode="managed")
        applied_policy = NetworkPolicy.from_payload({
            "configuration_name": "wg0", "interface_name": "wg0", "peer_public_key": PUBLIC_KEY,
            "tunnel_address": "10.10.0.2", "managed": True, "rules": [],
        })
        result = synchronizer.sync(
            [
                {"configuration_name": "wg0", "peer_public_key": PUBLIC_KEY, "peer_name": "alice", "tunnel_address": "10.10.0.2", "eligible": True},
                {"configuration_name": "wg0", "peer_public_key": "B" * 43 + "=", "peer_name": "bad", "tunnel_address": "10.10.0.3", "eligible": False},
                {"configuration_name": "other", "peer_public_key": "C" * 43 + "=", "peer_name": "other", "tunnel_address": "10.10.0.4", "eligible": True},
            ],
            [{"policy": applied_policy, "managed": True, "binding_status": "bound", "last_apply_status": "applied"}],
        )

        self.assertTrue(result["applied"])
        self.assertEqual("apply", client.requests[0][0])
        audit_config = client.requests[0][1]
        self.assertEqual(["10.10.0.2"], [peer.tunnel_address for peer in audit_config.peers])
        self.assertEqual(("10.10.0.2",), audit_config.managed_tunnel_addresses)
        self.assertEqual(NFLOG_POLICY_DECISION_GROUP, audit_config.policy_allowed_nflog_group)
        self.assertEqual(NFLOG_POLICY_DECISION_GROUP, audit_config.policy_denied_nflog_group)

    def test_sync_refuses_to_drop_a_malformed_live_eligible_peer(self):
        from network_audit.sync import AuditConfigSynchronizer, NetworkAuditSyncError

        synchronizer = AuditConfigSynchronizer(interface_name="wg0")

        with self.assertRaises(NetworkAuditSyncError):
            synchronizer.build_config(
                [{"configuration_name": "wg0", "peer_public_key": "invalid", "peer_name": "alice", "tunnel_address": "10.10.0.2", "eligible": True}],
                [],
            )

    def test_sync_publishes_the_latest_apply_or_failure_status(self):
        from network_audit.health import ConfigSyncStatus, read_config_sync_snapshot
        from network_audit.sync import AuditConfigSynchronizer, NetworkAuditSyncError

        class FailingAgentClient:
            def request(self, action, config=None):
                raise NetworkAuditSyncError("network audit agent is unavailable")

        with tempfile.TemporaryDirectory() as temporary_directory:
            status_path = pathlib.Path(temporary_directory) / "sync.json"
            synchronizer = AuditConfigSynchronizer(FailingAgentClient(), sync_status_path=status_path)

            with self.assertRaises(NetworkAuditSyncError):
                synchronizer.sync([], [])

            snapshot = read_config_sync_snapshot(status_path)
            self.assertEqual(ConfigSyncStatus.FAILED, snapshot["status"])
            self.assertEqual("network audit agent is unavailable", snapshot["error"])

    def test_sync_status_bounds_agent_failure_errors(self):
        from network_audit.health import read_config_sync_snapshot
        from network_audit.sync import AuditConfigSynchronizer, NetworkAuditSyncError

        failure = "nft error: " + ("x" * 400)

        class FailingAgentClient:
            def request(self, action, config=None):
                raise NetworkAuditSyncError(failure)

        with tempfile.TemporaryDirectory() as temporary_directory:
            status_path = pathlib.Path(temporary_directory) / "sync.json"
            synchronizer = AuditConfigSynchronizer(FailingAgentClient(), sync_status_path=status_path)

            with self.assertRaises(NetworkAuditSyncError):
                synchronizer.sync([], [])

            snapshot = read_config_sync_snapshot(status_path)
            self.assertEqual(255, len(snapshot["error"]))
            self.assertEqual(failure[:255], snapshot["error"])


class AuditAgentSocketAuthorizationTest(unittest.TestCase):
    def test_root_or_configured_group_members_are_authorized(self):
        from network_audit.agent import AuditAgentServer

        self.assertTrue(AuditAgentServer._credentials_are_authorized(0, set(), 11501))
        self.assertTrue(AuditAgentServer._credentials_are_authorized(1000, {1000, 11501}, 11501))
        self.assertFalse(AuditAgentServer._credentials_are_authorized(1000, {1000}, 11501))


class FakeNftRunner:
    def __init__(self):
        self.calls = []
        self.loaded_hash = None

    def __call__(self, command, input_text):
        self.calls.append((list(command), input_text))
        if "-f" in command and "--check" not in command and input_text:
            match = re.search(r'wgd-audit:([a-f0-9]{64})', input_text)
            self.loaded_hash = match.group(1) if match else None
        if command[1:5] == ["list", "table", "inet", "wgd_network_audit"]:
            stdout = (
                'table inet wgd_network_audit { comment "wgd-audit-owner:v1" '
                f'comment "wgd-audit:{self.loaded_hash}" }}'
                if self.loaded_hash else ""
            )
            return CompletedProcess(command, 0 if self.loaded_hash else 1, stdout, "")
        return CompletedProcess(command, 0, "nftables v1.0", "")


class AuditNftablesAgentTest(unittest.TestCase):
    def test_renderer_owns_only_audit_table_and_observes_new_wg_flows(self):
        from network_audit.agent import compile_audit_check_ruleset

        unmanaged = peer(public_key="B" * 43 + "=", peer_name="bob", tunnel_address="10.10.0.3")
        ruleset, digest = compile_audit_check_ruleset(config(peers=(peer(), unmanaged)))

        self.assertIn("add table inet wgd_network_audit_check", ruleset)
        self.assertIn('iifname "wg0" ip saddr 10.10.0.3 ct state new', ruleset)
        self.assertNotIn('ip saddr 10.10.0.2 ct state new', ruleset)
        self.assertIn('log prefix "wgd-audit:forward_observed" group 100', ruleset)
        self.assertIn(f'wgd-audit:{digest}', ruleset)
        self.assertNotIn("wgd_network_policy", ruleset)

    def test_renderer_observes_only_managed_peers_in_managed_mode(self):
        from network_audit.agent import compile_audit_check_ruleset

        unmanaged = peer(public_key="B" * 43 + "=", peer_name="bob", tunnel_address="10.10.0.3")
        ruleset, _ = compile_audit_check_ruleset(config(mode="managed", peers=(peer(), unmanaged)))

        self.assertIn('iifname "wg0" ip saddr 10.10.0.2 ct state new', ruleset)
        self.assertNotIn('ip saddr 10.10.0.3 ct state new', ruleset)

    def test_executor_checks_then_applies_fixed_commands_to_its_own_table(self):
        from network_audit.agent import AuditNftablesExecutor

        runner = FakeNftRunner()
        executor = AuditNftablesExecutor(runner=runner)
        executor.nft_path = "nft"

        result = executor.apply(config())

        self.assertTrue(result["applied"])
        self.assertTrue(all(command[0] == "nft" for command, _ in runner.calls))
        self.assertFalse(any("wgd_network_policy" in " ".join(command) for command, _ in runner.calls))

    def test_executor_removes_only_an_owned_audit_table(self):
        from network_audit.agent import AuditNftablesExecutor

        runner = FakeNftRunner()
        executor = AuditNftablesExecutor(runner=runner)
        executor.nft_path = "nft"
        executor.apply(config())

        result = executor.remove()

        self.assertTrue(result["removed"])
        self.assertIn(["nft", "delete", "table", "inet", "wgd_network_audit"], [call[0] for call in runner.calls])

    def test_remove_clears_the_last_applied_config_after_removing_the_owned_table(self):
        from network_audit.agent import AuditAgent, AuditNftablesExecutor

        with tempfile.TemporaryDirectory() as temporary_directory:
            config_path = pathlib.Path(temporary_directory) / "config.json"
            executor = AuditNftablesExecutor(runner=FakeNftRunner())
            executor.nft_path = "nft"
            agent = AuditAgent(executor=executor, config_path=config_path)
            agent.handle(AuditAgentRequest("apply", config()))

            result = agent.handle(AuditAgentRequest("remove"))

            self.assertTrue(result["removed"])
            self.assertFalse(config_path.exists())

    def test_agent_publishes_config_only_after_the_owned_table_applies(self):
        from network_audit.agent import AuditAgent, AuditNftablesExecutor, read_applied_config

        with tempfile.TemporaryDirectory() as temporary_directory:
            config_path = pathlib.Path(temporary_directory) / "config.json"
            executor = AuditNftablesExecutor(runner=FakeNftRunner())
            executor.nft_path = "nft"
            result = AuditAgent(executor=executor, config_path=config_path).handle(AuditAgentRequest("apply", config()))

            self.assertTrue(result["applied"])
            self.assertEqual(config(), read_applied_config(config_path))

    def test_agent_keeps_the_previous_config_when_the_ruleset_apply_fails(self):
        from network_audit.agent import AuditAgent, AuditNftablesError, AuditNftablesExecutor, read_applied_config, write_applied_config

        class FailingRunner(FakeNftRunner):
            def __call__(self, command, input_text):
                result = super().__call__(command, input_text)
                if "-f" in command and "--check" not in command:
                    return CompletedProcess(command, 1, "", "apply rejected")
                return result

        with tempfile.TemporaryDirectory() as temporary_directory:
            config_path = pathlib.Path(temporary_directory) / "config.json"
            previous = config(generation=3)
            write_applied_config(config_path, previous)
            executor = AuditNftablesExecutor(runner=FailingRunner())
            executor.nft_path = "nft"

            with self.assertRaises(AuditNftablesError):
                AuditAgent(executor=executor, config_path=config_path).handle(AuditAgentRequest("apply", config()))

            self.assertEqual(previous, read_applied_config(config_path))


if __name__ == "__main__":
    unittest.main()
