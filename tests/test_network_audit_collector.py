import json
import pathlib
import socket
import struct
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock


PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from network_audit.agent_protocol import AUDIT_CONFIG_VERSION, AuditAgentConfig, AuditPeerSnapshot
from network_audit.collector import (
    AuditCollector,
    AuditCollectorRuntime,
    AdapterCapability,
    CollectorCapabilityError,
    NflogSocketAdapter,
    Pyroute2ConntrackAdapter,
    _AuditServiceWriter,
    _netlink_multicast_mask,
    decode_conntrack_message,
    decode_nflog_datagram,
)
from network_audit.correlation import FlowCorrelator
from network_audit.health import (
    ConfigSyncStatus,
    HealthSnapshot,
    HealthStatus,
    read_health_snapshot,
    write_config_sync_snapshot,
    write_health_snapshot,
)
from network_audit.models import ConntrackEvent, ConntrackEventType, FlowKey, NflogEvent
from network_audit.spool import AuditSpool
from network_audit.validation import AuditDecision, AuditObservation, AuditValidationError


PUBLIC_KEY = "A" * 43 + "="
BASE_TIME = datetime(2026, 8, 19, 12, 0, tzinfo=timezone.utc)


def audit_config(**overrides):
    peer = AuditPeerSnapshot(
        configuration_name="office",
        public_key=PUBLIC_KEY,
        peer_name="alice",
        tunnel_address="10.10.0.2",
    )
    payload = {
        "version": AUDIT_CONFIG_VERSION,
        "generation": 9,
        "interface_name": "wg0",
        "mode": "all",
        "peers": (peer,),
        "managed_tunnel_addresses": (peer.tunnel_address,),
        "observation_nflog_group": 100,
        "policy_allowed_nflog_group": 101,
        "policy_denied_nflog_group": 102,
    }
    payload.update(overrides)
    return AuditAgentConfig(**payload)


def flow(**overrides):
    payload = {
        "source_address": "10.10.0.2",
        "destination_address": "198.51.100.20",
        "protocol": "tcp",
        "source_port": 43123,
        "destination_port": 443,
        "zone": 0,
    }
    payload.update(overrides)
    return FlowKey(**payload)


def observation(**overrides):
    payload = {
        "configuration_name": "office",
        "peer_public_key": PUBLIC_KEY,
        "peer_name_snapshot": "alice",
        "tunnel_address": "10.10.0.2",
        "destination_address": "198.51.100.20",
        "protocol": "tcp",
        "destination_port": 443,
        "decision": "policy_allowed",
        "observed_at": BASE_TIME,
        "connection_increment": 1,
        "bytes_from_peer": 12,
        "bytes_to_peer": 6,
    }
    payload.update(overrides)
    return AuditObservation(**payload)


class EventModelTest(unittest.TestCase):
    def test_flow_key_correlation_is_bidirectional_without_payload(self):
        original = flow()

        self.assertEqual(original.correlation_key, original.reverse().correlation_key)
        self.assertEqual(4, original.family)
        self.assertNotIn("payload", original.__dataclass_fields__)
        self.assertNotIn("raw_message", ConntrackEvent.__dataclass_fields__)
        self.assertNotIn("packet", NflogEvent.__dataclass_fields__)

    def test_event_models_validate_icmp_and_counter_metadata(self):
        icmp_flow = flow(protocol="icmp", source_port=None, destination_port=None)
        event = ConntrackEvent("new", icmp_flow, BASE_TIME, bytes_original=2, bytes_reply=3)

        self.assertEqual(ConntrackEventType.NEW, event.event_type)
        with self.assertRaises(AuditValidationError):
            flow(protocol="icmp", source_port=8, destination_port=None)
        with self.assertRaises(AuditValidationError):
            ConntrackEvent("new", flow(), BASE_TIME, bytes_original=-1)


class FlowCorrelationTest(unittest.TestCase):
    def test_denial_wins_over_allow_and_emits_one_observation(self):
        correlator = FlowCorrelator(timedelta(seconds=5))
        connection = flow()
        correlator.consume_conntrack(ConntrackEvent("new", connection, BASE_TIME), audit_config())
        correlator.consume_nflog(NflogEvent(connection.reverse(), "policy_allowed", BASE_TIME + timedelta(seconds=1)))
        correlator.consume_nflog(NflogEvent(connection, "policy_denied", BASE_TIME + timedelta(seconds=2)))
        correlator.consume_conntrack(
            ConntrackEvent("destroy", connection, BASE_TIME + timedelta(seconds=3), 42, 18),
            audit_config(),
        )

        observations = correlator.expire(BASE_TIME + timedelta(seconds=5))

        self.assertEqual(1, len(observations))
        self.assertEqual(AuditDecision.POLICY_DENIED, observations[0].decision)
        self.assertEqual((42, 18), (observations[0].bytes_from_peer, observations[0].bytes_to_peer))
        self.assertEqual(0, correlator.stats.incomplete_flows)

    def test_out_of_order_verdict_and_missing_destroy_use_one_fallback_window(self):
        correlator = FlowCorrelator(timedelta(seconds=3))
        connection = flow()
        correlator.consume_nflog(NflogEvent(connection, "policy_allowed", BASE_TIME))
        correlator.consume_conntrack(ConntrackEvent("new", connection, BASE_TIME + timedelta(seconds=1)), audit_config())

        observations = correlator.expire(BASE_TIME + timedelta(seconds=4))

        self.assertEqual([AuditDecision.POLICY_ALLOWED], [item.decision for item in observations])
        self.assertEqual(1, correlator.stats.correlation_timeouts)
        self.assertEqual(1, correlator.stats.incomplete_flows)

    def test_ipv6_udp_and_icmp_fallbacks_are_supported(self):
        for protocol, source_port, destination_port in (("udp", 50000, 53), ("icmp", None, None)):
            with self.subTest(protocol=protocol):
                correlator = FlowCorrelator(timedelta(seconds=1))
                connection = flow(
                    source_address="2001:db8:1::2",
                    destination_address="2001:db8:2::20",
                    protocol=protocol,
                    source_port=source_port,
                    destination_port=destination_port,
                )
                ipv6_config = audit_config(
                    peers=(AuditPeerSnapshot("office", PUBLIC_KEY, "alice", "2001:db8:1::2"),),
                    managed_tunnel_addresses=("2001:db8:1::2",),
                )
                correlator.consume_conntrack(ConntrackEvent("new", connection, BASE_TIME), ipv6_config)

                observations = correlator.expire(BASE_TIME + timedelta(seconds=1))

                self.assertEqual(AuditDecision.FORWARD_OBSERVED, observations[0].decision)
                self.assertEqual(destination_port, observations[0].destination_port)

    def test_managed_mode_ignores_unmanaged_peer_flows(self):
        peer = AuditPeerSnapshot("office", PUBLIC_KEY, "alice", "10.10.0.2")
        bob = AuditPeerSnapshot("office", "B" * 43 + "=", "bob", "10.10.0.3")
        managed = audit_config(mode="managed", peers=(peer, bob), managed_tunnel_addresses=(peer.tunnel_address,))
        correlator = FlowCorrelator(timedelta(seconds=1))

        correlator.consume_conntrack(
            ConntrackEvent("new", flow(source_address="10.10.0.3"), BASE_TIME),
            managed,
        )

        self.assertEqual([], correlator.expire(BASE_TIME + timedelta(seconds=1)))


class AuditSpoolTest(unittest.TestCase):
    def test_capacity_evicts_oldest_record_and_persists_only_observation_fields(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            spool = AuditSpool(
                pathlib.Path(temporary_directory) / "spool.db",
                max_records=2,
                max_bytes=4096,
                max_payload_bytes=1024,
            )
            try:
                spool.enqueue(observation(destination_address="198.51.100.1"), BASE_TIME)
                spool.enqueue(observation(destination_address="198.51.100.2"), BASE_TIME)
                spool.enqueue(observation(destination_address="198.51.100.3"), BASE_TIME)

                items = spool.due_items(BASE_TIME)
                stored_payload = json.loads(spool._connection.execute("SELECT Payload FROM AuditSpoolItems LIMIT 1").fetchone()[0])
                self.assertEqual(["198.51.100.2", "198.51.100.3"], [item.observation.destination_address for item in items])
                self.assertEqual(1, spool.stats().dropped_records)
                self.assertEqual(set(observation().__dict__), set(stored_payload))
                self.assertFalse({"payload", "url", "cookie", "raw_message"} & set(stored_payload))
            finally:
                spool.close()

    def test_retry_keeps_the_record_until_writer_recovers(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            spool = AuditSpool(pathlib.Path(temporary_directory) / "spool.db")
            try:
                spool.enqueue(observation(), BASE_TIME)
                retry_time = BASE_TIME + timedelta(seconds=10)
                self.assertEqual(0, spool.flush(lambda item: (_ for _ in ()).throw(RuntimeError("database unavailable")), now=BASE_TIME, retry_at=retry_time))
                self.assertEqual(0, len(spool.due_items(BASE_TIME + timedelta(seconds=9))))
                self.assertEqual(1, spool.due_items(retry_time)[0].attempts)
                received = []
                self.assertEqual(1, spool.flush(received.append, now=retry_time))
                self.assertEqual([observation()], received)
                self.assertEqual(0, spool.stats().records)
            finally:
                spool.close()

    def test_oversized_item_is_dropped_without_inserting_unbounded_data(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            spool = AuditSpool(pathlib.Path(temporary_directory) / "spool.db", max_bytes=256, max_payload_bytes=128)
            try:
                result = spool.enqueue(observation(peer_name_snapshot="x" * 200), BASE_TIME)
                self.assertIsNone(result.item_id)
                self.assertEqual(1, spool.stats().dropped_records)
                self.assertEqual(0, spool.stats().records)
            finally:
                spool.close()


class CollectorHealthTest(unittest.TestCase):
    def test_audit_service_writer_retries_initialization_after_database_failure(self):
        from network_audit.service import NetworkAuditServiceError

        received = []

        class WorkingService:
            def record_observation(self, item):
                received.append(item)

        with mock.patch(
            "network_audit.service.NetworkAuditService",
            side_effect=[NetworkAuditServiceError("audit database is unavailable"), WorkingService()],
        ) as service:
            writer = _AuditServiceWriter()
            with self.assertRaises(NetworkAuditServiceError):
                writer(observation())
            writer(observation())

        self.assertEqual(2, service.call_count)
        self.assertEqual([observation()], received)

    def test_collector_degrades_on_write_failure_and_writes_atomic_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            spool = AuditSpool(pathlib.Path(temporary_directory) / "spool.db")
            health_path = pathlib.Path(temporary_directory) / "health.json"
            try:
                collector = AuditCollector(
                    audit_config(),
                    spool,
                    lambda item: (_ for _ in ()).throw(RuntimeError("database unavailable")),
                    health_path=health_path,
                    now=BASE_TIME,
                )
                connection = flow()
                collector.handle_conntrack(ConntrackEvent("new", connection, BASE_TIME))
                collector.handle_nflog(NflogEvent(connection, "policy_allowed", BASE_TIME))
                collector.expire(BASE_TIME + timedelta(seconds=5))
                collector.flush(BASE_TIME + timedelta(seconds=5))
                snapshot = collector.write_health()

                self.assertEqual(HealthStatus.DEGRADED, snapshot.status)
                self.assertEqual("audit database unavailable", snapshot.last_error)
                self.assertEqual(snapshot, read_health_snapshot(health_path))
                self.assertEqual(1, snapshot.spool_records)
                self.assertEqual(1, snapshot.write_failures)
            finally:
                spool.close()

    def test_health_snapshot_rejects_unknown_fields_and_replaces_existing_file(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            health_path = pathlib.Path(temporary_directory) / "health.json"
            healthy = HealthSnapshot(HealthStatus.HEALTHY, BASE_TIME)
            failed = HealthSnapshot(HealthStatus.FAILED, BASE_TIME, last_error="NFLOG unavailable")
            write_health_snapshot(health_path, healthy)
            write_health_snapshot(health_path, failed)

            self.assertEqual(failed, read_health_snapshot(health_path))
            with self.assertRaises(AuditValidationError):
                HealthSnapshot.from_payload({**failed.to_payload(), "raw_packet": "secret"})

    def test_collector_merges_failed_config_sync_status_without_mutating_its_health_file(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            spool = AuditSpool(pathlib.Path(temporary_directory) / "spool.db")
            sync_status_path = pathlib.Path(temporary_directory) / "sync.json"
            try:
                write_config_sync_snapshot(
                    sync_status_path,
                    {
                        "status": "failed",
                        "updated_at": BASE_TIME,
                        "generation": 17,
                        "error": "network audit agent is unavailable",
                    },
                )
                snapshot = AuditCollector(
                    audit_config(),
                    spool,
                    lambda _item: None,
                    sync_status_path=sync_status_path,
                    now=BASE_TIME,
                ).health_snapshot()

                self.assertEqual(HealthStatus.DEGRADED, snapshot.status)
                self.assertEqual(ConfigSyncStatus.FAILED, snapshot.config_sync_status)
                self.assertEqual(17, snapshot.config_sync_generation)
                self.assertEqual("network audit agent is unavailable", snapshot.config_sync_error)
            finally:
                spool.close()


class AdapterCapabilityTest(unittest.TestCase):
    def test_conntrack_subscription_includes_new_update_and_destroy_groups(self):
        self.assertEqual(7, _netlink_multicast_mask((1, 2, 3)))

    def test_conntrack_reports_missing_optional_dependency_without_import_failure(self):
        with mock.patch("network_audit.collector.importlib.util.find_spec", return_value=None):
            capability = Pyroute2ConntrackAdapter().capability()

        self.assertFalse(capability.available)
        self.assertEqual("pyroute2 is not installed", capability.detail)

    def test_nflog_decoder_keeps_only_flow_metadata_and_fixed_decision(self):
        def attribute(attribute_type, value):
            length = 4 + len(value)
            padding = b"\x00" * ((4 - length % 4) % 4)
            return struct.pack("=HH", length, attribute_type) + value + padding

        ipv4_tcp = bytes((0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0, 10, 10, 0, 2, 198, 51, 100, 20))
        tcp_header = struct.pack("!HH", 43123, 443) + b"application-secret"
        attributes = b"".join((
            attribute(9, ipv4_tcp + tcp_header),
            attribute(10, b"wgd-audit:policy_allowed\x00"),
        ))
        netlink_length = 16 + 4 + len(attributes)
        datagram = (
            struct.pack("=IHHII", netlink_length, 1024, 0, 0, 0)
            + bytes((socket.AF_INET, 0)) + struct.pack("!H", 101)
            + attributes
        )

        events = decode_nflog_datagram(datagram, accepted_groups={100, 101, 102}, now=BASE_TIME)

        self.assertEqual(1, len(events))
        self.assertEqual(AuditDecision.POLICY_ALLOWED, events[0].decision)
        self.assertEqual(flow(), events[0].flow)
        self.assertNotIn("application-secret", repr(events[0]))

    def test_nflog_decoder_discards_unknown_prefix_and_truncated_packets(self):
        self.assertEqual([], decode_nflog_datagram(b"\x00" * 7, accepted_groups={100}, now=BASE_TIME))

    def test_conntrack_decoder_maps_original_tuple_and_counters_without_raw_message(self):
        message = {
            "header": {"type": 0, "flags": 1024},
            "attrs": [
                ["CTA_TUPLE_ORIG", {"attrs": [
                    ["CTA_TUPLE_IP", {"attrs": [["CTA_IP_V4_SRC", "10.10.0.2"], ["CTA_IP_V4_DST", "198.51.100.20"]]}],
                    ["CTA_TUPLE_PROTO", {"attrs": [["CTA_PROTO_NUM", 6], ["CTA_PROTO_SRC_PORT", 43123], ["CTA_PROTO_DST_PORT", 443]]}],
                ]}],
                ["CTA_COUNTERS_ORIG", {"attrs": [["CTA_COUNTERS_BYTES", 120]]}],
                ["CTA_COUNTERS_REPLY", {"attrs": [["CTA_COUNTERS_BYTES", 44]]}],
                ["CTA_ZONE", 3],
            ],
        }

        event = decode_conntrack_message(message, now=BASE_TIME)

        self.assertEqual(ConntrackEvent("new", flow(zone=3), BASE_TIME, 120, 44), event)

    def test_nflog_subscription_mode_uses_the_kernel_packed_six_byte_layout(self):
        adapter = NflogSocketAdapter({100})
        message = adapter._configuration_message(
            family=socket.AF_UNSPEC,
            resource_id=100,
            attributes=[adapter._attribute(adapter._NFULA_CFG_MODE, struct.pack("!IBx", 64, adapter._NFULNL_COPY_PACKET))],
            sequence=1,
        )
        attributes = list(adapter._configuration_attributes(message))

        self.assertEqual([(adapter._NFULA_CFG_MODE, struct.pack("!IBx", 64, adapter._NFULNL_COPY_PACKET))], attributes)


class CollectorRuntimeTest(unittest.TestCase):
    def test_runtime_marks_failed_and_writes_health_before_missing_adapter_exits(self):
        class UnavailableAdapter:
            def capability(self):
                return AdapterCapability(False, "test adapter unavailable")

            def events(self):
                return iter(())

        with tempfile.TemporaryDirectory() as temporary_directory:
            spool = AuditSpool(pathlib.Path(temporary_directory) / "spool.db")
            health_path = pathlib.Path(temporary_directory) / "health.json"
            try:
                collector = AuditCollector(audit_config(), spool, lambda _item: None, health_path=health_path, now=BASE_TIME)
                runtime = AuditCollectorRuntime(collector, UnavailableAdapter(), UnavailableAdapter(), health_interval=timedelta(0))

                with self.assertRaises(CollectorCapabilityError):
                    runtime.run()

                snapshot = read_health_snapshot(health_path)
                self.assertEqual(HealthStatus.FAILED, snapshot.status)
                self.assertEqual("collector failed", snapshot.last_error)
            finally:
                spool.close()

    def test_runtime_preserves_source_failure_health_without_relabeling_it_as_config_failure(self):
        class FailingAdapter:
            def capability(self):
                return AdapterCapability(True)

            def events(self):
                raise CollectorCapabilityError("source stopped")
                yield  # pragma: no cover

        with tempfile.TemporaryDirectory() as temporary_directory:
            spool = AuditSpool(pathlib.Path(temporary_directory) / "spool.db")
            health_path = pathlib.Path(temporary_directory) / "health.json"
            try:
                collector = AuditCollector(audit_config(), spool, lambda _item: None, health_path=health_path, now=BASE_TIME)
                runtime = AuditCollectorRuntime(collector, FailingAdapter(), FailingAdapter(), health_interval=timedelta(0))

                with self.assertRaises(CollectorCapabilityError):
                    runtime.run()

                self.assertEqual("collector failed", read_health_snapshot(health_path).last_error)
            finally:
                spool.close()


if __name__ == "__main__":
    unittest.main()
