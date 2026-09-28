import pathlib
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

try:
    import sqlalchemy as db
    from network_audit.alerts import (
        AlertConfiguration,
        AlertConfigurationError,
        AlertEvent,
        NetworkAuditAlertRunner,
        DEFAULT_STORAGE_WRITE_RECENCY,
        _alert_body,
        _alert_detail,
        _alert_subject,
        bounded_error,
        evaluate_health_snapshot,
        load_alert_configuration,
        storage_write_detail,
        storage_write_is_current,
    )
    from network_audit.health import HealthSnapshot, HealthStatus, write_health_snapshot
    from network_audit.service import NetworkAuditService
    from network_audit.validation import AuditObservation
except ModuleNotFoundError:
    db = None


PUBLIC_KEY = "a" * 43 + "="
BASE_TIME = datetime(2026, 8, 19, 12, 1, tzinfo=timezone.utc)


def observation(**overrides):
    payload = {
        "configuration_name": "wg0",
        "peer_public_key": PUBLIC_KEY,
        "peer_name_snapshot": "laptop",
        "tunnel_address": "10.8.0.2",
        "destination_address": "192.168.1.10",
        "protocol": "tcp",
        "destination_port": 443,
        "decision": "forward_observed",
        "observed_at": BASE_TIME,
        "connection_increment": 1,
        "bytes_from_peer": 0,
        "bytes_to_peer": 0,
    }
    payload.update(overrides)
    return AuditObservation(**payload)


class FakeMailer:
    def __init__(self, result=(True, None), ready=True):
        self.result = result
        self.ready = ready
        self.sent = []

    def is_ready(self):
        return self.ready

    def send(self, receiver, subject, body):
        self.sent.append((receiver, subject, body))
        return self.result


@unittest.skipIf(db is None, "SQLAlchemy is required for network audit alert tests")
class NetworkAuditAlertCoreTest(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temporary_directory.name)
        self.service = NetworkAuditService(self.root / "audit.db")
        self.health_path = self.root / "health.json"

    def tearDown(self):
        self.service.engine.dispose()
        self.temporary_directory.cleanup()

    def write_fresh(self, snapshot):
        """Publish a snapshot and backdate its mtime to BASE_TIME so staleness never interferes."""
        write_health_snapshot(self.health_path, snapshot)
        stamp = BASE_TIME.timestamp()
        os.utime(self.health_path, (stamp, stamp))

    def configuration(self, **overrides):
        payload = {
            "alerts_enabled": True,
            "recipient": "alerts@example.com",
            "denied_threshold": 2,
            "scan_threshold": 2,
            "cooldown_minutes": 30,
            "alert_tested_at": BASE_TIME,
            "alert_tested_recipient": "alerts@example.com",
            "alert_tested_smtp_ready": True,
        }
        payload.update(overrides)
        return AlertConfiguration.from_payload(payload)

    def test_typed_configuration_rejects_unknown_fields_and_requires_current_test(self):
        with self.assertRaises(AlertConfigurationError):
            AlertConfiguration.from_payload({"payload": "secret"})
        configuration = self.configuration(alert_tested_recipient="other@example.com")
        self.assertFalse(configuration.delivery_enabled)

    def test_activity_candidates_aggregate_denials_and_distinct_scan_dimensions(self):
        for _ in range(2):
            self.service.record_observation(observation(decision="policy_denied"))
        self.service.record_observation(observation(destination_address="192.168.1.11", destination_port=443))
        self.service.record_observation(observation(destination_address="192.168.1.11", destination_port=8443))
        self.service.record_observation(observation(destination_address="192.168.1.12", destination_port=443))

        candidates = self.service.alert_candidates(now=BASE_TIME + timedelta(minutes=4))
        by_type = {candidate["alert_type"]: candidate for candidate in candidates}
        self.assertEqual(2, by_type["denied"]["ObservedValue"])
        self.assertEqual(4, by_type["scan"]["ObservedValue"])

    def test_claim_is_atomic_and_cooldown_survives_delivery_failure(self):
        first = self.service.claim_alert(
            identity=f"denied:{PUBLIC_KEY}", alert_type="denied", cooldown=timedelta(minutes=30), now=BASE_TIME,
            peer_public_key=PUBLIC_KEY, peer_name_snapshot="laptop", tunnel_address="10.8.0.2",
        )
        self.assertIsNotNone(first)
        self.assertIsNone(self.service.claim_alert(
            identity=f"denied:{PUBLIC_KEY}", alert_type="denied", cooldown=timedelta(minutes=30),
            now=BASE_TIME + timedelta(minutes=1),
        ))
        self.service.complete_alert_delivery(first, succeeded=False, error_summary="SMTP unavailable", now=BASE_TIME)
        status = self.service.alert_status()
        self.assertFalse(status["latest_delivery"]["succeeded"])
        self.assertEqual("SMTP unavailable", status["last_error_summary"])
        self.assertIsNone(self.service.claim_alert(
            identity=f"denied:{PUBLIC_KEY}", alert_type="denied", cooldown=timedelta(minutes=30),
            now=BASE_TIME + timedelta(minutes=29),
        ))
        self.assertIsNotNone(self.service.claim_alert(
            identity=f"denied:{PUBLIC_KEY}", alert_type="denied", cooldown=timedelta(minutes=30),
            now=BASE_TIME + timedelta(minutes=30),
        ))

    def test_health_evaluation_handles_missing_stale_and_storage_failure(self):
        missing = evaluate_health_snapshot(self.health_path, now=BASE_TIME)
        self.assertEqual("collector_health", missing[0].identity)
        self.assertEqual("health snapshot is missing", missing[0].detail)

        write_health_snapshot(self.health_path, HealthSnapshot(HealthStatus.HEALTHY, BASE_TIME))
        stale_stamp = (BASE_TIME - timedelta(minutes=6)).timestamp()
        os.utime(self.health_path, (stale_stamp, stale_stamp))
        stale = evaluate_health_snapshot(self.health_path, now=BASE_TIME)
        self.assertEqual(["collector_health"], [event.identity for event in stale])
        self.assertEqual("health snapshot is stale", stale[0].detail)

        self.write_fresh(HealthSnapshot(
            HealthStatus.HEALTHY, BASE_TIME,
            write_failures=3, last_write_failure_at=BASE_TIME - timedelta(seconds=5),
        ))
        current = evaluate_health_snapshot(self.health_path, now=BASE_TIME)
        self.assertEqual(["storage_write"], [event.identity for event in current])
        self.assertEqual(3, current[0].observed_value)
        self.assertIn("cumulative_since_start=3", current[0].detail)

    def test_latched_storage_failure_outside_the_recency_window_stays_silent(self):
        # write_failures only resets on collector restart. The 2026-09-28 incident sent seven
        # identical emails for two transient failures four hours earlier, so a counted failure
        # has to be recent as well as non-zero.
        self.write_fresh(HealthSnapshot(
            HealthStatus.HEALTHY, BASE_TIME,
            write_failures=7, last_write_failure_at=BASE_TIME - timedelta(minutes=6),
        ))
        self.assertEqual([], evaluate_health_snapshot(self.health_path, now=BASE_TIME))

    def test_storage_write_recency_boundary_is_inclusive(self):
        for age, expected in ((timedelta(minutes=5), 1), (timedelta(minutes=5, seconds=1), 0)):
            with self.subTest(age=age):
                self.write_fresh(HealthSnapshot(
                    HealthStatus.HEALTHY, BASE_TIME, write_failures=2, last_write_failure_at=BASE_TIME - age,
                ))
                events = evaluate_health_snapshot(self.health_path, now=BASE_TIME)
                self.assertEqual(expected, len([event for event in events if event.identity == "storage_write"]))

    def test_snapshot_without_a_write_failure_timestamp_falls_back_to_status(self):
        # Collectors built before the timestamp existed only publish the counter. Falling back to
        # the live status keeps a real outage alerting without letting a recovered collector shout.
        self.write_fresh(HealthSnapshot(
            HealthStatus.DEGRADED, BASE_TIME, write_failures=4, last_error="audit database unavailable",
        ))
        degraded = evaluate_health_snapshot(self.health_path, now=BASE_TIME)
        self.assertEqual(["collector_health", "storage_write"], [event.identity for event in degraded])
        self.assertEqual("collector audit storage writes are failing", degraded[-1].detail)

        self.write_fresh(HealthSnapshot(HealthStatus.HEALTHY, BASE_TIME, write_failures=4))
        self.assertEqual([], evaluate_health_snapshot(self.health_path, now=BASE_TIME))

    def test_zero_write_failures_never_alert_even_with_a_current_timestamp(self):
        self.write_fresh(HealthSnapshot(
            HealthStatus.HEALTHY, BASE_TIME, write_failures=0, last_write_failure_at=BASE_TIME,
        ))
        self.assertEqual([], evaluate_health_snapshot(self.health_path, now=BASE_TIME))

    def test_storage_recency_must_be_a_positive_timedelta(self):
        self.write_fresh(HealthSnapshot(HealthStatus.HEALTHY, BASE_TIME))
        for invalid in (timedelta(0), timedelta(minutes=-1), "PT5M", None):
            with self.subTest(storage_recency=invalid):
                with self.assertRaises(ValueError):
                    evaluate_health_snapshot(self.health_path, now=BASE_TIME, storage_recency=invalid)

    def test_storage_write_recency_tolerates_the_naive_and_aware_mix(self):
        # normalize_utc() hands back naive UTC while HealthSnapshot stores aware UTC. Subtracting
        # one from the other raises TypeError, which used to abort every single health check.
        snapshot = HealthSnapshot(
            HealthStatus.HEALTHY, BASE_TIME, write_failures=1, last_write_failure_at=BASE_TIME,
        )
        self.assertTrue(storage_write_is_current(snapshot, BASE_TIME, DEFAULT_STORAGE_WRITE_RECENCY))
        self.assertTrue(storage_write_is_current(
            snapshot, BASE_TIME.replace(tzinfo=None), DEFAULT_STORAGE_WRITE_RECENCY,
        ))
        self.assertFalse(storage_write_is_current(
            snapshot, BASE_TIME + timedelta(minutes=6), DEFAULT_STORAGE_WRITE_RECENCY,
        ))

    def test_storage_write_detail_and_chinese_translation(self):
        snapshot = HealthSnapshot(
            HealthStatus.DEGRADED, BASE_TIME, write_failures=7,
            last_write_failure_at=datetime(2026, 9, 28, 2, 14, 3, tzinfo=timezone.utc),
            last_error="audit database unavailable",
        )
        detail = storage_write_detail(snapshot)
        self.assertEqual(
            "collector audit storage writes are failing "
            "(last_failure_at=2026-09-28T02:14:03+00:00; cumulative_since_start=7)",
            detail,
        )
        self.assertEqual(
            "采集器审计存储写入失败，最近一次 2026-09-28 02:14:03 UTC，自采集器启动累计 7 次",
            _alert_detail(detail),
        )
        body = _alert_body(
            AlertEvent(identity="storage_write", alert_type="storage_write", observed_value=7,
                       threshold=None, detail=detail),
            BASE_TIME,
        )
        self.assertIn("告警类型：审计存储写入失败", body)
        self.assertIn("详细信息：采集器审计存储写入失败，最近一次 2026-09-28 02:14:03 UTC", body)
        self.assertEqual(
            "collector audit storage writes are failing",
            storage_write_detail(HealthSnapshot(HealthStatus.HEALTHY, BASE_TIME, write_failures=2)),
        )

    def test_alert_email_subject_and_body_are_in_chinese(self):
        event = AlertEvent(
            identity="collector_health",
            alert_type="collector_health",
            observed_value=1,
            threshold=None,
            tunnel_address="10.253.157.1",
            detail="health snapshot is stale",
        )

        subject = _alert_subject(event)
        body = _alert_body(event, BASE_TIME)

        self.assertEqual("[WGDashboard] 网络审计告警：采集器健康状态", subject)
        self.assertIn("WGDashboard 网络审计告警", body)
        self.assertIn("告警类型：采集器健康状态", body)
        self.assertIn("详细信息：健康快照已过期", body)
        self.assertIn("隧道地址：10.253.157.1", body)
        self.assertIn("策略判定表示网关观测结果", body)

    def test_health_event_detail_carries_snapshot_last_error(self):
        write_health_snapshot(
            self.health_path,
            HealthSnapshot(
                HealthStatus.DEGRADED, BASE_TIME,
                netlink_overruns=2, last_error="netlink event buffer overflow",
            ),
        )
        timestamp = BASE_TIME.timestamp()
        os.utime(self.health_path, (timestamp, timestamp))

        events = evaluate_health_snapshot(self.health_path, now=BASE_TIME)

        self.assertEqual(1, len(events))
        self.assertEqual("collector_health", events[0].identity)
        self.assertEqual("collector status is degraded (netlink event buffer overflow)", events[0].detail)

    def test_health_event_detail_without_last_error_keeps_status_only(self):
        write_health_snapshot(self.health_path, HealthSnapshot(HealthStatus.FAILED, BASE_TIME))
        timestamp = BASE_TIME.timestamp()
        os.utime(self.health_path, (timestamp, timestamp))

        events = evaluate_health_snapshot(self.health_path, now=BASE_TIME)

        self.assertEqual(["collector status is failed"], [event.detail for event in events])

    def test_alert_detail_maps_known_last_error_and_truncates_unknown(self):
        self.assertEqual(
            "采集器状态：降级，最后错误：netlink 事件缓冲溢出",
            _alert_detail("collector status is degraded (netlink event buffer overflow)"),
        )
        self.assertEqual(
            "采集器状态：失败，最后错误：审计数据库不可用",
            _alert_detail("collector status is failed (audit database unavailable)"),
        )
        self.assertEqual("采集器状态：失败", _alert_detail("collector status is failed"))

        unknown = "x" * 1000
        self.assertEqual(
            f"采集器状态：降级，最后错误：{bounded_error(unknown)}",
            _alert_detail(f"collector status is degraded ({unknown})"),
        )

    def test_unrecognized_detail_is_returned_unchanged(self):
        self.assertEqual("unexpected transport hiccup", _alert_detail("unexpected transport hiccup"))

    def test_denied_event_body_has_no_detail_line(self):
        event = AlertEvent(
            identity=f"denied:{PUBLIC_KEY}",
            alert_type="denied",
            observed_value=2,
            threshold=2,
            peer_public_key=PUBLIC_KEY,
            peer_name_snapshot="laptop",
        )

        body = _alert_body(event, BASE_TIME)

        self.assertNotIn("详细信息", body)
        self.assertIn("告警类型：策略拒绝", body)

    def test_runner_delivers_once_then_deduplicates_and_bounds_smtp_error(self):
        for _ in range(2):
            self.service.record_observation(observation(decision="policy_denied"))
        write_health_snapshot(self.health_path, HealthSnapshot(HealthStatus.HEALTHY, BASE_TIME))
        timestamp = BASE_TIME.timestamp()
        os.utime(self.health_path, (timestamp, timestamp))
        mailer = FakeMailer(result=(False, "password=secret " + "x" * 1000))
        runner = NetworkAuditAlertRunner(
            self.service,
            configuration_provider=lambda: self.configuration(scan_threshold=100),
            health_path=self.health_path,
            email_sender_factory=lambda: mailer,
            health_timeout=timedelta(days=1),
        )
        first = runner.run_once(BASE_TIME + timedelta(minutes=4))
        second = runner.run_once(BASE_TIME + timedelta(minutes=5))
        self.assertEqual(1, first.claims_created)
        self.assertEqual(0, first.deliveries_succeeded)
        self.assertEqual(0, second.claims_created)
        self.assertEqual(1, len(mailer.sent))
        self.assertNotIn("password", self.service.alert_status()["last_error_summary"])
        self.assertLessEqual(len(self.service.alert_status()["last_error_summary"]), 512)

    def test_runner_configuration_reads_ini_without_flask(self):
        configuration_path = self.root / "wg-dashboard.ini"
        configuration_path.write_text(
            "[Email]\naudit_alert_recipient = alerts@example.com\n"
            "[NetworkAudit]\nalerts_enabled = true\ndenied_threshold = 10\nscan_threshold = 20\n"
            "cooldown_minutes = 30\nalert_tested_at = 2026-08-19T12:00:00Z\n"
            "alert_tested_recipient = alerts@example.com\nalert_tested_smtp_ready = true\n",
            encoding="utf-8",
        )
        configuration = load_alert_configuration(configuration_path)
        self.assertTrue(configuration.delivery_enabled)
        self.assertEqual(30, configuration.cooldown_minutes)


if __name__ == "__main__":
    unittest.main()
