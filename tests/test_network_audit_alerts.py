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
        NetworkAuditAlertRunner,
        evaluate_health_snapshot,
        load_alert_configuration,
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
        write_health_snapshot(
            self.health_path,
            HealthSnapshot(HealthStatus.HEALTHY, BASE_TIME, write_failures=3),
        )
        self.health_path.touch()
        timestamp = BASE_TIME.timestamp()
        os.utime(self.health_path, (timestamp, timestamp))
        current = evaluate_health_snapshot(self.health_path, now=BASE_TIME)
        self.assertEqual("storage_write", current[-1].identity)

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
