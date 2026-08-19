import importlib
import os
import pathlib
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

try:
    import sqlalchemy as db
    from network_audit.health import HealthSnapshot, HealthStatus, write_health_snapshot
    from network_audit.service import NetworkAuditService
except ModuleNotFoundError:
    db = None


@unittest.skipIf(db is None, "SQLAlchemy is required for network audit dashboard alert tests")
class NetworkAuditDashboardAlertsApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary_directory = tempfile.TemporaryDirectory()
        cls.previous_directory = os.getcwd()
        cls.previous_configuration_path = os.environ.get("CONFIGURATION_PATH")
        cls.previous_health_path = os.environ.get("WGD_NETWORK_AUDIT_HEALTH_PATH")
        cls.wireguard_directory = pathlib.Path(cls.temporary_directory.name) / "wireguard"
        cls.wireguard_directory.mkdir()
        (pathlib.Path(cls.temporary_directory.name) / "wg-dashboard.ini").write_text(
            f"[Server]\nwg_conf_path = {cls.wireguard_directory}\n",
            encoding="utf-8",
        )
        (pathlib.Path(cls.temporary_directory.name) / "static").symlink_to(
            ROOT / "src" / "static",
            target_is_directory=True,
        )
        cls.health_path = pathlib.Path(cls.temporary_directory.name) / "health.json"
        os.chdir(cls.temporary_directory.name)
        os.environ["CONFIGURATION_PATH"] = cls.temporary_directory.name
        os.environ["WGD_NETWORK_AUDIT_HEALTH_PATH"] = str(cls.health_path)
        sys.modules.pop("dashboard", None)
        sys.modules.pop("modules.DashboardClients", None)
        sys.modules.pop("modules.DashboardConfig", None)
        sys.modules.pop("modules.DashboardOIDC", None)
        cls.dashboard = importlib.import_module("dashboard")
        cls.service = NetworkAuditService(pathlib.Path(cls.temporary_directory.name) / "audit-alerts-api.db")
        cls.dashboard.NetworkAuditManager = cls.service
        cls.dashboard.app.config.update(TESTING=True)

    @classmethod
    def tearDownClass(cls):
        cls.service.engine.dispose()
        sys.modules.pop("dashboard", None)
        sys.modules.pop("modules.DashboardClients", None)
        sys.modules.pop("modules.DashboardConfig", None)
        sys.modules.pop("modules.DashboardOIDC", None)
        os.chdir(cls.previous_directory)
        if cls.previous_configuration_path is None:
            os.environ.pop("CONFIGURATION_PATH", None)
        else:
            os.environ["CONFIGURATION_PATH"] = cls.previous_configuration_path
        if cls.previous_health_path is None:
            os.environ.pop("WGD_NETWORK_AUDIT_HEALTH_PATH", None)
        else:
            os.environ["WGD_NETWORK_AUDIT_HEALTH_PATH"] = cls.previous_health_path
        cls.temporary_directory.cleanup()

    def setUp(self):
        self.client = self.dashboard.app.test_client()
        for section, key, value in (
            ("Email", "server", "smtp.example.com"),
            ("Email", "port", "587"),
            ("Email", "encryption", "STARTTLS"),
            ("Email", "username", "alerts@example.com"),
            ("Email", "email_password", "test-password"),
            ("Email", "send_from", "alerts@example.com"),
            ("Email", "audit_alert_recipient", ""),
            ("NetworkAudit", "alerts_enabled", False),
            ("NetworkAudit", "denied_threshold", 10),
            ("NetworkAudit", "scan_threshold", 20),
            ("NetworkAudit", "cooldown_minutes", 30),
            ("NetworkAudit", "alert_tested_at", ""),
            ("NetworkAudit", "alert_tested_recipient", ""),
            ("NetworkAudit", "alert_tested_smtp_ready", False),
        ):
            self.dashboard.DashboardConfig.SetConfig(section, key, value)
        self.health_path.unlink(missing_ok=True)

    def _admin_client(self):
        with self.client.session_transaction() as flask_session:
            flask_session["username"] = "admin"
            flask_session["role"] = "admin"
            flask_session["auth_source"] = "dashboard_login"
        return self.client

    @staticmethod
    def _config(**overrides):
        payload = {
            "alerts_enabled": False,
            "audit_alert_recipient": "alerts@example.com",
            "denied_threshold": 10,
            "scan_threshold": 20,
            "cooldown_minutes": 30,
        }
        payload.update(overrides)
        return payload

    def test_all_alert_endpoints_require_a_dashboard_admin_session(self):
        for method, path in (
            (self.client.get, "/api/networkAudit/health"),
            (self.client.get, "/api/networkAudit/alerts/config"),
            (self.client.post, "/api/networkAudit/alerts/config"),
            (self.client.post, "/api/networkAudit/alerts/test"),
            (self.client.get, "/api/networkAudit/alerts/status"),
        ):
            response = method(path, json=self._config()) if path.endswith("/config") else method(path)
            self.assertEqual(401, response.status_code)
            self.assertIsNone(response.get_json()["data"])

        authenticated = self._admin_client()
        response = authenticated.get(
            "/api/networkAudit/alerts/config", headers={"wg-dashboard-apikey": "blocked"},
        )
        self.assertEqual(401, response.status_code)
        self.assertIsNone(response.get_json()["data"])

    def test_configuration_rejects_invalid_input_and_enable_without_test(self):
        admin = self._admin_client()
        invalid_recipient = admin.post(
            "/api/networkAudit/alerts/config", json=self._config(audit_alert_recipient="invalid"),
        )
        self.assertEqual(400, invalid_recipient.status_code)

        invalid_threshold = admin.post(
            "/api/networkAudit/alerts/config", json=self._config(denied_threshold=True),
        )
        self.assertEqual(400, invalid_threshold.status_code)

        enable_without_test = admin.post(
            "/api/networkAudit/alerts/config", json=self._config(alerts_enabled=True),
        )
        self.assertEqual(400, enable_without_test.status_code)
        self.assertIn("recipient", enable_without_test.get_json()["message"].lower())

        bypass = admin.post(
            "/api/updateDashboardConfigurationItem",
            json={"section": "NetworkAudit", "key": "alerts_enabled", "value": True},
        )
        self.assertEqual(400, bypass.status_code)

    def test_test_email_marks_current_recipient_and_permits_enable(self):
        admin = self._admin_client()
        configured = admin.post("/api/networkAudit/alerts/config", json=self._config())
        self.assertEqual(200, configured.status_code)

        with mock.patch.object(self.dashboard.EmailSender, "is_ready", return_value=True), mock.patch.object(
            self.dashboard.EmailSender, "send", return_value=(True, None),
        ) as send:
            test_response = admin.post(
                "/api/networkAudit/alerts/test",
                json={"audit_alert_recipient": "alerts@example.com"},
            )
        self.assertEqual(200, test_response.status_code)
        send.assert_called_once()
        self.assertTrue(test_response.get_json()["data"]["ready_to_enable"])

        enabled = admin.post("/api/networkAudit/alerts/config", json=self._config(alerts_enabled=True))
        self.assertEqual(200, enabled.status_code)
        self.assertTrue(enabled.get_json()["data"]["alerts_enabled"])

        changed_recipient = admin.post(
            "/api/networkAudit/alerts/config",
            json=self._config(alerts_enabled=False, audit_alert_recipient="new-alerts@example.com"),
        )
        self.assertEqual(200, changed_recipient.status_code)
        self.assertFalse(changed_recipient.get_json()["data"]["test"]["ready_to_enable"])

    def test_test_email_failure_is_safe_and_health_is_structured(self):
        admin = self._admin_client()
        admin.post("/api/networkAudit/alerts/config", json=self._config())
        with mock.patch.object(self.dashboard.EmailSender, "is_ready", return_value=True), mock.patch.object(
            self.dashboard.EmailSender, "send", return_value=(False, "smtp password leaked"),
        ):
            failed = admin.post(
                "/api/networkAudit/alerts/test",
                json={"audit_alert_recipient": "alerts@example.com"},
            )
        self.assertEqual(503, failed.status_code)
        self.assertNotIn("password", failed.get_json()["message"].lower())

        missing_health = admin.get("/api/networkAudit/health")
        self.assertEqual(200, missing_health.status_code)
        self.assertEqual("missing", missing_health.get_json()["data"]["state"])

        write_health_snapshot(
            self.health_path,
            HealthSnapshot(HealthStatus.HEALTHY, datetime.now(timezone.utc)),
        )
        healthy = admin.get("/api/networkAudit/health")
        self.assertEqual(200, healthy.status_code)
        health_data = healthy.get_json()["data"]
        self.assertEqual("healthy", health_data["state"])
        self.assertEqual("healthy", health_data["snapshot"]["status"])

    def test_status_returns_persisted_alert_runner_state(self):
        response = self._admin_client().get("/api/networkAudit/alerts/status")
        self.assertEqual(200, response.status_code)
        self.assertIn("latest_run", response.get_json()["data"])
        self.assertIn("latest_delivery", response.get_json()["data"])


if __name__ == "__main__":
    unittest.main()
