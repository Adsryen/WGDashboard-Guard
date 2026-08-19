import importlib
import os
import pathlib
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

try:
    import sqlalchemy as db
    from network_audit.repository import WINDOW_DURATION
    from network_audit.service import NetworkAuditService, NetworkAuditServiceError
    from network_audit.validation import AuditObservation, AuditValidationError
except ModuleNotFoundError:
    db = None
    NetworkAuditService = None
    NetworkAuditServiceError = RuntimeError
    AuditObservation = None
    AuditValidationError = ValueError


PUBLIC_KEY = "a" * 43 + "="
BASE_TIME = datetime(2026, 8, 18, 12, 1, tzinfo=timezone.utc)


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
        "bytes_from_peer": 100,
        "bytes_to_peer": 200,
    }
    payload.update(overrides)
    return AuditObservation(**payload)


def query_payload(**overrides):
    payload = {
        "start_time": "2026-08-18T12:00:00Z",
        "end_time": "2026-08-18T13:00:00Z",
    }
    payload.update(overrides)
    return payload


@unittest.skipIf(db is None, "SQLAlchemy is required for network audit tests")
class NetworkAuditServiceTest(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = pathlib.Path(self.temporary_directory.name) / "wgdashboard_audit.db"
        self.service = NetworkAuditService(self.database_path)

    def tearDown(self):
        self.service.engine.dispose()
        self.temporary_directory.cleanup()

    def test_initializes_an_independent_schema_without_main_database_tables(self):
        tables = set(db.inspect(self.service.engine).get_table_names())

        self.assertEqual(
            {
                "AuditSchemaVersions", "AuditActivityWindows", "AuditDailyAggregates", "AuditRetentionRuns",
                "AuditAlertStates", "AuditAlertDeliveries", "AuditAlertRuns",
            },
            tables,
        )
        self.assertTrue(self.database_path.exists())

    def test_same_five_minute_window_upserts_and_null_port_key_does_not_duplicate(self):
        self.service.record_observation(observation(observed_at=BASE_TIME))
        self.service.record_observation(observation(
            observed_at=BASE_TIME.replace(minute=4), connection_increment=3,
            bytes_from_peer=20, bytes_to_peer=30,
        ))
        self.service.record_observation(observation(
            protocol="icmp", destination_port=None, observed_at=BASE_TIME,
        ))
        self.service.record_observation(observation(
            protocol="icmp", destination_port=None, observed_at=BASE_TIME.replace(minute=3),
        ))

        result = self.service.query(query_payload())
        self.assertEqual(2, result["pagination"]["total"])
        tcp_record = next(record for record in result["records"] if record["protocol"] == "tcp")
        icmp_record = next(record for record in result["records"] if record["protocol"] == "icmp")
        self.assertEqual("2026-08-18T12:00:00Z", tcp_record["window_started_at"])
        self.assertEqual(4, tcp_record["connection_count"])
        self.assertEqual(120, tcp_record["bytes_from_peer"])
        self.assertEqual(230, tcp_record["bytes_to_peer"])
        self.assertIsNone(icmp_record["destination_port"])
        self.assertEqual(2, icmp_record["connection_count"])

    def test_query_filters_preserve_snapshots_and_paginates_stably(self):
        self.service.record_observation(observation(
            observed_at=BASE_TIME, peer_name_snapshot="old-name", destination_address="192.168.1.10",
        ))
        self.service.record_observation(observation(
            observed_at=BASE_TIME + timedelta(minutes=5), peer_name_snapshot="new-name",
            destination_address="192.168.1.11", destination_port=8443, decision="policy_allowed",
        ))
        self.service.record_observation(observation(
            observed_at=BASE_TIME + timedelta(minutes=10), destination_address="2001:db8::10",
            destination_port=8443, decision="policy_denied",
        ))

        filtered = self.service.query(query_payload(
            destination="192.168.1.0/24", protocol="tcp", destination_port=8443,
            decision="policy_allowed", page_size=1,
        ))
        self.assertEqual(1, filtered["pagination"]["total"])
        self.assertEqual("new-name", filtered["records"][0]["peer_name_snapshot"])
        self.assertEqual("192.168.1.11", filtered["records"][0]["destination_address"])

        all_records = self.service.query(query_payload(page_size=10))["records"]
        self.assertEqual(["2001:db8::10", "192.168.1.11", "192.168.1.10"], [
            record["destination_address"] for record in all_records
        ])

    def test_validation_rejects_invalid_observations_and_unbounded_queries(self):
        with self.assertRaises(AuditValidationError):
            observation(destination_address="0.0.0.0")
        with self.assertRaises(AuditValidationError):
            observation(protocol="tcp", destination_port=None)
        with self.assertRaises(AuditValidationError):
            self.service.record_observation({**observation().__dict__, "http_payload": "secret"})
        with self.assertRaises(AuditValidationError):
            self.service.query({"start_time": "2026-08-18T12:00:00Z"})
        with self.assertRaises(AuditValidationError):
            self.service.query(query_payload(end_time="2026-10-18T12:00:00Z"))
        with self.assertRaises(AuditValidationError):
            self.service.query(query_payload(page_size=101))
        with self.assertRaises(AuditValidationError):
            self.service.query(query_payload(destination="0.0.0.0/0"))
        with self.assertRaises(AuditValidationError):
            self.service.query(query_payload(destination="::/0"))

    def test_summary_and_retention_keep_boundary_windows_and_delete_expired_rows(self):
        now = datetime(2026, 8, 18, 12, 0, tzinfo=timezone.utc)
        detail_boundary = now - timedelta(days=180)
        self.service.record_observation(observation(observed_at=detail_boundary - timedelta(minutes=4)))
        self.service.record_observation(observation(
            observed_at=detail_boundary - WINDOW_DURATION - timedelta(seconds=1), destination_address="192.168.1.11",
        ))
        self.service.record_observation(observation(
            observed_at=datetime(2024, 7, 18, 12, 0, tzinfo=timezone.utc), destination_address="192.168.1.12",
        ))

        summary = self.service.summary(query_payload())
        self.assertEqual(0, summary["window_count"])

        result = self.service.cleanup_retention(now)
        self.assertEqual(2, result["activity_windows_deleted"])
        self.assertEqual(1, result["daily_aggregates_deleted"])
        with self.service.engine.connect() as connection:
            remaining_windows = connection.scalar(db.select(db.func.count()).select_from(
                self.service.repository.activity_windows
            ))
            retention_runs = connection.scalar(db.select(db.func.count()).select_from(
                self.service.repository.retention_runs
            ))
        self.assertEqual(1, remaining_windows)
        self.assertEqual(1, retention_runs)

    def test_database_errors_are_exposed_as_audit_service_errors(self):
        with mock.patch.object(self.service.repository, "query", side_effect=db.exc.OperationalError("query", {}, Exception())):
            with self.assertRaises(NetworkAuditServiceError):
                self.service.query(query_payload())

    def test_engine_creation_errors_are_exposed_as_audit_service_errors(self):
        with mock.patch.object(NetworkAuditService, "_create_engine", side_effect=OSError("read-only directory")):
            with self.assertRaises(NetworkAuditServiceError):
                NetworkAuditService(self.database_path)


@unittest.skipIf(db is None, "SQLAlchemy is required for network audit API tests")
class NetworkAuditApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary_directory = tempfile.TemporaryDirectory()
        cls.previous_directory = os.getcwd()
        cls.previous_configuration_path = os.environ.get("CONFIGURATION_PATH")
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
        os.chdir(cls.temporary_directory.name)
        os.environ["CONFIGURATION_PATH"] = cls.temporary_directory.name
        sys.modules.pop("dashboard", None)
        cls.dashboard = importlib.import_module("dashboard")
        cls.service = NetworkAuditService(pathlib.Path(cls.temporary_directory.name) / "audit-api.db")
        cls.dashboard.NetworkAuditManager = cls.service
        cls.dashboard.app.config.update(TESTING=True)

    @classmethod
    def tearDownClass(cls):
        cls.service.engine.dispose()
        sys.modules.pop("dashboard", None)
        os.chdir(cls.previous_directory)
        if cls.previous_configuration_path is None:
            os.environ.pop("CONFIGURATION_PATH", None)
        else:
            os.environ["CONFIGURATION_PATH"] = cls.previous_configuration_path
        cls.temporary_directory.cleanup()

    def setUp(self):
        self.service.record_observation(observation())
        self.client = self.dashboard.app.test_client()

    def _admin_client(self):
        with self.client.session_transaction() as flask_session:
            flask_session["username"] = "admin"
            flask_session["role"] = "admin"
            flask_session["auth_source"] = "dashboard_login"
        return self.client

    def _api_key_client(self):
        api_key = "audit-api-key"
        self.dashboard.DashboardConfig.SetConfig("Server", "dashboard_api_key", True)
        self.dashboard.DashboardConfig.DashboardAPIKeys = [type("APIKey", (), {"Key": api_key})()]
        response = self.client.post(
            "/api/authenticate", json={}, headers={"wg-dashboard-apikey": api_key},
        )
        self.assertEqual(200, response.status_code)
        return self.client

    def test_query_and_summary_require_dashboard_admin_session(self):
        unauthorized = self.client.post("/api/networkAudit/query", json=query_payload())
        self.assertEqual(401, unauthorized.status_code)
        self.assertIsNone(unauthorized.get_json()["data"])

        api_key = self._api_key_client().post("/api/networkAudit/query", json=query_payload())
        self.assertEqual(401, api_key.status_code)
        self.assertIsNone(api_key.get_json()["data"])

        api_key_summary = self.client.get("/api/networkAudit/summary", query_string=query_payload())
        self.assertEqual(401, api_key_summary.status_code)
        self.assertIsNone(api_key_summary.get_json()["data"])

        authenticated_with_api_key = self._admin_client()
        api_key_query = authenticated_with_api_key.post(
            "/api/networkAudit/query",
            json=query_payload(),
            headers={"wg-dashboard-apikey": "audit-api-key"},
        )
        self.assertEqual(401, api_key_query.status_code)
        self.assertIsNone(api_key_query.get_json()["data"])

        api_key_summary = authenticated_with_api_key.get(
            "/api/networkAudit/summary",
            query_string=query_payload(),
            headers={"wg-dashboard-apikey": "audit-api-key"},
        )
        self.assertEqual(401, api_key_summary.status_code)
        self.assertIsNone(api_key_summary.get_json()["data"])

        with self.dashboard.app.test_request_context(
            "/api/networkAudit/query",
            method="POST",
            json=query_payload(),
            headers={"wg-dashboard-apikey": "audit-api-key"},
        ):
            self.dashboard.session.update({
                "username": "admin",
                "role": "admin",
                "auth_source": "dashboard_login",
            })
            self.dashboard.DashboardConfig.APIAccessed = False
            isolated_api_key_response = self.dashboard.API_NetworkAuditQuery()
        self.assertEqual(401, isolated_api_key_response.status_code)
        self.assertIsNone(isolated_api_key_response.get_json()["data"])

        query_response = self._admin_client().post("/api/networkAudit/query", json=query_payload())
        self.assertEqual(200, query_response.status_code)
        self.assertEqual(1, query_response.get_json()["data"]["pagination"]["total"])

        summary_response = self._admin_client().get("/api/networkAudit/summary", query_string=query_payload())
        self.assertEqual(200, summary_response.status_code)
        self.assertEqual(1, summary_response.get_json()["data"]["window_count"])

    def test_query_returns_400_for_invalid_filters_and_503_when_database_fails(self):
        bad_query = self._admin_client().post("/api/networkAudit/query", json={"page_size": 500})
        self.assertEqual(400, bad_query.status_code)

        with mock.patch.object(self.service.repository, "query", side_effect=db.exc.OperationalError("query", {}, Exception())):
            unavailable = self._admin_client().post("/api/networkAudit/query", json=query_payload())
        self.assertEqual(503, unavailable.status_code)


if __name__ == "__main__":
    unittest.main()
