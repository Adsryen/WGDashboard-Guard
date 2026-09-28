import importlib
import io
import logging
import os
import pathlib
import sys
import tempfile
import unittest
import ipaddress
from datetime import datetime, timedelta, timezone
from logging.config import dictConfig
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

try:
    import sqlalchemy as db
    from network_audit.repository import WINDOW_DURATION
    from network_audit.service import (
        NetworkAuditService,
        NetworkAuditServiceError,
        SQLITE_BUSY_TIMEOUT_MS,
        SQLITE_JOURNAL_MODE,
        SQLITE_JOURNAL_SIZE_LIMIT_BYTES,
    )
    from network_audit.validation import AuditObservation, AuditPeerNetwork, AuditPolicyRule, AuditQuery, AuditValidationError
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

    def test_audit_database_applies_the_configured_sqlite_pragmas(self):
        self.service.record_observation(observation())

        diagnostics = self.service.storage_diagnostics()

        self.assertEqual(SQLITE_JOURNAL_MODE, diagnostics["journal_mode"])
        self.assertEqual(SQLITE_BUSY_TIMEOUT_MS, diagnostics["busy_timeout"])
        self.assertEqual(SQLITE_JOURNAL_SIZE_LIMIT_BYTES, diagnostics["journal_size_limit"])
        # Durability outranks throughput: synchronous must stay at the SQLite FULL default.
        self.assertEqual(2, diagnostics["synchronous"])
        self.assertEqual(str(self.database_path), diagnostics["database_path"])
        self.assertEqual(1, self.service.query(query_payload())["pagination"]["total"])

    def test_pragma_statements_are_logged_once_per_database(self):
        # Services get constructed repeatedly, so the effective-settings line must appear exactly
        # once per database file or journalctl becomes useless. LOGGER is spied on rather than
        # captured with assertLogs(): dashboard.py dictConfig() runs with the default
        # disable_existing_loggers=True, so any network_audit logger created before that import is
        # muted inside the dashboard process - a real suppression that must not hide this bug.
        with tempfile.TemporaryDirectory() as temporary_directory:
            first_path = pathlib.Path(temporary_directory) / "wgdashboard_audit.db"
            with mock.patch("network_audit.service.LOGGER") as logger:
                for _ in range(2):
                    NetworkAuditService(first_path).engine.dispose()

                self.assertEqual(1, logger.info.call_count)
                rendered = logger.info.call_args.args[0] % logger.info.call_args.args[1:]
                self.assertIn(f"journal_mode={SQLITE_JOURNAL_MODE}", rendered)
                self.assertIn(f"path={first_path}", rendered)

                NetworkAuditService(pathlib.Path(temporary_directory) / "second.db").engine.dispose()

                self.assertEqual(2, logger.info.call_count)

    def test_sqlite_pragma_failures_do_not_block_audit_writes(self):
        # A filesystem that refuses WAL must degrade to the rollback journal, never lose the
        # audit path. Patched for the whole test because every fresh connection re-runs the
        # pragmas, and SQLite silently ignores anything it does not understand.
        with tempfile.TemporaryDirectory() as temporary_directory:
            database_path = pathlib.Path(temporary_directory) / "wgdashboard_audit.db"
            patcher = mock.patch(
                "network_audit.service._sqlite_pragma_statements",
                side_effect=RuntimeError("pragma configuration unavailable"),
            )
            self.addCleanup(patcher.stop)
            patcher.start()
            service = NetworkAuditService(database_path)
            self.addCleanup(service.engine.dispose)

            service.record_observation(observation())

            self.assertEqual(1, service.query(query_payload())["pagination"]["total"])
            diagnostics = service.storage_diagnostics()
            # journal_mode is the durable proof the pragma never ran: WAL lives in the file
            # header, so a database that was switched once would report "wal" forever.
            # busy_timeout cannot be used for that - pysqlite already defaults to 5000 ms,
            # which is why journal_size_limit (SQLite default -1) is asserted as well.
            self.assertEqual("delete", diagnostics["journal_mode"])
            self.assertEqual(-1, diagnostics["journal_size_limit"])

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

    def test_text_filters_are_case_insensitive_substrings_for_query_and_summary(self):
        self.service.record_observation(observation(
            configuration_name="OfficeVPN",
            peer_public_key="B" * 43 + "=",
            peer_name_snapshot="Alice-Laptop",
            tunnel_address="10.8.0.3",
            destination_address="192.168.10.25",
            protocol="udp",
            destination_port=8443,
            decision="policy_denied",
        ))

        filters = (
            ("configuration_name", "OFFICE"),
            ("peer_public_key", "BBBB"),
            ("peer_name", "LAPTOP"),
            ("tunnel_address", "10.8.0.3"),
            ("protocol", "udp"),
            ("decision", "policy_denied"),
            ("destination", "192.168.10"),
        )
        for field, value in filters:
            with self.subTest(field=field):
                payload = query_payload(**{field: value}, page_size=10)
                result = self.service.query(payload)
                self.assertEqual(1, result["pagination"]["total"])
                self.assertEqual("192.168.10.25", result["records"][0]["destination_address"])
                summary = self.service.summary(payload)
                self.assertEqual(1, summary["window_count"])

    def test_destination_partial_search_keeps_full_cidr_validation_strict(self):
        self.service.record_observation(observation(destination_address="192.168.10.25"))
        self.service.record_observation(observation(destination_address="192.168.20.25"))

        partial = self.service.query(query_payload(destination="192.168.10", page_size=10))
        self.assertEqual(1, partial["pagination"]["total"])
        self.assertEqual("192.168.10.25", partial["records"][0]["destination_address"])

        with self.assertRaises(AuditValidationError):
            self.service.query(query_payload(destination="192.168.10.0/not-a-cidr"))

    def test_destination_in_tunnel_filter_and_response_flag_use_configured_networks(self):
        self.service.record_observation(observation(destination_address="192.168.1.10"))
        self.service.record_observation(observation(destination_address="192.168.2.10"))
        tunnel_networks = (ipaddress.ip_network("192.168.1.0/24"),)

        all_query = AuditQuery(**query_payload(), tunnel_networks=tunnel_networks)
        all_result = self.service.query(all_query)
        flags = {record["destination_address"]: record["destination_in_tunnel"] for record in all_result["records"]}
        self.assertEqual({"192.168.1.10": True, "192.168.2.10": False}, flags)

        for value, expected_address in (("true", "192.168.1.10"), (False, "192.168.2.10")):
            with self.subTest(value=value):
                filtered_query = AuditQuery(
                    **query_payload(destination_in_tunnel=value), tunnel_networks=tunnel_networks,
                )
                result = self.service.query(filtered_query)
                self.assertEqual(1, result["pagination"]["total"])
                self.assertEqual(expected_address, result["records"][0]["destination_address"])
                summary = self.service.summary(filtered_query)
                self.assertEqual(1, summary["window_count"])

        unknown_networks = self.service.query(AuditQuery(**query_payload()))
        self.assertIsNone(unknown_networks["records"][0]["destination_in_tunnel"])

    def test_destination_in_tunnel_matches_peer_endpoint_allowed_networks(self):
        self.service.record_observation(observation(
            tunnel_address="10.253.157.49",
            destination_address="192.168.0.175",
        ))
        self.service.record_observation(observation(
            tunnel_address="10.253.157.49",
            destination_address="192.168.50.175",
            observed_at=BASE_TIME + timedelta(minutes=5),
        ))
        peer_networks = (
            AuditPeerNetwork(
                configuration_name="wg0",
                peer_public_key=PUBLIC_KEY,
                tunnel_address="10.253.157.49",
                networks=(ipaddress.ip_network("192.168.0.0/24"),),
            ),
        )
        query = AuditQuery(
            **query_payload(),
            peer_networks=peer_networks,
        )
        flags = {
            record["destination_address"]: record["destination_in_tunnel"]
            for record in self.service.query(query)["records"]
        }
        self.assertEqual({"192.168.0.175": True, "192.168.50.175": False}, flags)

    def test_default_route_is_not_classified_as_a_tunnel_network(self):
        self.service.record_observation(observation(
            tunnel_address="10.253.157.2",
            destination_address="106.55.88.125",
        ))
        query = AuditQuery(
            **query_payload(),
            peer_networks=(),
        )
        result = self.service.query(query)
        self.assertEqual(1, result["pagination"]["total"])
        self.assertFalse(result["records"][0]["destination_in_tunnel"])
        filtered = self.service.query(AuditQuery(
            **query_payload(destination_in_tunnel="false"),
            peer_networks=(),
        ))
        self.assertEqual(1, filtered["pagination"]["total"])

    def test_policy_target_match_uses_peer_policy_not_tunnel_network(self):
        self.service.record_observation(observation(
            tunnel_address="10.253.157.49",
            destination_address="192.168.0.175",
            destination_port=5435,
            decision="policy_allowed",
        ))
        self.service.record_observation(observation(
            tunnel_address="10.253.157.49",
            destination_address="192.168.0.175",
            destination_port=5436,
            observed_at=BASE_TIME + timedelta(minutes=5),
        ))

        policy_rules = (
            AuditPolicyRule(
                configuration_name="wg0",
                peer_public_key=PUBLIC_KEY,
                tunnel_address="10.253.157.49",
                destination="192.168.0.175/32",
                protocol="tcp",
                port_from=5435,
                port_to=5435,
            ),
        )
        query = AuditQuery(
            **query_payload(destination_in_policy="all"),
            policy_rules=policy_rules,
        )
        result = self.service.query(query)
        matches = {
            record["destination_port"]: record["destination_in_policy"]
            for record in result["records"]
        }
        self.assertEqual({5435: True, 5436: False}, matches)
        self.assertEqual(1, self.service.query(AuditQuery(
            **query_payload(destination_in_policy="true"), policy_rules=policy_rules,
        ))["pagination"]["total"])
        self.assertEqual(1, self.service.summary(AuditQuery(
            **query_payload(destination_in_policy="true"), policy_rules=policy_rules,
        ))["window_count"])

    def test_text_filters_escape_sql_wildcards(self):
        self.service.record_observation(observation(peer_name_snapshot="alpha_beta"))
        self.service.record_observation(observation(
            peer_name_snapshot="alphaXbeta", destination_address="192.168.1.11",
        ))
        self.service.record_observation(observation(
            peer_name_snapshot="100%device", destination_address="192.168.1.12",
        ))
        self.service.record_observation(observation(
            peer_name_snapshot="100Xdevice", destination_address="192.168.1.13",
        ))

        for value, expected in (("alpha_beta", "alpha_beta"), ("100%", "100%device")):
            with self.subTest(value=value):
                result = self.service.query(query_payload(peer_name=value, page_size=10))

                self.assertEqual(1, result["pagination"]["total"])
                self.assertEqual(expected, result["records"][0]["peer_name_snapshot"])

    def test_fuzzy_filters_accept_arbitrary_text_and_reject_wrong_enums(self):
        self.service.record_observation(observation(
            configuration_name="vpn-01",
            peer_public_key=PUBLIC_KEY,
            peer_name_snapshot="phone-full",
            tunnel_address="10.253.157.2",
            destination_address="192.168.0.134",
            destination_port=8096,
            decision="policy_allowed",
        ))
        self.service.record_observation(observation(
            configuration_name="other",
            destination_address="192.168.0.117",
        ))

        for field, value in (
            ("configuration_name", "vpn"),
            ("peer_name", "PHONE"),
            ("tunnel_address", "157.2"),
            ("destination", "192.168.0.134"),
        ):
            with self.subTest(field=field):
                result = self.service.query(query_payload(**{field: value}, page_size=10))
                self.assertEqual(1, result["pagination"]["total"])
                self.assertEqual("192.168.0.134", result["records"][0]["destination_address"])
                summary = self.service.summary(query_payload(**{field: value}))
                self.assertEqual(1, summary["window_count"])

        with self.subTest("peer_public_key fragment"):
            key_fragment = PUBLIC_KEY[:-2]
            result = self.service.query(query_payload(
                peer_public_key=key_fragment, configuration_name="vpn", page_size=10,
            ))
            self.assertEqual(1, result["pagination"]["total"])
            self.assertEqual("192.168.0.134", result["records"][0]["destination_address"])

        with self.subTest("protocol case-insensitive enum"):
            result = self.service.query(query_payload(protocol="TCP", page_size=10))
            self.assertEqual(2, result["pagination"]["total"])

        with self.assertRaises(AuditValidationError) as context:
            self.service.query(query_payload(protocol="sctp"))
        self.assertIn("tcp, udp, icmp", str(context.exception))
        with self.assertRaises(AuditValidationError) as context:
            self.service.query(query_payload(protocol="tcpudp"))
        self.assertIn("tcp, udp, icmp", str(context.exception))
        with self.assertRaises(AuditValidationError) as context:
            self.service.query(query_payload(decision="denied"))
        self.assertIn("forward_observed, policy_allowed, policy_denied", str(context.exception))
        with self.assertRaises(AuditValidationError) as context:
            self.service.query(query_payload(decision="policy"))
        self.assertIn("forward_observed, policy_allowed, policy_denied", str(context.exception))
        with self.assertRaises(AuditValidationError) as context:
            self.service.query(query_payload(destination="foo/24"))
        self.assertIn("CIDR", str(context.exception))

        self.assertTrue(isinstance(self.service.query(query_payload(destination="192.168.1.0/24"))["records"], list))

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
        with self.service.engine.begin() as connection:
            connection.execute(self.service.repository.activity_windows.delete())
            connection.execute(self.service.repository.daily_aggregates.delete())
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

    def test_api_uses_peer_endpoint_allowed_networks_for_tunnel_filter_and_flag(self):
        self.service.record_observation(observation(
            tunnel_address="10.253.157.49", destination_address="192.168.0.175",
        ))
        self.service.record_observation(observation(
            tunnel_address="10.253.157.49", destination_address="192.168.50.175",
        ))
        original_configurations = self.dashboard.WireguardConfigurations
        self.addCleanup(setattr, self.dashboard, "WireguardConfigurations", original_configurations)
        self.dashboard.WireguardConfigurations = {
            "wg0": type("Configuration", (), {
                "Name": "wg0",
                "Peers": [type("Peer", (), {
                    "id": PUBLIC_KEY,
                    "allowed_ip": "10.253.157.49/32",
                    "endpoint_allowed_ip": "192.168.0.0/24,192.168.10.0/24,192.168.30.0/24,10.253.157.0/24",
                })()],
            })(),
        }

        response = self._admin_client().post(
            "/api/networkAudit/query",
            json=query_payload(destination_in_tunnel="true"),
        )
        self.assertEqual(200, response.status_code)
        data = response.get_json()["data"]
        self.assertEqual(1, data["pagination"]["total"])
        self.assertEqual("192.168.0.175", data["records"][0]["destination_address"])
        self.assertTrue(data["records"][0]["destination_in_tunnel"])

        summary = self._admin_client().get(
            "/api/networkAudit/summary", query_string=query_payload(destination_in_tunnel="true"),
        )
        self.assertEqual(200, summary.status_code)
        self.assertEqual(1, summary.get_json()["data"]["window_count"])

    def test_api_classifies_a_flow_against_the_bound_network_policy(self):
        self.service.record_observation(observation(
            tunnel_address="10.253.157.49",
            destination_address="192.168.0.175",
            destination_port=5435,
            decision="policy_allowed",
        ))
        policy = type("Policy", (), {
            "configuration_name": "wg0",
            "peer_public_key": PUBLIC_KEY,
            "tunnel_address": "10.253.157.49",
            "rules": (type("Rule", (), {
                "destination": "192.168.0.175/32",
                "protocol": "tcp",
                "port_from": 5435,
                "port_to": 5435,
            })(),),
        })()
        original_records = self.dashboard.NetworkPolicyManager.repository.current_records
        self.addCleanup(
            setattr,
            self.dashboard.NetworkPolicyManager.repository,
            "current_records",
            original_records,
        )
        self.dashboard.NetworkPolicyManager.repository.current_records = lambda: [{
            "policy": policy,
            "managed": True,
            "binding_status": "bound",
            "last_apply_status": "applied",
        }]

        response = self._admin_client().post(
            "/api/networkAudit/query",
            json=query_payload(destination_in_policy="true"),
        )
        self.assertEqual(200, response.status_code)
        data = response.get_json()["data"]
        self.assertEqual(1, data["pagination"]["total"])
        self.assertTrue(data["records"][0]["destination_in_policy"])



class NetworkAuditRuntimeLoggingTest(unittest.TestCase):
    """The standalone units must be able to prove their own storage settings from the journal.

    These cases capture a real stream instead of counting calls on a mocked logger. Production
    shipped that failure mode on 2026-09-28: the connect-event pragmas *were* applied
    (``journal_size_limit=67108864`` read back from the live engine) while
    ``journalctl -u wgd-network-audit-collector`` showed nothing, because no handler existed and
    the logging last-resort handler only emits WARNING+. A call-count assertion cannot see that.
    """

    def setUp(self):
        from network_audit import runtime_logging

        self.module = runtime_logging
        self.logger = logging.getLogger(runtime_logging.AUDIT_LOGGER_NAME)
        self.saved = (self.logger.level, self.logger.propagate, list(self.logger.handlers))
        self.stream = io.StringIO()

    def tearDown(self):
        for handler in list(self.logger.handlers):
            self.logger.removeHandler(handler)
        self.logger.setLevel(self.saved[0])
        self.logger.propagate = self.saved[1]
        self.logger.handlers = self.saved[2]

    def configure(self, **kwargs):
        return self.module.configure_runtime_logging(stream=self.stream, **kwargs)

    def render(self):
        for handler in self.logger.handlers:
            handler.flush()
        return self.stream.getvalue()

    def test_info_records_become_observable(self):
        self.configure()

        logging.getLogger("network_audit.service").info(
            "network audit sqlite storage: journal_mode=%s", "wal"
        )

        rendered = self.render()
        self.assertIn("journal_mode=wal", rendered)
        self.assertIn("INFO", rendered)
        self.assertIn("network_audit.service", rendered)

    def test_records_survive_a_dashboard_style_dictconfig(self):
        # Faithful reproduction of the real mechanism, not of a test-order accident: dashboard.py
        # installs a dictConfig with disable_existing_loggers left at its True default, which marks
        # *every* logger that already exists as disabled - children included. A version of this fix
        # that only cleared the "network_audit" root name passed the isolated run and still lost the
        # line, because Logger.handle() bails on the child's own flag before the hierarchy is asked.
        manager = logging.Logger.manager
        child = logging.getLogger("network_audit.service")
        root = logging.getLogger()
        saved_disabled = {
            name: value.disabled
            for name, value in manager.loggerDict.items()
            if isinstance(value, logging.Logger)
        }
        saved_root_level, saved_root_handlers = root.level, list(root.handlers)
        try:
            dictConfig({"version": 1, "root": {"level": "INFO"}})
            self.assertTrue(child.disabled, "precondition: dictConfig must disable the child logger")

            self.configure()
            child.info("network audit sqlite storage: journal_mode=%s", "wal")

            self.assertIn("journal_mode=wal", self.render())
        finally:
            for name, disabled in saved_disabled.items():
                value = manager.loggerDict.get(name)
                if isinstance(value, logging.Logger):
                    value.disabled = disabled
            root.setLevel(saved_root_level)
            root.handlers = saved_root_handlers

    def test_sweep_is_scoped_to_the_audit_subtree(self):
        # Un-disabling the whole process would resurrect every third-party logger that
        # disable_existing_loggers intentionally silenced. Only our subtree may be touched.
        third_party = logging.getLogger("sqlalchemy.engine")
        third_party.disabled = True
        try:
            self.configure()
            self.assertTrue(third_party.disabled)
            self.assertGreater(self.module.enable_audit_logging(), 0)
        finally:
            third_party.disabled = False

    def test_third_party_info_stays_quiet(self):
        # Promoting the audit subtree must not turn on SQL echoing for the whole process.
        self.configure()

        logging.getLogger("sqlalchemy.engine").info("SELECT count(*) FROM AuditEvents")

        self.assertEqual("", self.render())

    def test_configure_is_idempotent(self):
        first = self.configure()
        second = self.configure()

        logging.getLogger("network_audit.service").info("one line")

        self.assertIs(first, second)
        self.assertEqual(1, len(self.logger.handlers))
        self.assertEqual(1, self.render().count("\n"))

    def test_records_are_not_emitted_twice_through_root(self):
        # propagate is off for a reason: a root handler must not turn every audit line into two.
        root = logging.getLogger()
        saved_root_level = root.level
        external = io.StringIO()
        handler = logging.StreamHandler(external)
        root.addHandler(handler)
        root.setLevel(logging.DEBUG)
        try:
            self.configure()
            logging.getLogger("network_audit.collector").info("exactly once")
        finally:
            root.removeHandler(handler)
            root.setLevel(saved_root_level)

        self.assertEqual(1, self.render().count("exactly once"))
        self.assertEqual("", external.getvalue())

    def test_environment_level_is_honoured(self):
        with mock.patch.dict(os.environ, {self.module.LOG_LEVEL_ENVIRONMENT_VARIABLE: "WARNING"}):
            self.configure()
            logging.getLogger("network_audit.service").info("hidden info")
            logging.getLogger("network_audit.service").warning("visible warning")

        rendered = self.render()
        self.assertNotIn("hidden info", rendered)
        self.assertIn("visible warning", rendered)

    def test_unusable_level_falls_back_instead_of_raising(self):
        # These processes are the only writer of the audit trail; a bad env value must not
        # be able to stop collection.
        with mock.patch.dict(os.environ, {self.module.LOG_LEVEL_ENVIRONMENT_VARIABLE: "very-loud"}):
            self.configure()
            logging.getLogger("network_audit.service").info("still observable")

        self.assertIn("still observable", self.render())

    def test_collector_entrypoint_configures_logging(self):
        from network_audit import collector

        calls = []
        with mock.patch.object(
            collector, "configure_runtime_logging",
            side_effect=lambda **kw: calls.append("logging") or {"configured": True},
        ), mock.patch.object(collector, "run_collector", side_effect=lambda **kw: calls.append("run")):
            with mock.patch.object(sys, "argv", ["collector"]):
                collector.main()

        self.assertEqual(["logging", "run"], calls)

    def test_alerts_entrypoint_configures_logging_before_the_service(self):
        from network_audit import alerts

        calls = []

        def note(name):
            def _side_effect(*args, **kwargs):
                calls.append(name)
                return mock.MagicMock()
            return _side_effect

        with mock.patch.object(alerts, "configure_runtime_logging", side_effect=note("logging")), \
             mock.patch.object(alerts, "NetworkAuditService", side_effect=note("service")), \
             mock.patch.object(alerts, "NetworkAuditAlertRunner", side_effect=note("runner")), \
             mock.patch.object(alerts, "signal"):
            with mock.patch.object(sys, "argv", ["alerts", "--once"]):
                alerts.main()

        self.assertEqual(["logging", "service", "runner"], calls)


if __name__ == "__main__":
    unittest.main()
