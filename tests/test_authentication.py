import importlib
import os
import pathlib
import sys
import tempfile
import unittest

import pyotp


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))


class DashboardAuthenticationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary_directory = tempfile.TemporaryDirectory()
        cls.previous_directory = os.getcwd()
        cls.previous_configuration_path = os.environ.get("CONFIGURATION_PATH")
        from modules.DashboardConfig import DashboardConfig as DashboardConfigClass
        from modules.DashboardOIDC import DashboardOIDC
        cls.dashboard_config_class = DashboardConfigClass
        cls.previous_dashboard_config_path = DashboardConfigClass.ConfigurationPath
        cls.previous_dashboard_config_file = DashboardConfigClass.ConfigurationFilePath
        cls.dashboard_oidc_class = DashboardOIDC
        cls.previous_dashboard_oidc_path = DashboardOIDC.ConfigurationPath
        cls.previous_dashboard_oidc_file = DashboardOIDC.ConfigurationFilePath
        cls.wireguard_directory = pathlib.Path(cls.temporary_directory.name) / "wireguard"
        cls.wireguard_directory.mkdir()
        pathlib.Path(cls.temporary_directory.name, "wg-dashboard.ini").write_text(
            f"[Server]\nwg_conf_path = {cls.wireguard_directory}\n",
            encoding="utf-8",
        )
        pathlib.Path(cls.temporary_directory.name, "static").symlink_to(
            ROOT / "src" / "static",
            target_is_directory=True,
        )
        os.chdir(cls.temporary_directory.name)
        os.environ["CONFIGURATION_PATH"] = cls.temporary_directory.name
        sys.modules.pop("dashboard", None)
        cls.dashboard = importlib.import_module("dashboard")
        cls.dashboard.app.config.update(TESTING=True)

    @classmethod
    def tearDownClass(cls):
        cls.dashboard.DashboardConfig.engine.dispose()
        sys.modules.pop("dashboard", None)
        os.chdir(cls.previous_directory)
        if cls.previous_configuration_path is None:
            os.environ.pop("CONFIGURATION_PATH", None)
        else:
            os.environ["CONFIGURATION_PATH"] = cls.previous_configuration_path
        cls.dashboard_config_class.ConfigurationPath = cls.previous_dashboard_config_path
        cls.dashboard_config_class.ConfigurationFilePath = cls.previous_dashboard_config_file
        cls.dashboard_oidc_class.ConfigurationPath = cls.previous_dashboard_oidc_path
        cls.dashboard_oidc_class.ConfigurationFilePath = cls.previous_dashboard_oidc_file
        cls.temporary_directory.cleanup()

    def setUp(self):
        self.client = self.dashboard.app.test_client()
        self.dashboard.DashboardConfig.SetConfig("Account", "enable_totp", True)
        self.dashboard.DashboardConfig.SetConfig("Server", "session_lifetime_hours", 168)

    def tearDown(self):
        self.dashboard.DashboardConfig.SetConfig("Account", "enable_totp", False)

    def test_session_secret_is_persisted_and_hidden_from_configuration(self):
        secret = self.dashboard.DashboardConfig.GetConfig("Server", "session_secret")[1]
        reloaded = type(self.dashboard.DashboardConfig)()
        try:
            self.assertTrue(secret)
            self.assertEqual(secret, reloaded.GetConfig("Server", "session_secret")[1])
            self.assertNotIn("session_secret", reloaded.toJson()["Server"])
            self.assertEqual(secret, self.dashboard.app.secret_key)
        finally:
            reloaded.engine.dispose()

    def test_session_lifetime_accepts_hours_in_a_safe_range(self):
        valid, message = self.dashboard.DashboardConfig.ValidateConfig(
            "Server", "session_lifetime_hours", 720,
        )
        self.assertTrue(valid, message)

        invalid, message = self.dashboard.DashboardConfig.ValidateConfig(
            "Server", "session_lifetime_hours", 0,
        )
        self.assertFalse(invalid)
        self.assertIn("between 1 and 8760", message)

    def test_session_lifetime_update_reconfigures_flask_sessions(self):
        with self.client.session_transaction() as flask_session:
            flask_session["username"] = "admin"
            flask_session["role"] = "admin"

        response = self.client.post(
            "/api/updateDashboardConfigurationItem",
            json={"section": "Server", "key": "session_lifetime_hours", "value": 24},
        )

        self.assertEqual(200, response.status_code)
        self.assertEqual(24 * 60 * 60, self.dashboard.app.permanent_session_lifetime.total_seconds())

    def test_untrusted_login_uses_browser_session_cookie(self):
        response = self._authenticate(trust_device=False)
        auth_cookie = self._set_cookie(response, "authToken")

        self.assertNotIn("Max-Age=", auth_cookie)
        self.assertNotIn("Expires=", auth_cookie)
        with self.client.session_transaction() as flask_session:
            self.assertFalse(flask_session.permanent)

    def test_validation_accepts_signed_session_when_auth_token_cookie_is_missing(self):
        self._authenticate(trust_device=True)
        self.client.delete_cookie("authToken")

        response = self.client.get("/api/validateAuthentication")

        self.assertTrue(response.json["status"])

    def test_trusted_login_uses_configured_persistent_cookie(self):
        self.dashboard.DashboardConfig.SetConfig("Server", "session_lifetime_hours", 24)

        response = self._authenticate(trust_device=True)
        auth_cookie = self._set_cookie(response, "authToken")

        self.assertIn("Max-Age=86400", auth_cookie)
        self.assertIn("HttpOnly", auth_cookie)
        self.assertIn("SameSite=Lax", auth_cookie)
        with self.client.session_transaction() as flask_session:
            self.assertTrue(flask_session.permanent)

    def test_login_without_totp_preserves_persistent_session_behavior(self):
        self.dashboard.DashboardConfig.SetConfig("Account", "enable_totp", False)

        response = self.client.post(
            "/api/authenticate",
            json={"username": "admin", "password": "admin"},
        )

        auth_cookie = self._set_cookie(response, "authToken")
        self.assertIn("Max-Age=604800", auth_cookie)
        with self.client.session_transaction() as flask_session:
            self.assertTrue(flask_session.permanent)

    def _authenticate(self, trust_device):
        totp_key = self.dashboard.DashboardConfig.GetConfig("Account", "totp_key")[1]
        return self.client.post(
            "/api/authenticate",
            json={
                "username": "admin",
                "password": "admin",
                "totp": pyotp.TOTP(totp_key).now(),
                "trust_device": trust_device,
            },
        )

    @staticmethod
    def _set_cookie(response, name):
        prefix = f"{name}="
        return next(
            header for header in response.headers.getlist("Set-Cookie")
            if header.startswith(prefix)
        )


if __name__ == "__main__":
    unittest.main()
