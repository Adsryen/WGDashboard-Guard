import pathlib
import sys
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from gunicorn_tls import get_tls_files


class GunicornTlsTest(unittest.TestCase):
    def test_tls_is_disabled_when_both_files_are_missing(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            self.assertEqual({}, get_tls_files(temporary_directory))

    def test_tls_rejects_a_partial_certificate_pair(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            ssl_directory = pathlib.Path(temporary_directory) / "ssl"
            ssl_directory.mkdir()
            (ssl_directory / "dashboard.crt").write_text("certificate", encoding="utf-8")

            with self.assertRaises(RuntimeError):
                get_tls_files(temporary_directory)

    def test_tls_returns_both_certificate_paths_when_configured(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            ssl_directory = pathlib.Path(temporary_directory) / "ssl"
            ssl_directory.mkdir()
            certificate = ssl_directory / "dashboard.crt"
            private_key = ssl_directory / "dashboard.key"
            certificate.write_text("certificate", encoding="utf-8")
            private_key.write_text("private key", encoding="utf-8")

            self.assertEqual(
                {"certfile": str(certificate), "keyfile": str(private_key)},
                get_tls_files(temporary_directory),
            )


if __name__ == "__main__":
    unittest.main()
