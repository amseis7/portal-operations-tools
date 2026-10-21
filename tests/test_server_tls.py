"""server.py must never fall back to plain HTTP. Before this fix, missing
cert/key files silently set PORT=8080 and started a WSGIServer with no
ssl_adapter. Now resolver_certificados_tls() aborts the process (sys.exit)
for any of the 3 missing-file combinations, and construir_servidor() always
sets ssl_adapter — there is no code path left that builds an HTTP listener.

server.py is a script with module-level side effects (it calls
app.create_app() at import time), so `app.create_app` is mocked out BEFORE
importing it here — this test never creates a real Flask app, never starts
a real scheduler, and never opens a real socket.
"""
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

os.environ.setdefault("SECRET_KEY", "test-only-secret-key")
os.environ.setdefault("SECRET_KEY_DB", "vQw_68XQ6A1hb0wD6M3lp1yu4r6FOf34PRLba-gu9N0=")
os.environ.setdefault("CREDENTIAL_MANAGER_KEY", "test-only-credential-manager-key")
os.environ.setdefault("VAULT_KEY", "vQw_68XQ6A1hb0wD6M3lp1yu4r6FOf34PRLba-gu9N0=")


def _import_server_with_mocked_app():
    sys.modules.pop("server", None)
    with patch("app.create_app", return_value=MagicMock()):
        import server  # noqa: F401 -- import side effect is the point
    return server


class TestResolverCertificadosTLS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = _import_server_with_mocked_app()

    def setUp(self):
        # _diag() writes to BASE_DIR/startup.log; never let a test touch
        # the real repo file.
        self._diag_patch = patch.object(self.server, "_diag")
        self._diag_patch.start()

    def tearDown(self):
        self._diag_patch.stop()

    def test_both_present_returns_paths_without_exiting(self):
        with patch("os.path.exists", return_value=True):
            cert_path, key_path = self.server.resolver_certificados_tls()
        self.assertTrue(cert_path.endswith("cert.pem"))
        self.assertTrue(key_path.endswith("key.pem"))

    def test_both_missing_aborts(self):
        with patch("os.path.exists", return_value=False):
            with self.assertRaises(SystemExit):
                self.server.resolver_certificados_tls()

    def test_cert_only_aborts(self):
        cert_path = os.path.join(self.server.BASE_DIR, self.server.CERT_FILE)

        def fake_exists(path):
            return path == cert_path

        with patch("os.path.exists", side_effect=fake_exists):
            with self.assertRaises(SystemExit):
                self.server.resolver_certificados_tls()

    def test_key_only_aborts(self):
        key_path = os.path.join(self.server.BASE_DIR, self.server.KEY_FILE)

        def fake_exists(path):
            return path == key_path

        with patch("os.path.exists", side_effect=fake_exists):
            with self.assertRaises(SystemExit):
                self.server.resolver_certificados_tls()


class TestConstruirServidor(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = _import_server_with_mocked_app()

    def test_server_always_has_ssl_adapter_configured(self):
        """No HTTP-fallback listener is ever constructed: ssl_adapter is set
        unconditionally, with no branch that skips it."""
        fake_adapter = MagicMock()
        with patch.object(self.server, "WSGIServer", return_value=MagicMock()) as mock_wsgi, \
             patch.object(self.server, "BuiltinSSLAdapter", return_value=fake_adapter) as mock_adapter:
            built = self.server.construir_servidor("/fake/cert.pem", "/fake/key.pem")

        mock_wsgi.assert_called_once()
        mock_adapter.assert_called_once_with("/fake/cert.pem", "/fake/key.pem")
        self.assertIs(built.ssl_adapter, fake_adapter)

    def test_fallback_http_port_and_flag_no_longer_exist_in_source(self):
        """Regression guard: the removed `usar_ssl` branch and its
        `PORT = 8080` HTTP fallback must not reappear."""
        with open(os.path.join(os.path.dirname(os.path.dirname(__file__)), "server.py"), encoding="utf-8") as f:
            source = f.read()
        self.assertNotIn("usar_ssl", source)
        self.assertNotIn("8080", source)


if __name__ == "__main__":
    unittest.main()
