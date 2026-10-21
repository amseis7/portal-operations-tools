"""A-04: session cookie had no Secure/HttpOnly/SameSite configured
(Flask defaults: Secure=False, SameSite=None). Verifies the production
Config values directly, and that an authenticated response's real
Set-Cookie header carries Secure/HttpOnly/SameSite=Lax end-to-end.

Remember-cookie (Flask-Login's `remember=True`) is not used anywhere in
this app (`login_user(user)` is called with no `remember` kwarg, confirmed
by inspection of app/auth/routes.py) -- so no REMEMBER_COOKIE_* setting is
added here; there is nothing to configure or test.
"""
import os
import tempfile
import unittest

os.environ.setdefault("SECRET_KEY", "test-only-secret-key")
os.environ.setdefault("SECRET_KEY_DB", "vQw_68XQ6A1hb0wD6M3lp1yu4r6FOf34PRLba-gu9N0=")
os.environ.setdefault("CREDENTIAL_MANAGER_KEY", "test-only-credential-manager-key")
os.environ.setdefault("VAULT_KEY", "vQw_68XQ6A1hb0wD6M3lp1yu4r6FOf34PRLba-gu9N0=")

from config import Config, DevelopmentConfig
from app import create_app
from app.extensions import db
from tests.base import PortalTestCase, TestConfig, SYNTHETIC_PASSWORD


class TestProductionConfigCookieFlags(unittest.TestCase):
    """Pure config-class assertions -- no app needed."""

    def test_session_cookie_secure_is_true(self):
        self.assertIs(Config.SESSION_COOKIE_SECURE, True)

    def test_session_cookie_httponly_is_true(self):
        self.assertIs(Config.SESSION_COOKIE_HTTPONLY, True)

    def test_session_cookie_samesite_is_lax(self):
        self.assertEqual(Config.SESSION_COOKIE_SAMESITE, "Lax")

    def test_development_config_relaxes_only_secure_for_plain_http(self):
        """run.py's dev server has no TLS -- Secure must be off there, but
        HttpOnly/SameSite don't depend on TLS and stay inherited."""
        self.assertIs(DevelopmentConfig.SESSION_COOKIE_SECURE, False)
        self.assertIs(DevelopmentConfig.SESSION_COOKIE_HTTPONLY, True)
        self.assertEqual(DevelopmentConfig.SESSION_COOKIE_SAMESITE, "Lax")


class _SecureCookieTestConfig(TestConfig):
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"


class TestLoginSetCookieHeader(PortalTestCase):
    """End-to-end: an authenticated login response's real Set-Cookie header
    must carry the hardened flags. Uses its own app (SESSION_COOKIE_SECURE
    differs from the shared suite's TestConfig) -- isolated from every
    other test file, no risk of affecting unrelated tests.
    """

    @classmethod
    def setUpClass(cls):
        cls._instance_dir = tempfile.mkdtemp(prefix="portal-test-instance-cookie-")
        _SecureCookieTestConfig.KB_ATTACHMENTS_DIR = os.path.join(cls._instance_dir, "kb_attachments")
        cls.app = create_app(config_class=_SecureCookieTestConfig, instance_path=cls._instance_dir)

    def test_login_response_set_cookie_has_secure_httponly_samesite(self):
        self.make_user("cookie_user", is_admin=False)
        page = self.client.get("/auth/login")
        token = self.extract_csrf(page.get_data(as_text=True))

        response = self.client.post(
            "/auth/login",
            data={"username": "cookie_user", "password": SYNTHETIC_PASSWORD, "csrf_token": token},
            follow_redirects=False,
        )

        set_cookie_headers = response.headers.get_all("Set-Cookie")
        session_cookie = next((h for h in set_cookie_headers if h.startswith("session=")), None)
        self.assertIsNotNone(session_cookie, f"no session cookie in: {set_cookie_headers}")
        self.assertIn("Secure", session_cookie)
        self.assertIn("HttpOnly", session_cookie)
        self.assertIn("SameSite=Lax", session_cookie)


if __name__ == "__main__":
    unittest.main()
