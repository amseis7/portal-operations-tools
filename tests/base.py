import os
import re
import shutil
import tempfile
import unittest

# Must be set before `app`/`config` is imported — Config raises RuntimeError
# at import time if any of these are missing. Values are synthetic and only
# ever used inside this disposable, in-memory test database.
os.environ.setdefault("SECRET_KEY", "test-only-secret-key")
os.environ.setdefault("SECRET_KEY_DB", "vQw_68XQ6A1hb0wD6M3lp1yu4r6FOf34PRLba-gu9N0=")
os.environ.setdefault("CREDENTIAL_MANAGER_KEY", "test-only-credential-manager-key")
os.environ.setdefault("VAULT_KEY", "vQw_68XQ6A1hb0wD6M3lp1yu4r6FOf34PRLba-gu9N0=")

from app import create_app
from app.extensions import db
from app.models.user import User, UserTool

SYNTHETIC_PASSWORD = "Synthetic-Pass-123!"


class TestConfig:
    SECRET_KEY = os.environ["SECRET_KEY"]
    SECRET_KEY_DB = os.environ["SECRET_KEY_DB"].encode()
    CREDENTIAL_MANAGER_KEY = os.environ["CREDENTIAL_MANAGER_KEY"]
    VAULT_KEY = os.environ["VAULT_KEY"]
    VAULT_KDBX_PATH = ""
    VAULT_KDBX_PASSWORD = ""
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SCHEDULER_API_ENABLED = False
    TESTING = True
    WTF_CSRF_ENABLED = True
    RATELIMIT_ENABLED = False  # /auth/login's 5-per-minute limit is process-global and would fail unrelated tests that log in more than 2-3 times in one run

    # --- Knowledge Base attachments ---
    # KB_ATTACHMENTS_DIR is overwritten in setUpClass to point at the
    # isolated instance_path temp dir, not the real project path.
    KB_ATTACHMENTS_DIR = "kb_attachments"
    KB_ATTACHMENT_MAX_SIZE_BYTES = 10 * 1024 * 1024
    KB_ATTACHMENT_MAX_TOTAL_BYTES = 50 * 1024 * 1024
    KB_ATTACHMENT_ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp", "pdf", "docx", "xlsx", "xls", "csv", "txt"}
    KB_ATTACHMENT_IMAGE_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
    KB_ATTACHMENT_DRAFT_TTL_HOURS = 24
    KB_SCANNER = "null"


class PortalTestCase(unittest.TestCase):
    """Base test case: one real Flask app per test class, one clean
    in-memory schema per test method. Uses db.create_all() because this is
    a disposable test database, not schema evolution (ADR-002 governs real
    deployments, not throwaway test fixtures)."""

    @classmethod
    def setUpClass(cls):
        # Creating the app is the expensive part (real APScheduler startup) —
        # do it once per test class.
        # instance_path is an isolated temp directory, never the project's
        # real instance/ — some routes (e.g. Vault KeePass import) write
        # transient files under current_app.instance_path, and tests must
        # never touch real runtime data to verify that behavior.
        cls._instance_dir = tempfile.mkdtemp(prefix="portal-test-instance-")
        TestConfig.KB_ATTACHMENTS_DIR = os.path.join(cls._instance_dir, "kb_attachments")
        cls.app = create_app(config_class=TestConfig, instance_path=cls._instance_dir)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls._instance_dir, ignore_errors=True)

    def setUp(self):
        # The app context is pushed/popped per TEST METHOD, not per class:
        # Flask-Login's current_user is cached on flask.g, which lives for
        # the lifetime of the app context. A context shared across tests
        # leaks the logged-in user from one test's client into the next
        # test's client, even though they are different FlaskClient
        # instances with no shared cookies.
        self.app_context = self.app.app_context()
        self.app_context.push()
        db.create_all()
        self.client = self.app.test_client()
        # app/__init__.py's check_setup_needed before_request hook redirects
        # every request (except auth.setup/static) to /auth/setup whenever no
        # admin exists yet. A bootstrap admin keeps that hook out of every
        # other test's way regardless of which users the test itself creates.
        self.make_user("_bootstrap_admin", is_admin=True)

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def make_user(self, username, is_admin=False, tools=None):
        user = User(
            username=username,
            is_admin=is_admin,
            must_change_password=False,
            nombre_completo="Usuario de Prueba",
        )
        user.set_password(SYNTHETIC_PASSWORD)
        db.session.add(user)
        db.session.flush()
        for tool_name in (tools or []):
            db.session.add(UserTool(user_id=user.id, tool_name=tool_name))
        db.session.commit()
        return user

    def extract_csrf(self, html: str) -> str:
        match = re.search(r'name="csrf_token" value="([^"]+)"', html)
        assert match, "csrf_token not found in rendered page"
        return match.group(1)

    def login(self, username, password=SYNTHETIC_PASSWORD):
        page = self.client.get("/auth/login")
        if page.status_code == 302:
            # Already authenticated as a different user in this test method
            # (/auth/login redirects straight to /dashboard when logged in) —
            # log out first so the login form is reachable again.
            dashboard = self.client.get(page.headers["Location"])
            token = self.extract_csrf(dashboard.get_data(as_text=True))
            self.client.post("/auth/logout", data={"csrf_token": token})
            page = self.client.get("/auth/login")
        token = self.extract_csrf(page.get_data(as_text=True))
        return self.client.post(
            "/auth/login",
            data={"username": username, "password": password, "csrf_token": token},
            follow_redirects=True,
        )
