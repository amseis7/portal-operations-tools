import io
import os
import shutil
import tempfile
import unittest

from app import create_app
from app.knowledge_base.scanning import (
    DevAllowScanner,
    NullScanner,
    ScanStatus,
    get_scanner,
    validate_scanner_config,
)
from tests.base import PortalTestCase, TestConfig


class TestScannerClasses(unittest.TestCase):
    def test_null_scanner_returns_not_scanned(self):
        result = NullScanner().scan_file("irrelevant-path")
        self.assertEqual(result.status, ScanStatus.NOT_SCANNED)

    def test_dev_allow_scanner_returns_clean_with_unambiguous_detail(self):
        result = DevAllowScanner().scan_file("irrelevant-path")
        self.assertEqual(result.status, ScanStatus.CLEAN)
        self.assertIsNotNone(result.detail)
        self.assertIn("NOT", result.detail)


class _StartupConfig(TestConfig):
    """Base for startup-validation tests — each test subclasses this to
    set only the KB_SCANNER*/flags under test, inheriting everything else
    (secrets, in-memory DB, etc.) TestConfig already provides."""


class TestValidateScannerConfigAtStartup(unittest.TestCase):
    """Exercises validate_scanner_config() through real create_app() calls,
    not a fake app stand-in — this is config-wiring behavior, and the only
    thing that proves the wiring is correct is create_app() itself."""

    def _create_app(self, config_class):
        # Each successful create_app() here starts a real APScheduler with
        # live background-job threads (unlike PortalTestCase's single
        # shared cls.app). Shutting it down immediately — before the
        # instance_dir it was pointed at gets removed — avoids leaking 4
        # extra scheduler threads per test run, each referencing a
        # directory that no longer exists.
        instance_dir = tempfile.mkdtemp(prefix="portal-test-instance-scanvalidate-")
        # Without this, create_app()'s os.makedirs(KB_ATTACHMENTS_DIR) would
        # use TestConfig's bare "kb_attachments" (or whatever stale tempdir
        # another test class's shared TestConfig last pointed it at),
        # creating/leaking a directory this test never cleans up.
        config_class.KB_ATTACHMENTS_DIR = os.path.join(instance_dir, "kb_attachments")
        app = None
        try:
            app = create_app(config_class=config_class, instance_path=instance_dir)
            return app
        finally:
            if app is not None:
                app.apscheduler.shutdown(wait=False)
            shutil.rmtree(instance_dir, ignore_errors=True)

    def test_null_scanner_is_default_and_starts_ok(self):
        class Cfg(_StartupConfig):
            pass  # KB_SCANNER="null" inherited from TestConfig, unchanged

        app = self._create_app(Cfg)
        self.assertEqual(app.config["KB_SCANNER"], "null")
        # Startup validation alone isn't enough proof — confirm get_scanner()
        # actually resolves the scanner this specific app was configured
        # with (regression guard for the startup log line reading the same
        # config key: a logging-only change must never affect resolution).
        with app.app_context():
            self.assertIsInstance(get_scanner(), NullScanner)

    def test_dev_allow_without_flag_raises_runtime_error(self):
        class Cfg(_StartupConfig):
            KB_SCANNER = "dev_allow"
            # KB_ALLOW_INSECURE_DEV_SCANNER deliberately omitted

        with self.assertRaises(RuntimeError):
            self._create_app(Cfg)

    def test_dev_allow_with_flag_starts_ok(self):
        class Cfg(_StartupConfig):
            KB_SCANNER = "dev_allow"
            KB_ALLOW_INSECURE_DEV_SCANNER = True

        app = self._create_app(Cfg)
        self.assertEqual(app.config["KB_SCANNER"], "dev_allow")
        with app.app_context():
            self.assertIsInstance(get_scanner(), DevAllowScanner)

    def test_unknown_scanner_name_raises_runtime_error(self):
        class Cfg(_StartupConfig):
            KB_SCANNER = "clamav"  # not implemented — must not silently become NullScanner

        with self.assertRaises(RuntimeError):
            self._create_app(Cfg)

    def test_dev_allow_with_non_boolean_truthy_flag_still_raises_runtime_error(self):
        """The shipped Config always coerces this to a real bool via
        .strip().lower() == 'true', but the gate itself must not rely on
        plain truthiness — a non-empty string like "false" is truthy in
        Python and must NOT satisfy this guard."""

        class Cfg(_StartupConfig):
            KB_SCANNER = "dev_allow"
            KB_ALLOW_INSECURE_DEV_SCANNER = "false"

        with self.assertRaises(RuntimeError):
            self._create_app(Cfg)


class TestGetScannerResolution(PortalTestCase):
    """get_scanner() itself, resolved against a real app context — uses the
    shared default (null) app from PortalTestCase since no dev_allow
    behavior is under test here."""

    def test_get_scanner_returns_null_scanner_by_default(self):
        self.assertIsInstance(get_scanner(), NullScanner)

    def test_get_scanner_with_invalid_runtime_config_raises_runtime_error_not_keyerror(self):
        """validate_scanner_config() already guarantees this can't happen
        through normal startup, but get_scanner() must still fail loud and
        clear — never a raw KeyError/500 — if KB_SCANNER is ever mutated to
        an unregistered value after create_app() has returned."""
        original = self.app.config["KB_SCANNER"]
        self.app.config["KB_SCANNER"] = "mutated-after-startup-invalid"
        try:
            with self.assertRaises(RuntimeError):
                get_scanner()
        finally:
            self.app.config["KB_SCANNER"] = original


class TestNullScannerDefaultEndToEnd(PortalTestCase):
    """Confirms the real upload path (not a fabricated DB row) wires
    get_scanner() -> NullScanner -> scan_status="not_scanned" -> both
    serving routes blocked, under the suite's default KB_SCANNER="null"."""

    def setUp(self):
        super().setUp()
        from app.models.knowledge import KnowledgeArticle

        self.author = self.make_user("kb_author_scan", tools=["knowledge_base"])
        self.login("kb_author_scan")
        from app.extensions import db

        self.article = KnowledgeArticle(title="t", problem_md="p", solution_md="s", author=self.author)
        db.session.add(self.article)
        db.session.commit()

    def test_uploaded_image_is_not_scanned_and_both_routes_block_it(self):
        page = self.client.get(f"/kb/{self.article.id}/editar")
        token = self.extract_csrf(page.get_data(as_text=True))
        png_bytes = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20
        upload = self.client.post(
            f"/kb/{self.article.id}/attachments/upload",
            data={"file": (io.BytesIO(png_bytes), "shot.png"), "csrf_token": token},
            content_type="multipart/form-data",
        )
        self.assertEqual(upload.status_code, 200)
        att_id = upload.get_json()["id"]
        self.assertEqual(upload.get_json()["scan_status"], "not_scanned")

        self.assertEqual(self.client.get(f"/kb/attachments/{att_id}/view").status_code, 404)
        self.assertEqual(self.client.get(f"/kb/attachments/{att_id}/download").status_code, 404)
