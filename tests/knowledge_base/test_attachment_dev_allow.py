import io
import os
import shutil
import tempfile

from app import create_app
from app.extensions import db
from app.knowledge_base.scanning import get_scanner
from app.models.audit import AuditLog
from app.models.knowledge import KnowledgeArticle, KnowledgeAttachment
from tests.base import PortalTestCase, TestConfig

PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20
PDF_BYTES = b"%PDF-1.4\n%%EOF"


class DevAllowTestConfig(TestConfig):
    KB_SCANNER = "dev_allow"
    KB_ALLOW_INSECURE_DEV_SCANNER = True


class TestDevAllowScannerAttachments(PortalTestCase):
    """A dedicated app/instance dir with KB_SCANNER=dev_allow — cannot reuse
    PortalTestCase's shared cls.app, which is built once with the suite's
    default TestConfig (KB_SCANNER="null") and must stay that way for every
    other test class."""

    @classmethod
    def setUpClass(cls):
        cls._instance_dir = tempfile.mkdtemp(prefix="portal-test-instance-devallow-")
        DevAllowTestConfig.KB_ATTACHMENTS_DIR = os.path.join(cls._instance_dir, "kb_attachments")
        cls.app = create_app(config_class=DevAllowTestConfig, instance_path=cls._instance_dir)

    @classmethod
    def tearDownClass(cls):
        cls.app.apscheduler.shutdown(wait=False)
        shutil.rmtree(cls._instance_dir, ignore_errors=True)

    def setUp(self):
        super().setUp()
        self.author = self.make_user("kb_author_da", tools=["knowledge_base"])
        self.login("kb_author_da")
        self.article = KnowledgeArticle(title="t", problem_md="p", solution_md="s", author=self.author)
        db.session.add(self.article)
        db.session.commit()

    def _csrf(self):
        page = self.client.get(f"/kb/{self.article.id}/editar")
        return self.extract_csrf(page.get_data(as_text=True))

    def _upload(self, content, filename):
        return self.client.post(
            f"/kb/{self.article.id}/attachments/upload",
            data={"file": (io.BytesIO(content), filename), "csrf_token": self._csrf()},
            content_type="multipart/form-data",
        )

    def test_image_upload_with_dev_allow_is_marked_clean(self):
        resp = self._upload(PNG_BYTES, "shot.png")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.get_json()["scan_status"], "clean")

    def test_clean_image_view_returns_200(self):
        att_id = self._upload(PNG_BYTES, "shot.png").get_json()["id"]
        resp = self.client.get(f"/kb/attachments/{att_id}/view")
        self.assertEqual(resp.status_code, 200)

    def test_clean_image_download_returns_200(self):
        att_id = self._upload(PNG_BYTES, "shot.png").get_json()["id"]
        resp = self.client.get(f"/kb/attachments/{att_id}/download")
        self.assertEqual(resp.status_code, 200)

    def test_clean_pdf_download_returns_200(self):
        att_id = self._upload(PDF_BYTES, "doc.pdf").get_json()["id"]
        resp = self.client.get(f"/kb/attachments/{att_id}/download")
        self.assertEqual(resp.status_code, 200)

    def test_clean_pdf_view_still_404_not_an_image(self):
        att_id = self._upload(PDF_BYTES, "doc.pdf").get_json()["id"]
        resp = self.client.get(f"/kb/attachments/{att_id}/view")
        self.assertEqual(resp.status_code, 404)

    def test_invalid_signature_still_rejected_with_dev_allow_active(self):
        resp = self._upload(b"not-a-real-png-signature", "fake.png")
        self.assertEqual(resp.status_code, 400)
        self.assertEqual(KnowledgeAttachment.query.count(), 0)

    def test_scanner_error_during_upload_does_not_orphan_file_or_crash(self):
        """get_scanner() can raise RuntimeError (dev_allow's flag cleared
        mid-request). By that point the uploaded file is already written
        to disk — the route must catch this, remove the orphaned file, and
        return a clean error, never an unhandled 500 with a leftover file
        no cleanup path will ever find (neither the quota query nor
        purge_expired_drafts look at files without a DB row)."""
        self.app.config["KB_ALLOW_INSECURE_DEV_SCANNER"] = False
        try:
            before = set(os.listdir(self.app.config["KB_ATTACHMENTS_DIR"]))
            resp = self._upload(PNG_BYTES, "shot.png")
            self.assertEqual(resp.status_code, 500)
            self.assertEqual(KnowledgeAttachment.query.count(), 0)
            after = set(os.listdir(self.app.config["KB_ATTACHMENTS_DIR"]))
            self.assertEqual(after, before, "upload must not leave an orphaned file behind")
        finally:
            self.app.config["KB_ALLOW_INSECURE_DEV_SCANNER"] = True

    def test_get_scanner_rechecks_flag_and_raises_if_cleared_after_startup(self):
        """validate_scanner_config() only runs once, at create_app() time.
        get_scanner() must independently re-check KB_ALLOW_INSECURE_DEV_SCANNER
        on every call — not just KB_SCANNER — so clearing the flag at runtime
        (without a full restart) actually revokes DevAllowScanner instead of
        leaving it silently active because KB_SCANNER still says dev_allow."""
        original = self.app.config["KB_ALLOW_INSECURE_DEV_SCANNER"]
        self.app.config["KB_ALLOW_INSECURE_DEV_SCANNER"] = False
        try:
            with self.assertRaises(RuntimeError):
                get_scanner()
        finally:
            self.app.config["KB_ALLOW_INSECURE_DEV_SCANNER"] = original

    # -- investigative probe: Flow B (draft-upload -> /kb/nuevo promotion) --
    # -- never exercised by any dev_allow test above, all of which only --
    # -- cover Flow A (/kb/<article_id>/attachments/upload) -------------

    def test_draft_upload_then_new_article_promotion_preserves_clean_status(self):
        draft_token = "diag-draft-token-1"
        new_page = self.client.get("/kb/nuevo")
        token = self.extract_csrf(new_page.get_data(as_text=True))

        draft_resp = self.client.post(
            "/kb/attachments/draft-upload",
            data={"file": (io.BytesIO(PNG_BYTES), "shot.png"), "draft_token": draft_token, "csrf_token": token},
            content_type="multipart/form-data",
        )
        self.assertEqual(draft_resp.status_code, 200)
        draft_id = draft_resp.get_json()["id"]
        self.assertEqual(draft_resp.get_json()["scan_status"], "clean")

        create_resp = self.client.post(
            "/kb/nuevo",
            data={
                "title": "Nuevo articulo diag",
                "problem_md": "p", "solution_md": "s",
                "draft_token": draft_token, "csrf_token": token,
            },
            follow_redirects=False,
        )
        self.assertEqual(create_resp.status_code, 302)

        promoted = db.session.get(KnowledgeAttachment, draft_id)
        self.assertIsNotNone(promoted.article_id)
        self.assertIsNone(promoted.draft_token)
        self.assertEqual(promoted.scan_status, "clean")

        self.assertEqual(self.client.get(f"/kb/attachments/{draft_id}/view").status_code, 200)
        self.assertEqual(self.client.get(f"/kb/attachments/{draft_id}/download").status_code, 200)

    def test_upload_with_dev_allow_records_unscanned_detail_in_audit_log(self):
        """The 'dev-allow: file was NOT malware-scanned' detail only earns
        its keep if something durable actually records it — otherwise a
        rubber-stamped upload is indistinguishable from a real clean scan
        to anyone auditing later."""
        att_id = self._upload(PNG_BYTES, "shot.png").get_json()["id"]
        audit = AuditLog.query.filter_by(
            module="knowledge_base", action="attachment_upload", object_id=str(att_id)
        ).first()
        self.assertIsNotNone(audit)
        self.assertIsNotNone(audit.details)
        self.assertIn("NOT", audit.details)
