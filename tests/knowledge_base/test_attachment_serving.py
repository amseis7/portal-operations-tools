from tests.base import PortalTestCase
from app.extensions import db
from app.models.knowledge import KnowledgeArticle, KnowledgeAttachment  # noqa: F401


class TestAttachmentServing(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.author = self.make_user("kb_author", tools=["knowledge_base"])
        self.reader = self.make_user("kb_reader", tools=["knowledge_base"])
        self.article = KnowledgeArticle(title="t", problem_md="p", solution_md="s", author=self.author)
        db.session.add(self.article)
        db.session.flush()

    def _make_attachment(self, scan_status, is_image=True, article_id=None, draft_token=None, uploaded_by=None):
        import hashlib, os
        content = b"fake-content"
        stored = "test-" + hashlib.sha1(os.urandom(8)).hexdigest() + (".png" if is_image else ".pdf")
        path = os.path.join(self.app.config["KB_ATTACHMENTS_DIR"], stored)
        os.makedirs(self.app.config["KB_ATTACHMENTS_DIR"], exist_ok=True)
        with open(path, "wb") as f:
            f.write(content)
        att = KnowledgeAttachment(
            article_id=article_id, draft_token=draft_token,
            original_filename="x.png" if is_image else "x.pdf",
            stored_filename=stored,
            mime_type="image/png" if is_image else "application/pdf",
            extension="png" if is_image else "pdf",
            size_bytes=len(content), sha256=hashlib.sha256(content).hexdigest(),
            is_image=is_image, uploaded_by=uploaded_by or self.author.id,
            scan_status=scan_status,
        )
        db.session.add(att)
        db.session.commit()
        return att

    def test_clean_image_view_succeeds_for_any_tool_user(self):
        att = self._make_attachment("clean", is_image=True, article_id=self.article.id)
        self.login("kb_reader")
        resp = self.client.get(f"/kb/attachments/{att.id}/view")
        self.assertEqual(resp.status_code, 200)

    def test_pending_image_view_blocked(self):
        att = self._make_attachment("pending", is_image=True, article_id=self.article.id)
        self.login("kb_reader")
        self.assertEqual(self.client.get(f"/kb/attachments/{att.id}/view").status_code, 404)

    def test_not_scanned_image_view_blocked(self):
        att = self._make_attachment("not_scanned", is_image=True, article_id=self.article.id)
        self.login("kb_reader")
        self.assertEqual(self.client.get(f"/kb/attachments/{att.id}/view").status_code, 404)

    def test_infected_blocked_on_both_routes(self):
        att = self._make_attachment("infected", is_image=True, article_id=self.article.id)
        self.login("kb_reader")
        self.assertEqual(self.client.get(f"/kb/attachments/{att.id}/view").status_code, 404)
        self.assertEqual(self.client.get(f"/kb/attachments/{att.id}/download").status_code, 404)

    def test_scan_error_blocked(self):
        att = self._make_attachment("scan_error", is_image=False, article_id=self.article.id)
        self.login("kb_reader")
        self.assertEqual(self.client.get(f"/kb/attachments/{att.id}/download").status_code, 404)

    def test_clean_document_download_is_attachment_not_inline(self):
        att = self._make_attachment("clean", is_image=False, article_id=self.article.id)
        self.login("kb_reader")
        resp = self.client.get(f"/kb/attachments/{att.id}/download")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("attachment", resp.headers.get("Content-Disposition", ""))

    def test_clean_document_has_no_view_route_access(self):
        att = self._make_attachment("clean", is_image=False, article_id=self.article.id)
        self.login("kb_reader")
        self.assertEqual(self.client.get(f"/kb/attachments/{att.id}/view").status_code, 404)

    def test_view_missing_physical_file_returns_404_not_500(self):
        # A "clean" row whose physical file disappeared from disk (an
        # orphaned-row edge case, not security-relevant on its own) must
        # degrade to a graceful 404, never an unhandled FileNotFoundError.
        import os
        att = self._make_attachment("clean", is_image=True, article_id=self.article.id)
        os.remove(os.path.join(self.app.config["KB_ATTACHMENTS_DIR"], att.stored_filename))
        self.login("kb_reader")
        self.assertEqual(self.client.get(f"/kb/attachments/{att.id}/view").status_code, 404)

    def test_download_missing_physical_file_returns_404_not_500(self):
        import os
        att = self._make_attachment("clean", is_image=False, article_id=self.article.id)
        os.remove(os.path.join(self.app.config["KB_ATTACHMENTS_DIR"], att.stored_filename))
        self.login("kb_reader")
        self.assertEqual(self.client.get(f"/kb/attachments/{att.id}/download").status_code, 404)

    def test_draft_attachment_readable_only_by_its_uploader(self):
        att = self._make_attachment("clean", is_image=True, draft_token="tok-x", uploaded_by=self.author.id)
        self.login("kb_reader")  # different user than uploader
        self.assertEqual(self.client.get(f"/kb/attachments/{att.id}/view").status_code, 404)
        self.login("kb_author")
        self.assertEqual(self.client.get(f"/kb/attachments/{att.id}/view").status_code, 200)
