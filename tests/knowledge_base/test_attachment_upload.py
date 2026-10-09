import io
from tests.base import PortalTestCase
from app.models.knowledge import KnowledgeArticle, KnowledgeAttachment  # noqa: F401
from app.extensions import db

PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20


class TestAttachmentUploadToExistingArticle(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.author = self.make_user("kb_author", tools=["knowledge_base"])
        self.login("kb_author")
        self.article = KnowledgeArticle(title="t", problem_md="p", solution_md="s", author=self.author)
        db.session.add(self.article)
        db.session.commit()

    def _csrf(self):
        page = self.client.get(f"/kb/{self.article.id}/editar")
        return self.extract_csrf(page.get_data(as_text=True))

    def test_author_can_upload_to_own_article(self):
        resp = self.client.post(
            f"/kb/{self.article.id}/attachments/upload",
            data={"file": (io.BytesIO(PNG_BYTES), "shot.png"), "csrf_token": self._csrf()},
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(KnowledgeAttachment.query.filter_by(article_id=self.article.id).count(), 1)

    def test_non_owner_non_admin_cannot_upload(self):
        self.make_user("other_user", tools=["knowledge_base"])
        self.login("other_user")
        csrf = self.extract_csrf(self.client.get("/kb/").get_data(as_text=True))
        resp = self.client.post(
            f"/kb/{self.article.id}/attachments/upload",
            data={"file": (io.BytesIO(PNG_BYTES), "shot.png"), "csrf_token": csrf},
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 403)
        self.assertEqual(KnowledgeAttachment.query.filter_by(article_id=self.article.id).count(), 0)

    def test_admin_can_upload_to_any_article(self):
        self.make_user("admin_user", is_admin=True, tools=["knowledge_base"])
        self.login("admin_user")
        csrf = self.extract_csrf(self.client.get("/kb/").get_data(as_text=True))
        resp = self.client.post(
            f"/kb/{self.article.id}/attachments/upload",
            data={"file": (io.BytesIO(PNG_BYTES), "shot.png"), "csrf_token": csrf},
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 200)

    def test_infected_attachment_does_not_permanently_consume_quota(self):
        # An infected row's physical file is already unlinked (Task 5's
        # upload handler), so it has no real disk footprint left — it
        # must not count against the article's size quota forever.
        infected = KnowledgeAttachment(
            article_id=self.article.id, draft_token=None,
            original_filename="old-infected.pdf", stored_filename="old-infected.pdf",
            mime_type="application/pdf", extension="pdf",
            # Deliberately less headroom than len(PNG_BYTES) leaves: if the
            # infected row is (wrongly) still counted, this upload would be
            # rejected by the quota check; the test only passes for the
            # right reason if infected rows are excluded from the sum.
            size_bytes=self.app.config["KB_ATTACHMENT_MAX_TOTAL_BYTES"] - len(PNG_BYTES) + 1,
            sha256="a" * 64, is_image=False, uploaded_by=self.author.id,
            scan_status="infected",
        )
        db.session.add(infected)
        db.session.commit()

        resp = self.client.post(
            f"/kb/{self.article.id}/attachments/upload",
            data={"file": (io.BytesIO(PNG_BYTES), "shot.png"), "csrf_token": self._csrf()},
            content_type="multipart/form-data",
        )
        self.assertEqual(resp.status_code, 200)

    def test_oversized_file_rejected(self):
        self.app.config["KB_ATTACHMENT_MAX_SIZE_BYTES"] = 10  # force a tiny limit for this test
        try:
            resp = self.client.post(
                f"/kb/{self.article.id}/attachments/upload",
                data={"file": (io.BytesIO(PNG_BYTES), "shot.png"), "csrf_token": self._csrf()},
                content_type="multipart/form-data",
            )
            self.assertEqual(resp.status_code, 400)
        finally:
            self.app.config["KB_ATTACHMENT_MAX_SIZE_BYTES"] = 10 * 1024 * 1024  # restore
