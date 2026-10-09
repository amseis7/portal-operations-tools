import io
from unittest.mock import patch
from tests.base import PortalTestCase
from app.extensions import db
from app.knowledge_base import attachment_routes
from app.models.knowledge import KnowledgeArticle, KnowledgeAttachment  # noqa: F401

PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20


class TestAttachmentDraftLifecycle(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.author = self.make_user("kb_author", tools=["knowledge_base"])
        self.login("kb_author")
        attachment_routes._last_lazy_purge_at[0] = 0.0  # avoid cross-test throttle state leaking

    def _csrf(self, url="/kb/nuevo"):
        page = self.client.get(url)
        return self.extract_csrf(page.get_data(as_text=True))

    def _draft_upload(self, token, csrf, filename="shot.png", data=PNG_BYTES):
        return self.client.post(
            "/kb/attachments/draft-upload",
            data={
                "file": (io.BytesIO(data), filename),
                "draft_token": token,
                "csrf_token": csrf,
            },
            content_type="multipart/form-data",
        )

    def test_draft_upload_creates_attachment_owned_by_uploader(self):
        resp = self._draft_upload("tok-A", self._csrf())
        self.assertEqual(resp.status_code, 200)
        att = KnowledgeAttachment.query.filter_by(draft_token="tok-A").first()
        self.assertIsNotNone(att)
        self.assertEqual(att.uploaded_by, self.author.id)

    def test_upload_response_includes_server_authoritative_original_filename(self):
        # The client must never have to trust its own (locally-known,
        # untruncated) file.name when rendering the just-uploaded row —
        # the response should carry the server's own (length-capped)
        # original_filename, the same value a page reload would show.
        resp = self._draft_upload("tok-name", self._csrf(), filename="shot.png")
        self.assertEqual(resp.get_json()["original_filename"], "shot.png")

    def test_other_user_draft_upload_gets_independent_token_ownership(self):
        self._draft_upload("tok-A", self._csrf())
        self.make_user("other_user", tools=["knowledge_base"])
        self.login("other_user")
        self._draft_upload("tok-A", self._csrf())  # same token string, different user

        rows = KnowledgeAttachment.query.filter_by(draft_token="tok-A").all()
        self.assertEqual(len(rows), 2)
        uploaders = {r.uploaded_by for r in rows}
        self.assertEqual(len(uploaders), 2)  # each row owned by its own uploader, not shared

    def test_promotion_on_successful_article_creation(self):
        token = "tok-promote"
        self._draft_upload(token, self._csrf())

        csrf = self._csrf()
        self.client.post(
            "/kb/nuevo",
            data={
                "title": "Articulo con adjunto",
                "problem_md": "p", "solution_md": "s",
                "draft_token": token, "csrf_token": csrf,
            },
            follow_redirects=True,
        )

        article = KnowledgeArticle.query.filter_by(title="Articulo con adjunto").first()
        self.assertIsNotNone(article)
        att = KnowledgeAttachment.query.filter_by(article_id=article.id).first()
        self.assertIsNotNone(att)
        self.assertIsNone(att.draft_token)

    def test_failed_article_creation_leaves_draft_untouched(self):
        token = "tok-fail"
        self._draft_upload(token, self._csrf())

        csrf = self._csrf()
        self.client.post(  # missing title -> validation failure
            "/kb/nuevo",
            data={"problem_md": "p", "solution_md": "s", "draft_token": token, "csrf_token": csrf},
        )

        att = KnowledgeAttachment.query.filter_by(draft_token=token).first()
        self.assertIsNotNone(att)
        self.assertIsNone(att.article_id)

    def test_draft_total_size_quota_enforced(self):
        # Draft-stage uploads (article_id is None) had no total-size cap at
        # all — only the per-file KB_ATTACHMENT_MAX_SIZE_BYTES check — so a
        # single draft_token could accumulate unlimited files on disk
        # before ever being promoted (or abandoned). Same quota must apply,
        # scoped by draft_token instead of article_id.
        self.app.config["KB_ATTACHMENT_MAX_TOTAL_BYTES"] = len(PNG_BYTES)
        try:
            token = "tok-quota"
            first = self._draft_upload(token, self._csrf())
            self.assertEqual(first.status_code, 200)
            second = self._draft_upload(token, self._csrf())
            self.assertEqual(second.status_code, 400)
        finally:
            self.app.config["KB_ATTACHMENT_MAX_TOTAL_BYTES"] = 50 * 1024 * 1024

    def test_draft_token_preserved_across_validation_failure_rerender(self):
        token = "tok-preserve"
        csrf = self._csrf()
        resp = self.client.post(
            "/kb/nuevo",  # missing title -> validation failure
            data={"problem_md": "p", "solution_md": "s", "draft_token": token, "csrf_token": csrf},
        )
        self.assertIn(f'value="{token}"'.encode(), resp.data)

    def test_lazy_purge_is_throttled_not_run_on_every_request(self):
        # purge_expired_drafts() does a full table scan plus a per-row
        # delete+commit loop — calling it unconditionally on every single
        # draft-upload request duplicates the 24h scheduled job's work on
        # a hot path. It must be throttled, not invoked every time.
        with patch("app.knowledge_base.attachment_routes.purge_expired_drafts") as mock_purge:
            self._draft_upload("tok-a", self._csrf())
            self._draft_upload("tok-b", self._csrf())
        self.assertEqual(mock_purge.call_count, 1)

    def test_previously_uploaded_drafts_reappear_after_validation_failure_rerender(self):
        token = "tok-reappear"
        self._draft_upload(token, self._csrf(), filename="screenshot.png")

        csrf = self._csrf()
        resp = self.client.post(
            "/kb/nuevo",  # missing title -> validation failure
            data={"problem_md": "p", "solution_md": "s", "draft_token": token, "csrf_token": csrf},
        )
        self.assertIn(b"screenshot.png", resp.data)
