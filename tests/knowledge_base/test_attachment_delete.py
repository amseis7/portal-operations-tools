import os
from unittest.mock import patch
from tests.base import PortalTestCase
from app.extensions import db
from app.models.knowledge import KnowledgeArticle, KnowledgeAttachment  # noqa: F401


class TestAttachmentDelete(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.author = self.make_user("kb_author", tools=["knowledge_base"])
        self.article = KnowledgeArticle(title="t", problem_md="p", solution_md="s", author=self.author)
        db.session.add(self.article)
        db.session.flush()

    def _make_attachment(self, article_id=None, draft_token=None, uploaded_by=None):
        import hashlib
        stored = "del-" + hashlib.sha1(os.urandom(8)).hexdigest() + ".png"
        os.makedirs(self.app.config["KB_ATTACHMENTS_DIR"], exist_ok=True)
        path = os.path.join(self.app.config["KB_ATTACHMENTS_DIR"], stored)
        with open(path, "wb") as f:
            f.write(b"x")
        att = KnowledgeAttachment(
            article_id=article_id, draft_token=draft_token,
            original_filename="x.png", stored_filename=stored,
            mime_type="image/png", extension="png", size_bytes=1,
            sha256="a" * 64, is_image=True, uploaded_by=uploaded_by or self.author.id,
            scan_status="clean",
        )
        db.session.add(att)
        db.session.commit()
        return att, path

    def _csrf(self):
        page = self.client.get(f"/kb/{self.article.id}/editar")
        return self.extract_csrf(page.get_data(as_text=True))

    def test_author_can_delete_attachment_of_own_article(self):
        self.login("kb_author")
        att, path = self._make_attachment(article_id=self.article.id)
        resp = self.client.post(f"/kb/attachments/{att.id}/delete", data={"csrf_token": self._csrf()})
        self.assertEqual(resp.status_code, 200)
        self.assertIsNone(db.session.get(KnowledgeAttachment, att.id))
        self.assertFalse(os.path.exists(path))

    def test_admin_can_delete_attachment_of_any_article(self):
        self.make_user("admin_user", is_admin=True, tools=["knowledge_base"])
        self.login("admin_user")
        att, path = self._make_attachment(article_id=self.article.id)
        csrf = self.extract_csrf(self.client.get("/kb/").get_data(as_text=True))
        resp = self.client.post(f"/kb/attachments/{att.id}/delete", data={"csrf_token": csrf})
        self.assertEqual(resp.status_code, 200)
        self.assertIsNone(db.session.get(KnowledgeAttachment, att.id))

    def test_non_owner_non_admin_cannot_delete_promoted_attachment(self):
        self.make_user("other_user", tools=["knowledge_base"])
        self.login("other_user")
        att, path = self._make_attachment(article_id=self.article.id)
        csrf = self.extract_csrf(self.client.get("/kb/").get_data(as_text=True))
        resp = self.client.post(f"/kb/attachments/{att.id}/delete", data={"csrf_token": csrf})
        self.assertEqual(resp.status_code, 403)
        self.assertIsNotNone(db.session.get(KnowledgeAttachment, att.id))
        self.assertTrue(os.path.exists(path))

    def test_uploader_can_discard_own_draft_attachment(self):
        self.login("kb_author")
        att, path = self._make_attachment(draft_token="tok-x", uploaded_by=self.author.id)
        csrf = self.extract_csrf(self.client.get("/kb/").get_data(as_text=True))
        resp = self.client.post(f"/kb/attachments/{att.id}/delete", data={"csrf_token": csrf})
        self.assertEqual(resp.status_code, 200)
        self.assertIsNone(db.session.get(KnowledgeAttachment, att.id))
        self.assertFalse(os.path.exists(path))

    def test_non_uploader_cannot_discard_someone_elses_draft_attachment(self):
        att, path = self._make_attachment(draft_token="tok-x", uploaded_by=self.author.id)
        self.make_user("other_user", tools=["knowledge_base"])
        self.login("other_user")
        csrf = self.extract_csrf(self.client.get("/kb/").get_data(as_text=True))
        resp = self.client.post(f"/kb/attachments/{att.id}/delete", data={"csrf_token": csrf})
        self.assertEqual(resp.status_code, 403)
        self.assertIsNotNone(db.session.get(KnowledgeAttachment, att.id))
        self.assertTrue(os.path.exists(path))

    def test_file_is_not_unlinked_if_db_commit_fails(self):
        # The file must only ever be removed once the row deletion is
        # actually committed — never the other way around, since a failed
        # commit means the row (still claiming scan_status="clean") would
        # otherwise point at a file that no longer exists on disk.
        self.login("kb_author")
        att, path = self._make_attachment(article_id=self.article.id)
        csrf = self._csrf()
        with patch.object(db.session, "commit", side_effect=Exception("simulated DB failure")):
            with self.assertRaises(Exception):
                self.client.post(f"/kb/attachments/{att.id}/delete", data={"csrf_token": csrf})
        self.assertTrue(os.path.exists(path))
        self.assertIsNotNone(db.session.get(KnowledgeAttachment, att.id))

    def test_deleting_already_missing_file_does_not_raise(self):
        self.login("kb_author")
        att, path = self._make_attachment(article_id=self.article.id)
        os.remove(path)
        resp = self.client.post(f"/kb/attachments/{att.id}/delete", data={"csrf_token": self._csrf()})
        self.assertEqual(resp.status_code, 200)
        self.assertIsNone(db.session.get(KnowledgeAttachment, att.id))
