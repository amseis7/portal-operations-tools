import io
import os
from unittest.mock import patch
from tests.base import PortalTestCase
from app.extensions import db
from app.models.knowledge import KnowledgeArticle, KnowledgeAttachment  # noqa: F401

PNG_BYTES = b"\x89PNG\r\n\x1a\n" + b"\x00" * 20


class TestArticleDeleteCleansAttachments(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.admin = self.make_user("kb_admin", is_admin=True)
        self.login("kb_admin")
        self.article = KnowledgeArticle(title="t", problem_md="p", solution_md="s", author=self.admin)
        db.session.add(self.article)
        db.session.commit()
        csrf = self.extract_csrf(self.client.get(f"/kb/{self.article.id}/editar").get_data(as_text=True))
        self.client.post(
            f"/kb/{self.article.id}/attachments/upload",
            data={"file": (io.BytesIO(PNG_BYTES), "shot.png"), "csrf_token": csrf},
            content_type="multipart/form-data",
        )

    def test_deleting_article_removes_attachment_file_from_disk(self):
        att = KnowledgeAttachment.query.filter_by(article_id=self.article.id).first()
        path = os.path.join(self.app.config["KB_ATTACHMENTS_DIR"], att.stored_filename)
        self.assertTrue(os.path.exists(path))

        csrf = self.extract_csrf(self.client.get(f"/kb/{self.article.id}").get_data(as_text=True))
        self.client.post(f"/kb/{self.article.id}/eliminar", data={"csrf_token": csrf}, follow_redirects=True)

        self.assertFalse(os.path.exists(path))
        self.assertIsNone(db.session.get(KnowledgeAttachment, att.id))

    def test_attachment_file_is_not_unlinked_if_db_commit_fails(self):
        att = KnowledgeAttachment.query.filter_by(article_id=self.article.id).first()
        path = os.path.join(self.app.config["KB_ATTACHMENTS_DIR"], att.stored_filename)
        self.assertTrue(os.path.exists(path))

        csrf = self.extract_csrf(self.client.get(f"/kb/{self.article.id}").get_data(as_text=True))
        with patch.object(db.session, "commit", side_effect=Exception("simulated DB failure")):
            with self.assertRaises(Exception):
                self.client.post(f"/kb/{self.article.id}/eliminar", data={"csrf_token": csrf})

        self.assertTrue(os.path.exists(path))
        self.assertIsNotNone(db.session.get(KnowledgeAttachment, att.id))
