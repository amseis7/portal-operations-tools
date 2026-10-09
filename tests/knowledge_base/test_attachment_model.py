from tests.base import PortalTestCase
from app.extensions import db
from app.models.knowledge import KnowledgeArticle, KnowledgeAttachment  # noqa: F401
from sqlalchemy.exc import IntegrityError


class TestKnowledgeAttachmentModel(PortalTestCase):
    def _make_article(self):
        author = self.make_user("kb_author")
        article = KnowledgeArticle(title="t", problem_md="p", solution_md="s", author=author)
        db.session.add(article)
        db.session.flush()
        return article, author

    def test_attachment_belongs_to_article(self):
        article, author = self._make_article()
        att = KnowledgeAttachment(
            article_id=article.id, original_filename="shot.png",
            stored_filename="abc123.png", mime_type="image/png", extension="png",
            size_bytes=100, sha256="x" * 64, is_image=True, uploaded_by=author.id,
        )
        db.session.add(att)
        db.session.commit()
        self.assertEqual(KnowledgeArticle.query.get(article.id).attachments[0].original_filename, "shot.png")

    def test_attachment_belongs_to_draft_token(self):
        author = self.make_user("kb_author2")
        att = KnowledgeAttachment(
            draft_token="tok-1", original_filename="shot.png",
            stored_filename="def456.png", mime_type="image/png", extension="png",
            size_bytes=100, sha256="y" * 64, is_image=True, uploaded_by=author.id,
        )
        db.session.add(att)
        db.session.commit()
        self.assertEqual(KnowledgeAttachment.query.filter_by(draft_token="tok-1").count(), 1)

    def test_neither_article_nor_draft_token_violates_constraint(self):
        author = self.make_user("kb_author3")
        att = KnowledgeAttachment(
            original_filename="shot.png", stored_filename="ghi789.png",
            mime_type="image/png", extension="png", size_bytes=100,
            sha256="z" * 64, is_image=True, uploaded_by=author.id,
        )
        db.session.add(att)
        with self.assertRaises(IntegrityError):
            db.session.commit()

    def test_both_article_and_draft_token_violates_constraint(self):
        article, author = self._make_article()
        att = KnowledgeAttachment(
            article_id=article.id, draft_token="tok-2",
            original_filename="shot.png", stored_filename="jkl012.png",
            mime_type="image/png", extension="png", size_bytes=100,
            sha256="w" * 64, is_image=True, uploaded_by=author.id,
        )
        db.session.add(att)
        with self.assertRaises(IntegrityError):
            db.session.commit()

    def test_deleting_article_cascades_attachment_rows(self):
        article, author = self._make_article()
        att = KnowledgeAttachment(
            article_id=article.id, original_filename="shot.png",
            stored_filename="mno345.png", mime_type="image/png", extension="png",
            size_bytes=100, sha256="v" * 64, is_image=True, uploaded_by=author.id,
        )
        db.session.add(att)
        db.session.commit()
        att_id = att.id

        db.session.delete(article)
        db.session.commit()

        self.assertIsNone(db.session.get(KnowledgeAttachment, att_id))
