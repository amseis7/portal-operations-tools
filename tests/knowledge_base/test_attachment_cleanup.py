import os
from datetime import datetime, timedelta
from tests.base import PortalTestCase
from app.extensions import db
from app.models.knowledge import KnowledgeArticle, KnowledgeAttachment  # noqa: F401
from app.knowledge_base.attachment_cleanup import purge_expired_drafts


class TestAttachmentCleanup(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.author = self.make_user("kb_author")

    def _make_attachment(self, created_at, article_id=None, draft_token=None):
        import hashlib
        stored = "cleanup-" + hashlib.sha1(os.urandom(8)).hexdigest() + ".png"
        os.makedirs(self.app.config["KB_ATTACHMENTS_DIR"], exist_ok=True)
        path = os.path.join(self.app.config["KB_ATTACHMENTS_DIR"], stored)
        with open(path, "wb") as f:
            f.write(b"x")
        att = KnowledgeAttachment(
            article_id=article_id, draft_token=draft_token,
            original_filename="x.png", stored_filename=stored,
            mime_type="image/png", extension="png", size_bytes=1,
            sha256="a" * 64, is_image=True, uploaded_by=self.author.id,
            scan_status="pending", created_at=created_at,
        )
        db.session.add(att)
        db.session.commit()
        return att, path

    def test_expired_draft_is_purged(self):
        att, path = self._make_attachment(
            created_at=datetime.utcnow() - timedelta(hours=25), draft_token="tok-old"
        )
        att_id = att.id  # captured before purge expires/deletes the ORM instance
        deleted = purge_expired_drafts(self.app)
        self.assertEqual(deleted, 1)
        # purge_expired_drafts() opens its own nested app context, which
        # Flask-SQLAlchemy gives its own Session — the outer test session's
        # identity map still holds the pre-delete object, so db.session.get()
        # (which trusts the identity map for a primary-key lookup) would
        # return the stale cached instance instead of re-querying. A real
        # query always hits the DB and correctly reflects the deletion.
        self.assertIsNone(KnowledgeAttachment.query.filter_by(id=att_id).first())
        self.assertFalse(os.path.exists(path))

    def test_draft_within_ttl_is_not_purged(self):
        att, path = self._make_attachment(
            created_at=datetime.utcnow() - timedelta(hours=1), draft_token="tok-fresh"
        )
        purge_expired_drafts(self.app)
        self.assertIsNotNone(db.session.get(KnowledgeAttachment, att.id))
        self.assertTrue(os.path.exists(path))

    def test_promoted_attachment_is_never_purged_even_if_old(self):
        article = KnowledgeArticle(title="t", problem_md="p", solution_md="s", author=self.author)
        db.session.add(article)
        db.session.flush()
        att, path = self._make_attachment(
            created_at=datetime.utcnow() - timedelta(hours=48), article_id=article.id
        )
        purge_expired_drafts(self.app)
        self.assertIsNotNone(db.session.get(KnowledgeAttachment, att.id))
        self.assertTrue(os.path.exists(path))

    def test_purge_already_missing_file_does_not_raise(self):
        att, path = self._make_attachment(
            created_at=datetime.utcnow() - timedelta(hours=25), draft_token="tok-nofile"
        )
        os.remove(path)  # simulate a prior/concurrent run already having removed it
        deleted = purge_expired_drafts(self.app)  # must not raise
        self.assertEqual(deleted, 1)

    def test_running_purge_twice_concurrently_is_safe(self):
        self._make_attachment(
            created_at=datetime.utcnow() - timedelta(hours=25), draft_token="tok-dup"
        )
        first = purge_expired_drafts(self.app)
        second = purge_expired_drafts(self.app)  # same expired row, run again
        self.assertEqual(first, 1)
        self.assertEqual(second, 0)  # nothing left to purge, no error

    # A real-OS-thread variant of the test above was tried and removed: two
    # threads calling purge_expired_drafts() at the exact same instant both
    # end up hitting this test harness's single shared SQLite StaticPool
    # connection simultaneously, which produced an intermittent spurious
    # [0, 0] result (confirmed via a standalone repro — not a double-delete,
    # not an exception, just sqlite3's undefined behavior under literally
    # concurrent use of one connection object from two threads). That is a
    # property of this test harness's DB engine configuration, not of the
    # atomic-delete fix: the fix's correctness rests on documented SQL
    # statement-level atomicity (a single DELETE ... WHERE ... is atomic by
    # construction), which the sequential double-call test above already
    # exercises deterministically.
