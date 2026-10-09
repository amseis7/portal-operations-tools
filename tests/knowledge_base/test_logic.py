from tests.base import PortalTestCase
from app.extensions import db
from app.models.knowledge import KnowledgeArticle, KnowledgeTag  # noqa: F401


class TestSyncTags(PortalTestCase):
    def test_creates_new_tags_normalized(self):
        from app.knowledge_base.logic import sync_tags

        author = self.make_user("autor")
        article = KnowledgeArticle(
            title="t", problem_md="p", solution_md="s", author=author
        )
        db.session.add(article)
        db.session.flush()

        sync_tags(article, "DNS, Windows ,  dns")  # dup + case + whitespace
        db.session.commit()

        names = sorted(t.name for t in article.tags)
        self.assertEqual(names, ["dns", "windows"])
        self.assertEqual(KnowledgeTag.query.count(), 2)

    def test_reuses_existing_tag_instead_of_duplicating(self):
        from app.knowledge_base.logic import sync_tags

        db.session.add(KnowledgeTag(name="dns"))
        db.session.commit()

        author = self.make_user("autor2")
        article = KnowledgeArticle(
            title="t2", problem_md="p", solution_md="s", author=author
        )
        db.session.add(article)
        db.session.flush()

        sync_tags(article, "dns")
        db.session.commit()

        self.assertEqual(KnowledgeTag.query.count(), 1)

    def test_removes_tags_no_longer_present(self):
        from app.knowledge_base.logic import sync_tags

        author = self.make_user("autor3")
        article = KnowledgeArticle(
            title="t3", problem_md="p", solution_md="s", author=author
        )
        db.session.add(article)
        db.session.flush()
        sync_tags(article, "dns, windows")
        db.session.commit()

        sync_tags(article, "windows")
        db.session.commit()

        self.assertEqual([t.name for t in article.tags], ["windows"])


class TestEscapeLike(PortalTestCase):
    def test_escapes_percent_and_underscore(self):
        from app.knowledge_base.logic import escape_like

        self.assertEqual(escape_like("50%_done"), r"50\%\_done")

    def test_escapes_backslash_first(self):
        from app.knowledge_base.logic import escape_like

        self.assertEqual(escape_like("a\\b"), "a\\\\b")
