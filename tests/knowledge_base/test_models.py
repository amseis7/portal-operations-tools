from tests.base import PortalTestCase
from app.extensions import db
from app.models.knowledge import KnowledgeArticle, KnowledgeTag  # noqa: F401 — must load before setUp()'s db.create_all()


class TestKnowledgeModels(PortalTestCase):
    def test_create_article_with_tags(self):
        author = self.make_user("autor1")
        tag = KnowledgeTag(name="dns")
        article = KnowledgeArticle(
            title="Resolver DNS intermitente",
            problem_md="El **DNS** falla a veces.",
            solution_md="Reiniciar el servicio `named`.",
            client="Acme Corp",
            platform="BIND9",
            author=author,
        )
        article.tags.append(tag)
        db.session.add(article)
        db.session.commit()

        fetched = KnowledgeArticle.query.first()
        self.assertEqual(fetched.title, "Resolver DNS intermitente")
        self.assertEqual(fetched.author.username, "autor1")
        self.assertEqual([t.name for t in fetched.tags], ["dns"])
        self.assertIsNotNone(fetched.created_at)
        self.assertIsNotNone(fetched.updated_at)

    def test_article_requires_title_problem_solution(self):
        from sqlalchemy.exc import IntegrityError

        author = self.make_user("autor2")
        article = KnowledgeArticle(
            title=None,  # violates nullable=False
            problem_md="x",
            solution_md="y",
            author=author,
        )
        db.session.add(article)
        with self.assertRaises(IntegrityError):
            db.session.commit()
