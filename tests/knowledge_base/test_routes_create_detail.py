from tests.base import PortalTestCase
from app.models.knowledge import KnowledgeArticle  # noqa: F401
from app.models.audit import AuditLog  # noqa: F401


class TestCreateAndDetail(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.make_user("creador", tools=["knowledge_base"])
        self.login("creador")

    def _csrf_get(self, url):
        page = self.client.get(url)
        return self.extract_csrf(page.get_data(as_text=True))

    def test_create_article_persists_and_audits(self):
        token = self._csrf_get("/kb/nuevo")

        resp = self.client.post(
            "/kb/nuevo",
            data={
                "title": "Nuevo artículo",
                "problem_md": "Problema **grave**",
                "solution_md": "Reiniciar servicio",
                "client": "Acme",
                "platform": "Linux",
                "tags_raw": "linux, servicios",
                "csrf_token": token,
            },
            follow_redirects=True,
        )

        self.assertEqual(resp.status_code, 200)
        article = KnowledgeArticle.query.filter_by(title="Nuevo artículo").first()
        self.assertIsNotNone(article)
        self.assertEqual(sorted(t.name for t in article.tags), ["linux", "servicios"])

        audit = AuditLog.query.filter_by(module="knowledge_base", action="create").first()
        self.assertIsNotNone(audit)
        self.assertEqual(audit.object_name, "Nuevo artículo")

    def test_create_strips_whitespace_from_client_and_platform(self):
        token = self._csrf_get("/kb/nuevo")

        self.client.post(
            "/kb/nuevo",
            data={
                "title": "Con espacios",
                "problem_md": "p",
                "solution_md": "s",
                "client": " Acme ",
                "platform": " Linux ",
                "csrf_token": token,
            },
            follow_redirects=True,
        )

        article = KnowledgeArticle.query.filter_by(title="Con espacios").first()
        self.assertEqual(article.client, "Acme")
        self.assertEqual(article.platform, "Linux")

        # the index route's exact-match filter must actually find it
        resp = self.client.get("/kb/?client=Acme")
        self.assertIn(b"Con espacios", resp.data)

    def test_create_missing_title_shows_validation_error(self):
        token = self._csrf_get("/kb/nuevo")

        resp = self.client.post(
            "/kb/nuevo",
            data={"problem_md": "p", "solution_md": "s", "csrf_token": token},
        )

        self.assertEqual(resp.status_code, 200)  # re-renders form, does not redirect
        self.assertEqual(KnowledgeArticle.query.count(), 0)

    def test_detail_renders_sanitized_markdown(self):
        token = self._csrf_get("/kb/nuevo")
        self.client.post(
            "/kb/nuevo",
            data={
                "title": "Con XSS",
                "problem_md": "before <script>alert(1)</script> after",
                "solution_md": "**ok**",
                "csrf_token": token,
            },
            follow_redirects=True,
        )
        article = KnowledgeArticle.query.filter_by(title="Con XSS").first()

        resp = self.client.get(f"/kb/{article.id}")

        self.assertEqual(resp.status_code, 200)
        # The page legitimately includes <script src="...bootstrap...">;
        # what must never survive is the bare, attribute-less injected tag.
        self.assertNotIn(b"<script>", resp.data)
        self.assertIn(b"<strong>ok</strong>", resp.data)
