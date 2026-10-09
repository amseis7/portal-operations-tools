from urllib.parse import urlparse, parse_qs
import re

from tests.base import PortalTestCase
from app.extensions import db
from app.models.knowledge import KnowledgeArticle  # noqa: F401


class TestKnowledgeListRoute(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.user = self.make_user("lector", tools=["knowledge_base"])
        self.login("lector")

    def _make_article(self, **overrides):
        defaults = dict(
            title="Artículo", problem_md="p", solution_md="s", author=self.user
        )
        defaults.update(overrides)
        article = KnowledgeArticle(**defaults)
        db.session.add(article)
        db.session.commit()
        return article

    def test_empty_state_renders(self):
        resp = self.client.get("/kb/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("No hay artículos".encode("utf-8"), resp.data)

    def test_search_literal_percent_is_not_a_wildcard(self):
        self._make_article(title="Ticket 50%_completado")
        self._make_article(title="Otro artículo totalmente distinto")

        resp = self.client.get("/kb/?q=50%25_completado")  # literal '%' and '_'

        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Ticket 50", resp.data)
        self.assertNotIn(b"Otro art\xc3\xadculo totalmente distinto", resp.data)

    def test_filter_by_client(self):
        self._make_article(title="Para Acme", client="Acme")
        self._make_article(title="Para Globex", client="Globex")

        resp = self.client.get("/kb/?client=Acme")

        self.assertIn(b"Para Acme", resp.data)
        self.assertNotIn(b"Para Globex", resp.data)

    def test_pagination_second_page(self):
        for i in range(25):
            self._make_article(title=f"Articulo {i}")

        page1 = self.client.get("/kb/")
        page2 = self.client.get("/kb/?page=2")

        self.assertEqual(page1.status_code, 200)
        self.assertEqual(page2.status_code, 200)
        self.assertNotEqual(page1.data, page2.data)

    def test_pagination_link_preserves_special_characters_in_query(self):
        for i in range(25):
            self._make_article(title=f"AT&T item {i}")

        resp = self.client.get("/kb/?q=AT%26T")
        body = resp.get_data(as_text=True)

        match = re.search(r'href="([^"]*page=2[^"]*)"', body)
        self.assertIsNotNone(match, "next-page link not found in rendered page")
        href = match.group(1).replace("&amp;", "&")
        parsed = parse_qs(urlparse(href).query)
        self.assertEqual(parsed.get("q"), ["AT&T"])
