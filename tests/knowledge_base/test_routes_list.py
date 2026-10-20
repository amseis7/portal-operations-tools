from urllib.parse import urlparse, parse_qs
import re

from tests.base import PortalTestCase
from app.extensions import db
from app.models.knowledge import KnowledgeArticle  # noqa: F401


class TestKnowledgeBrandGrid(PortalTestCase):
    """/kb is the brand grid now — no flat article list here."""

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
        self.assertIn("Todavía no hay artículos".encode("utf-8"), resp.data)

    def test_index_shows_brand_cards_not_flat_article_list(self):
        self._make_article(title="Falla de autenticación SSO", platform="Microsoft 365")
        self._make_article(title="Timeout de VPN", platform="Fortinet")

        resp = self.client.get("/kb/")

        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Microsoft 365", resp.data)
        self.assertIn(b"Fortinet", resp.data)
        # Article titles themselves must not leak into the grid view.
        self.assertNotIn("Falla de autenticación SSO".encode("utf-8"), resp.data)
        self.assertNotIn(b"Timeout de VPN", resp.data)

    def test_brand_card_shows_article_count_without_n_plus_1(self):
        from sqlalchemy import event

        self._make_article(title="A1", platform="Fortinet")
        self._make_article(title="A2", platform="Fortinet")
        self._make_article(title="B1", platform="Cisco")

        queries = []
        def _count(conn, cursor, statement, *a, **kw):
            queries.append(statement)
        event.listen(db.engine, "before_cursor_execute", _count)
        try:
            resp = self.client.get("/kb/")
        finally:
            event.remove(db.engine, "before_cursor_execute", _count)

        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"2 art\xc3\xadculos", resp.data)  # Fortinet
        self.assertIn(b"1 art\xc3\xadculo<", resp.data)  # Cisco, singular
        # One grouped query for named-brand counts + one count query for the
        # "Sin marca" bucket — never one query per card (no N+1), regardless
        # of how many brands exist. Scoped to knowledge_article specifically
        # since the request also runs unrelated queries (user loader, tool
        # check, notification badge) that aren't part of this claim.
        kb_queries = [q for q in queries if "knowledge_article" in q]
        self.assertEqual(len(kb_queries), 2)

    def test_sin_marca_card_shown_when_unbranded_articles_exist(self):
        self._make_article(title="Sin marca asignada")  # platform left None

        resp = self.client.get("/kb/")

        self.assertEqual(resp.status_code, 200)
        self.assertIn("Sin marca".encode("utf-8"), resp.data)

    def test_sin_marca_card_absent_when_no_unbranded_articles(self):
        self._make_article(title="Con marca", platform="Fortinet")

        resp = self.client.get("/kb/")

        self.assertEqual(resp.status_code, 200)
        self.assertNotIn("Sin marca".encode("utf-8"), resp.data)


class TestKnowledgeBrandArticles(PortalTestCase):
    """/kb/brand/<platform> and /kb/sin-marca."""

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

    def test_brand_page_shows_only_its_own_articles(self):
        self._make_article(title="Para Fortinet", platform="Fortinet")
        self._make_article(title="Para Cisco", platform="Cisco")

        resp = self.client.get("/kb/brand/Fortinet")

        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Para Fortinet", resp.data)
        self.assertNotIn(b"Para Cisco", resp.data)

    def test_other_brand_does_not_see_first_brands_articles(self):
        self._make_article(title="Para Fortinet", platform="Fortinet")
        self._make_article(title="Para Cisco", platform="Cisco")

        resp = self.client.get("/kb/brand/Cisco")

        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Para Cisco", resp.data)
        self.assertNotIn(b"Para Fortinet", resp.data)

    def test_unknown_brand_is_404(self):
        self._make_article(title="Para Fortinet", platform="Fortinet")

        resp = self.client.get("/kb/brand/NoExiste")

        self.assertEqual(resp.status_code, 404)

    def test_sin_marca_shows_only_unbranded_articles(self):
        self._make_article(title="Sin marca 1")  # platform=None
        self._make_article(title="Con marca", platform="Fortinet")

        resp = self.client.get("/kb/sin-marca")

        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Sin marca 1", resp.data)
        self.assertNotIn(b"Con marca", resp.data)

    def test_sin_marca_includes_empty_string_platform(self):
        self._make_article(title="Plataforma vacía", platform="")

        resp = self.client.get("/kb/sin-marca")

        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Plataforma vac\xc3\xada", resp.data)

    def test_search_within_brand_literal_percent_is_not_a_wildcard(self):
        self._make_article(title="Ticket 50%_completado", platform="Fortinet")
        self._make_article(title="Otro artículo totalmente distinto", platform="Fortinet")

        resp = self.client.get("/kb/brand/Fortinet?q=50%25_completado")  # literal '%' and '_'

        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Ticket 50", resp.data)
        self.assertNotIn(b"Otro art\xc3\xadculo totalmente distinto", resp.data)

    def test_search_within_brand_does_not_leak_other_brands(self):
        self._make_article(title="Incidente de red", platform="Fortinet")
        self._make_article(title="Incidente de correo", platform="Cisco")

        resp = self.client.get("/kb/brand/Fortinet?q=Incidente")

        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Incidente de red", resp.data)
        self.assertNotIn(b"Incidente de correo", resp.data)

    def test_pagination_second_page_within_brand(self):
        for i in range(25):
            self._make_article(title=f"Articulo {i}", platform="Fortinet")

        page1 = self.client.get("/kb/brand/Fortinet")
        page2 = self.client.get("/kb/brand/Fortinet?page=2")

        self.assertEqual(page1.status_code, 200)
        self.assertEqual(page2.status_code, 200)
        self.assertNotEqual(page1.data, page2.data)

    def test_pagination_second_page_within_sin_marca(self):
        for i in range(25):
            self._make_article(title=f"Articulo {i}")

        page1 = self.client.get("/kb/sin-marca")
        page2 = self.client.get("/kb/sin-marca?page=2")

        self.assertEqual(page1.status_code, 200)
        self.assertEqual(page2.status_code, 200)
        self.assertNotEqual(page1.data, page2.data)

    def test_pagination_link_preserves_special_characters_in_query(self):
        for i in range(25):
            self._make_article(title=f"AT&T item {i}", platform="Fortinet")

        resp = self.client.get("/kb/brand/Fortinet?q=AT%26T")
        body = resp.get_data(as_text=True)

        match = re.search(r'href="([^"]*page=2[^"]*)"', body)
        self.assertIsNotNone(match, "next-page link not found in rendered page")
        href = match.group(1).replace("&amp;", "&")
        parsed = parse_qs(urlparse(href).query)
        self.assertEqual(parsed.get("q"), ["AT&T"])
