"""Brand names are free text (KnowledgeArticle.platform) — this exercises
navigation for plausible-but-awkward values via url_for() (never a hand-built
path string), confirming the grid link actually round-trips to the article
list for that brand, plus the security properties that must hold regardless
of which URL converter is used:

- unknown brand -> 404 (no separate Brand table; existence = "some article
  uses this exact value")
- the lookup is still a parameterized SQLAlchemy exact-match filter
- `platform` is never used as a filesystem path (no path traversal surface)
"""
from flask import url_for

from tests.base import PortalTestCase
from app.extensions import db
from app.models.knowledge import KnowledgeArticle  # noqa: F401


class TestBrandRoutingSpecialCharacters(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.user = self.make_user("lector", tools=["knowledge_base"])
        self.login("lector")

    def _make_article(self, **overrides):
        defaults = dict(title="Artículo", problem_md="p", solution_md="s", author=self.user)
        defaults.update(overrides)
        article = KnowledgeArticle(**defaults)
        db.session.add(article)
        db.session.commit()
        return article

    def _brand_url(self, platform):
        with self.app.test_request_context():
            return url_for("knowledge_base.brand_articles", platform=platform)

    def test_brand_with_slash_opens_from_generated_url(self):
        brand = "Fortinet/FortiGate"
        self._make_article(title="Guía FortiGate", platform=brand)

        url = self._brand_url(brand)
        resp = self.client.get(url)

        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Gu\xc3\xada FortiGate", resp.data)

    def test_brand_with_slash_and_spaces_opens_from_generated_url(self):
        brand = "Microsoft / Office 365"
        self._make_article(title="Licenciamiento O365", platform=brand)

        url = self._brand_url(brand)
        resp = self.client.get(url)

        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Licenciamiento O365", resp.data)

    def test_brand_with_ampersand_opens_from_generated_url(self):
        brand = "AT&T"
        self._make_article(title="Incidente de enlace", platform=brand)

        url = self._brand_url(brand)
        resp = self.client.get(url)

        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Incidente de enlace", resp.data)

    def test_brand_with_spaces_opens_from_generated_url(self):
        brand = "Marca con espacios"
        self._make_article(title="Procedimiento genérico", platform=brand)

        url = self._brand_url(brand)
        resp = self.client.get(url)

        self.assertEqual(resp.status_code, 200)
        self.assertIn("Procedimiento genérico".encode("utf-8"), resp.data)

    def test_brand_with_unicode_opens_from_generated_url(self):
        brand = "Información Técnica 日本語"
        self._make_article(title="Soporte en japonés", platform=brand)

        url = self._brand_url(brand)
        resp = self.client.get(url)

        self.assertEqual(resp.status_code, 200)
        self.assertIn("Soporte en japonés".encode("utf-8"), resp.data)

    def test_grid_card_links_to_working_brand_page(self):
        brand = "Fortinet/FortiGate"
        self._make_article(title="Guía FortiGate", platform=brand)

        grid_resp = self.client.get("/kb/")
        body = grid_resp.get_data(as_text=True)

        expected_href = self._brand_url(brand)
        self.assertIn(expected_href, body, "grid card href does not match url_for()-generated link")

        follow_resp = self.client.get(expected_href)
        self.assertEqual(follow_resp.status_code, 200)
        self.assertIn(b"Gu\xc3\xada FortiGate", follow_resp.data)

    def test_unknown_brand_with_slash_is_404(self):
        self._make_article(title="Otro", platform="Cisco")

        url = self._brand_url("Fortinet/NoExiste")
        resp = self.client.get(url)

        self.assertEqual(resp.status_code, 404)

    def test_lookup_is_exact_match_not_prefix_or_substring(self):
        self._make_article(title="Solo Fortinet", platform="Fortinet")
        self._make_article(title="Fortinet y algo más", platform="Fortinet/FortiGate")

        resp = self.client.get(self._brand_url("Fortinet"))

        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Solo Fortinet", resp.data)
        self.assertNotIn("Fortinet y algo m\xc3\xa1s".encode("utf-8"), resp.data)

    def test_platform_value_is_not_used_as_filesystem_path(self):
        """A path-traversal-shaped value must behave exactly like any other
        unmatched string: a normal parameterized DB lookup, 404 if no
        article has that literal platform — never filesystem access."""
        traversal_like = "../../../etc/passwd"

        resp = self.client.get(self._brand_url(traversal_like))
        self.assertEqual(resp.status_code, 404)

        # And when an article genuinely has that literal (unlikely but
        # legal free-text) value, it is served as ordinary data, not
        # interpreted as a path.
        self._make_article(title="Valor literal raro", platform=traversal_like)
        resp2 = self.client.get(self._brand_url(traversal_like))
        self.assertEqual(resp2.status_code, 200)
        self.assertIn(b"Valor literal raro", resp2.data)

    def test_sin_marca_route_unaffected_by_brand_converter_change(self):
        self._make_article(title="Sin marca aquí")  # platform=None

        resp = self.client.get("/kb/sin-marca")

        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Sin marca aqu\xc3\xad", resp.data)
