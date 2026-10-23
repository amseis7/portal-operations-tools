import re

from tests.base import PortalTestCase
from app.extensions import db
from app.models.knowledge import KnowledgeArticle  # noqa: F401


class TestMarkdownToolbarPresence(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.make_user("autor", tools=["knowledge_base"])
        self.login("autor")

    def _create_article(self):
        token = self.extract_csrf(self.client.get("/kb/nuevo").get_data(as_text=True))
        self.client.post(
            "/kb/nuevo",
            data={
                "title": "Articulo toolbar",
                "problem_md": "p",
                "solution_md": "s",
                "csrf_token": token,
            },
            follow_redirects=True,
        )
        return KnowledgeArticle.query.filter_by(title="Articulo toolbar").first()

    def test_create_form_has_single_toolbar_for_both_fields(self):
        resp = self.client.get("/kb/nuevo")
        html = resp.get_data(as_text=True)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(html.count('id="kb-markdown-toolbar"'), 1)
        self.assertIn('data-markdown-targets="problem_md,solution_md"', html)
        self.assertIn('id="kb-md-current-field-value"', html)
        self.assertIn(">Problema<", html)
        self.assertIn("kb-markdown-toolbar.js", html)

    def test_heading_levels_1_to_3_are_direct_buttons(self):
        html = self.client.get("/kb/nuevo").get_data(as_text=True)
        for level in (1, 2, 3):
            self.assertIn(f'data-md-action="heading" data-md-level="{level}"', html)

    def test_heading_levels_4_to_6_available_in_dropdown(self):
        html = self.client.get("/kb/nuevo").get_data(as_text=True)
        self.assertIn("Más títulos", html)
        for level in (4, 5, 6):
            self.assertIn(f'data-md-action="heading" data-md-level="{level}"', html)

    def test_edit_form_has_single_toolbar_for_both_fields(self):
        article = self._create_article()
        resp = self.client.get(f"/kb/{article.id}/editar")
        html = resp.get_data(as_text=True)
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(html.count('id="kb-markdown-toolbar"'), 1)
        self.assertIn('data-markdown-targets="problem_md,solution_md"', html)

    def test_all_toolbar_buttons_are_type_button(self):
        html = self.client.get("/kb/nuevo").get_data(as_text=True)
        buttons = re.findall(r'<button[^>]*class="[^"]*kb-md-btn[^"]*"[^>]*>', html)
        self.assertTrue(buttons, "expected at least one kb-md-btn button")
        for b in buttons:
            self.assertIn('type="button"', b)

    def test_no_image_button_offered(self):
        # img[src] only survives sanitization for /kb/attachments/<id>/view —
        # a hand-typed image button would produce markup that never renders.
        html = self.client.get("/kb/nuevo").get_data(as_text=True)
        self.assertNotIn('data-md-action="image"', html)

    def test_original_create_post_still_works(self):
        token = self.extract_csrf(self.client.get("/kb/nuevo").get_data(as_text=True))
        resp = self.client.post(
            "/kb/nuevo",
            data={
                "title": "T",
                "problem_md": "p",
                "solution_md": "s",
                "platform": "",
                "tags_raw": "",
                "csrf_token": token,
            },
            follow_redirects=False,
        )
        self.assertEqual(resp.status_code, 302)
