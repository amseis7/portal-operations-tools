from tests.base import PortalTestCase


class TestKnowledgeArticleForm(PortalTestCase):
    def test_valid_data_passes(self):
        from app.knowledge_base.forms import KnowledgeArticleForm

        with self.app.test_request_context(
            "/kb/nuevo",
            method="POST",
            data={
                "title": "Título",
                "problem_md": "Problema",
                "solution_md": "Solución",
                "client": "Acme",
                "platform": "BIND9",
                "tags_raw": "dns, windows",
            },
        ):
            form = KnowledgeArticleForm(meta={"csrf": False})
            self.assertTrue(form.validate())

    def test_missing_required_fields_fails(self):
        from app.knowledge_base.forms import KnowledgeArticleForm

        with self.app.test_request_context("/kb/nuevo", method="POST", data={}):
            form = KnowledgeArticleForm(meta={"csrf": False})
            self.assertFalse(form.validate())
            self.assertIn("title", form.errors)
            self.assertIn("problem_md", form.errors)
            self.assertIn("solution_md", form.errors)
