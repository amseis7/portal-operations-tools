from tests.base import PortalTestCase
from app.extensions import db
from app.models.knowledge import KnowledgeArticle  # noqa: F401


class TestEditDeleteAuthorization(PortalTestCase):
    def _create_article_as(self, username):
        token = self.extract_csrf(self.client.get("/kb/nuevo").get_data(as_text=True))
        self.client.post(
            "/kb/nuevo",
            data={
                "title": f"Articulo de {username}",
                "problem_md": "p",
                "solution_md": "s",
                "csrf_token": token,
            },
            follow_redirects=True,
        )
        return KnowledgeArticle.query.filter_by(title=f"Articulo de {username}").first()

    def test_author_can_edit_own_article(self):
        self.make_user("autorA", tools=["knowledge_base"])
        self.login("autorA")
        article = self._create_article_as("autorA")

        token = self.extract_csrf(
            self.client.get(f"/kb/{article.id}/editar").get_data(as_text=True)
        )
        resp = self.client.post(
            f"/kb/{article.id}/editar",
            data={
                "title": "Titulo editado",
                "problem_md": "p2",
                "solution_md": "s2",
                "csrf_token": token,
            },
            follow_redirects=True,
        )

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(db.session.get(KnowledgeArticle, article.id).title, "Titulo editado")

    def test_edit_strips_whitespace_from_client_and_platform(self):
        self.make_user("autorF", tools=["knowledge_base"])
        self.login("autorF")
        article = self._create_article_as("autorF")

        token = self.extract_csrf(
            self.client.get(f"/kb/{article.id}/editar").get_data(as_text=True)
        )
        self.client.post(
            f"/kb/{article.id}/editar",
            data={
                "title": article.title,
                "problem_md": "p",
                "solution_md": "s",
                "client": " Acme ",
                "platform": " Linux ",
                "csrf_token": token,
            },
            follow_redirects=True,
        )

        updated = db.session.get(KnowledgeArticle, article.id)
        self.assertEqual(updated.client, "Acme")
        self.assertEqual(updated.platform, "Linux")

    def test_non_author_non_admin_cannot_edit(self):
        self.make_user("autorB", tools=["knowledge_base"])
        self.login("autorB")
        article = self._create_article_as("autorB")

        self.make_user("otroUsuario", tools=["knowledge_base"])
        login_resp = self.login("otroUsuario")  # follow_redirects=True lands on /dashboard
        token = self.extract_csrf(login_resp.get_data(as_text=True))

        resp_get = self.client.get(f"/kb/{article.id}/editar")
        self.assertEqual(resp_get.status_code, 403)

        # A valid CSRF token is included so this exercises the application's
        # own authorization check (403), not an unrelated CSRF rejection (400).
        resp_post = self.client.post(
            f"/kb/{article.id}/editar",
            data={"title": "hackeado", "problem_md": "x", "solution_md": "y", "csrf_token": token},
        )
        self.assertEqual(resp_post.status_code, 403)
        self.assertEqual(
            db.session.get(KnowledgeArticle, article.id).title, "Articulo de autorB"
        )

    def test_admin_can_edit_any_article(self):
        self.make_user("autorC", tools=["knowledge_base"])
        self.login("autorC")
        article = self._create_article_as("autorC")

        self.make_user("admin2", is_admin=True)
        self.login("admin2")

        token = self.extract_csrf(
            self.client.get(f"/kb/{article.id}/editar").get_data(as_text=True)
        )
        resp = self.client.post(
            f"/kb/{article.id}/editar",
            data={
                "title": "Editado por admin",
                "problem_md": "p",
                "solution_md": "s",
                "csrf_token": token,
            },
            follow_redirects=True,
        )

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(
            db.session.get(KnowledgeArticle, article.id).title, "Editado por admin"
        )

    def test_author_cannot_delete_own_article(self):
        self.make_user("autorD", tools=["knowledge_base"])
        self.login("autorD")
        article = self._create_article_as("autorD")
        token = self.extract_csrf(
            self.client.get(f"/kb/{article.id}").get_data(as_text=True)
        )

        resp = self.client.post(
            f"/kb/{article.id}/eliminar", data={"csrf_token": token}
        )

        self.assertEqual(resp.status_code, 403)
        self.assertIsNotNone(db.session.get(KnowledgeArticle, article.id))

    def test_admin_can_delete_any_article(self):
        self.make_user("autorE", tools=["knowledge_base"])
        self.login("autorE")
        article = self._create_article_as("autorE")
        article_id = article.id

        self.make_user("admin3", is_admin=True)
        self.login("admin3")
        token = self.extract_csrf(
            self.client.get(f"/kb/{article_id}").get_data(as_text=True)
        )

        resp = self.client.post(
            f"/kb/{article_id}/eliminar",
            data={"csrf_token": token},
            follow_redirects=True,
        )

        self.assertEqual(resp.status_code, 200)
        self.assertIsNone(db.session.get(KnowledgeArticle, article_id))
