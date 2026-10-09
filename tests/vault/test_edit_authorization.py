from tests.base import PortalTestCase
from app.extensions import db
from app.vault.models import VaultEntry  # noqa: F401 — must load before setUp()'s db.create_all()
from app.vault.crypto import encrypt


class TestVaultEditAuthorization(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.owner = self.make_user("owner_user")

    def _make_entry(self, shared):
        entry = VaultEntry(
            title="Entrada original",
            category="server",
            username="svc",
            password_enc=encrypt("Synthetic-Entry-Password-1"),
            owner_id=self.owner.id,
            shared=shared,
        )
        db.session.add(entry)
        db.session.commit()
        return entry

    def _csrf_token(self):
        page = self.client.get("/vault/")
        return self.extract_csrf(page.get_data(as_text=True))

    def _post_edit(self, entry, token, title="Título modificado"):
        return self.client.post(
            f"/vault/{entry.id}/edit",
            data={
                "title": title,
                "category": entry.category,
                "username": entry.username,
                "password": "",
                "shared": "y" if entry.shared else "",
                "csrf_token": token,
                "custom_fields_json": "[]",
            },
        )

    # 1. owner can GET/POST edit
    def test_owner_can_get_and_post_edit(self):
        entry = self._make_entry(shared=False)
        self.login("owner_user")

        resp_get = self.client.get(f"/vault/{entry.id}/edit")
        self.assertEqual(resp_get.status_code, 200)

        token = self._csrf_token()
        resp_post = self._post_edit(entry, token)
        self.assertEqual(resp_post.status_code, 302)  # redirect to detail on success

    # 2. admin can GET/POST edit
    def test_admin_can_get_and_post_edit(self):
        entry = self._make_entry(shared=False)
        self.make_user("admin_user", is_admin=True)
        self.login("admin_user")

        resp_get = self.client.get(f"/vault/{entry.id}/edit")
        self.assertEqual(resp_get.status_code, 200)

        token = self._csrf_token()
        resp_post = self._post_edit(entry, token)
        self.assertEqual(resp_post.status_code, 302)

    # 3. non-owner, shared=False -> 403 on GET and POST
    def test_non_owner_non_shared_gets_403_on_get_and_post(self):
        entry = self._make_entry(shared=False)
        self.make_user("other_user")
        self.login("other_user")

        resp_get = self.client.get(f"/vault/{entry.id}/edit")
        self.assertEqual(resp_get.status_code, 403)

        token = self._csrf_token()
        resp_post = self._post_edit(entry, token)
        self.assertEqual(resp_post.status_code, 403)

    # 4. non-owner, shared=True -> 403 on GET and POST (shared visibility != edit permission)
    def test_non_owner_shared_gets_403_on_get_and_post(self):
        entry = self._make_entry(shared=True)
        self.make_user("other_user")
        self.login("other_user")

        resp_get = self.client.get(f"/vault/{entry.id}/edit")
        self.assertEqual(resp_get.status_code, 403)

        token = self._csrf_token()
        resp_post = self._post_edit(entry, token)
        self.assertEqual(resp_post.status_code, 403)

    # 5. authorized POST persists changes
    def test_authorized_post_persists_changes(self):
        entry = self._make_entry(shared=False)
        self.login("owner_user")
        token = self._csrf_token()

        self._post_edit(entry, token, title="Título modificado")

        updated = db.session.get(VaultEntry, entry.id)
        self.assertEqual(updated.title, "Título modificado")

    # 6. unauthorized POST does not modify the entry
    def test_unauthorized_post_does_not_modify_entry(self):
        entry = self._make_entry(shared=True)
        self.make_user("other_user")
        self.login("other_user")
        token = self._csrf_token()

        self._post_edit(entry, token, title="Intento de modificación")

        unchanged = db.session.get(VaultEntry, entry.id)
        self.assertEqual(unchanged.title, "Entrada original")
