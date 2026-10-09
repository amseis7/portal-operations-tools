from tests.base import PortalTestCase
from app.extensions import db
from app.vault.models import VaultEntry  # noqa: F401
from app.vault.crypto import encrypt


class TestVaultEditButtonVisibility(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.owner = self.make_user("owner_user")
        self.entry = VaultEntry(
            title="Entrada compartida",
            category="server",
            username="svc",
            password_enc=encrypt("Synthetic-Entry-Password-1"),
            owner_id=self.owner.id,
            shared=True,
        )
        db.session.add(self.entry)
        db.session.commit()

    def _edit_href(self):
        return f"/vault/{self.entry.id}/edit".encode()

    # detail.html
    def test_detail_shows_edit_button_for_owner(self):
        self.login("owner_user")
        resp = self.client.get(f"/vault/{self.entry.id}")
        self.assertIn(self._edit_href(), resp.data)

    def test_detail_shows_edit_button_for_admin(self):
        self.make_user("admin_user", is_admin=True)
        self.login("admin_user")
        resp = self.client.get(f"/vault/{self.entry.id}")
        self.assertIn(self._edit_href(), resp.data)

    def test_detail_hides_edit_button_for_non_owner_shared_viewer(self):
        self.make_user("other_user")
        self.login("other_user")
        resp = self.client.get(f"/vault/{self.entry.id}")
        self.assertEqual(resp.status_code, 200)  # can still view (shared=True)
        self.assertNotIn(self._edit_href(), resp.data)

    # index.html
    def test_index_shows_edit_button_for_owner(self):
        self.login("owner_user")
        resp = self.client.get("/vault/")
        self.assertIn(self._edit_href(), resp.data)

    def test_index_hides_edit_button_for_non_owner_shared_viewer(self):
        self.make_user("other_user")
        self.login("other_user")
        resp = self.client.get("/vault/")
        self.assertIn(b"Entrada compartida", resp.data)  # still listed (shared=True)
        self.assertNotIn(self._edit_href(), resp.data)
