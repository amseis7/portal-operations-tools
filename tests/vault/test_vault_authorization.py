"""Blueprint-level tool-authorization guard for Vault (GAP #1).

Mirrors tests/knowledge_base/test_authorization.py: a user without the
`vault` UserTool must be blocked by proteger_blueprint()'s before_request
hook before any route body (including ownership/share logic) ever runs.
Ownership/share/admin semantics themselves are already covered by
test_delete_authorization.py, test_edit_authorization.py, and
test_detail_protected_fields.py and are not re-tested here.
"""
from tests.base import PortalTestCase
from app.extensions import db
from app.vault.models import VaultEntry  # noqa: F401 — must load before setUp()'s db.create_all()
from app.vault.crypto import encrypt


class TestVaultBlueprintToolGuard(PortalTestCase):
    def _make_entry(self, owner_id, shared=False):
        entry = VaultEntry(
            title="Entrada de prueba",
            category="server",
            username="svc",
            password_enc=encrypt("Synthetic-Entry-Password-1"),
            owner_id=owner_id,
            shared=shared,
        )
        db.session.add(entry)
        db.session.commit()
        return entry

    def _csrf_from_profile(self):
        """CSRF tokens are session-bound, not route-bound — /auth/perfil is
        login-only (not gated by the vault tool), so a user without the
        vault tool can still fetch a valid token from it."""
        page = self.client.get("/auth/perfil")
        return self.extract_csrf(page.get_data(as_text=True))

    def _assert_blocked(self, resp):
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/dashboard", resp.headers.get("Location", ""))

    # -- no tool: blocked before any view logic runs -------------------------

    def test_user_without_tool_is_blocked_from_index(self):
        self.make_user("sintool_idx", tools=[])
        self.login("sintool_idx")

        resp = self.client.get("/vault/", follow_redirects=False)

        self._assert_blocked(resp)

    def test_user_without_tool_is_blocked_from_new_get(self):
        self.make_user("sintool_new", tools=[])
        self.login("sintool_new")

        resp = self.client.get("/vault/new", follow_redirects=False)

        self._assert_blocked(resp)

    def test_user_without_tool_is_blocked_from_detail_even_when_shared(self):
        owner = self.make_user("vaultowner_guard1", tools=["vault"])
        entry = self._make_entry(owner.id, shared=True)
        self.make_user("sintool_detail", tools=[])
        self.login("sintool_detail")

        resp = self.client.get(f"/vault/{entry.id}", follow_redirects=False)

        self._assert_blocked(resp)

    def test_user_without_tool_is_blocked_from_reveal_even_when_shared(self):
        owner = self.make_user("vaultowner_guard2", tools=["vault"])
        entry = self._make_entry(owner.id, shared=True)
        self.make_user("sintool_reveal", tools=[])
        self.login("sintool_reveal")
        token = self._csrf_from_profile()

        resp = self.client.post(
            f"/vault/{entry.id}/reveal",
            data={"csrf_token": token},
            follow_redirects=False,
        )

        self._assert_blocked(resp)

    def test_user_without_tool_is_blocked_from_edit_get(self):
        owner = self.make_user("vaultowner_guard3", tools=["vault"])
        entry = self._make_entry(owner.id, shared=False)
        self.make_user("sintool_edit", tools=[])
        self.login("sintool_edit")

        resp = self.client.get(f"/vault/{entry.id}/edit", follow_redirects=False)

        self._assert_blocked(resp)

    def test_user_without_tool_is_blocked_from_delete(self):
        owner = self.make_user("vaultowner_guard4", tools=["vault"])
        entry = self._make_entry(owner.id, shared=False)
        self.make_user("sintool_delete", tools=[])
        self.login("sintool_delete")
        token = self._csrf_from_profile()

        resp = self.client.post(
            f"/vault/{entry.id}/delete",
            data={"csrf_token": token},
            follow_redirects=False,
        )

        self._assert_blocked(resp)
        self.assertIsNotNone(db.session.get(VaultEntry, entry.id))

    def test_user_without_tool_is_blocked_from_group_new(self):
        self.make_user("sintool_group", tools=[])
        self.login("sintool_group")
        token = self._csrf_from_profile()

        resp = self.client.post(
            "/vault/grupos/nuevo",
            data={"name": "Grupo intento", "csrf_token": token},
            follow_redirects=False,
        )

        self._assert_blocked(resp)

    # -- with tool: existing behavior preserved -------------------------------

    def test_user_with_tool_can_reach_index(self):
        self.make_user("contool_idx", tools=["vault"])
        self.login("contool_idx")

        resp = self.client.get("/vault/")

        self.assertEqual(resp.status_code, 200)

    def test_user_with_tool_can_reach_detail_of_own_entry(self):
        owner = self.make_user("contool_detail", tools=["vault"])
        entry = self._make_entry(owner.id, shared=False)
        self.login("contool_detail")

        resp = self.client.get(f"/vault/{entry.id}")

        self.assertEqual(resp.status_code, 200)

    # -- admin: bypass preserved without an explicit UserTool row -----------

    def test_admin_can_reach_index_without_explicit_usertool(self):
        self.make_user("admin_guard_idx", is_admin=True)
        self.login("admin_guard_idx")

        resp = self.client.get("/vault/")

        self.assertEqual(resp.status_code, 200)

    def test_admin_can_reach_detail_of_others_entry_without_explicit_usertool(self):
        owner = self.make_user("vaultowner_guard5", tools=["vault"])
        entry = self._make_entry(owner.id, shared=False)
        self.make_user("admin_guard_detail", is_admin=True)
        self.login("admin_guard_detail")

        resp = self.client.get(f"/vault/{entry.id}")

        self.assertEqual(resp.status_code, 200)
