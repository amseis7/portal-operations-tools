"""Technical debt #43: Vault Edit/Delete Authorization Duplicated Across
Templates. `_entry_permissions(entry)` is now the single presentation
source of truth for Editar/Eliminar button visibility in detail.html and
index.html — templates must consume it rather than re-deriving
`current_user.is_admin or entry.owner_id == current_user.id` inline.

This is presentation only: _can_edit()/_can_delete() remain the sole
backend authority (already covered by tests/vault/test_edit_authorization.py
and tests/vault/test_delete_authorization.py, unchanged by this refactor).
HTTP-level button-visibility regressions (owner/admin/hidden-for-shared-
viewer, in both detail.html and index.html) are already covered by
tests/vault/test_edit_button_visibility.py and
tests/vault/test_delete_authorization.py — not duplicated here.
"""
import re

from tests.base import PortalTestCase
from app.extensions import db
from app.vault.models import VaultEntry  # noqa: F401 — must load before setUp()'s db.create_all()
from app.vault.crypto import encrypt
from app.vault.routes import _entry_permissions


class TestEntryPermissionsHelper(PortalTestCase):
    """Direct unit tests of the pure presentation helper."""

    def setUp(self):
        super().setUp()
        self.owner = self.make_user("entryperm_owner", tools=["vault"])
        self.other = self.make_user("entryperm_other", tools=["vault"])
        self.admin = self.make_user("entryperm_admin", is_admin=True)
        self.entry = VaultEntry(
            title="Entrada de prueba",
            category="server",
            username="svc",
            password_enc=encrypt("Synthetic-Entry-Password-1"),
            owner_id=self.owner.id,
            shared=True,
        )
        db.session.add(self.entry)
        db.session.commit()

    def _perms_as(self, username):
        """_entry_permissions() reads current_user, which only resolves
        inside an active request context. `with self.client:` preserves
        the context of the request made inside the block (Flask/Werkzeug
        test-client idiom) so the helper can be called directly right
        after, the same way a route handler would call it."""
        self.login(username)
        with self.client:
            self.client.get("/vault/")
            return _entry_permissions(self.entry)

    def test_returns_dict_with_can_edit_and_can_delete_keys(self):
        perms = self._perms_as("entryperm_owner")
        self.assertEqual(set(perms.keys()), {"can_edit", "can_delete"})

    def test_owner_gets_true_for_both(self):
        perms = self._perms_as("entryperm_owner")
        self.assertTrue(perms["can_edit"])
        self.assertTrue(perms["can_delete"])

    def test_admin_gets_true_for_both_on_others_entry(self):
        perms = self._perms_as("entryperm_admin")
        self.assertTrue(perms["can_edit"])
        self.assertTrue(perms["can_delete"])

    def test_non_owner_shared_viewer_gets_false_for_both(self):
        """entry.shared == True grants view access but must not grant
        edit/delete — the exact regression ADR/debt #1 and #2 already
        guard at the backend; this confirms the presentation helper
        reflects the same rule, not a looser one."""
        perms = self._perms_as("entryperm_other")
        self.assertFalse(perms["can_edit"])
        self.assertFalse(perms["can_delete"])


class TestIndexEntryPermissionsPerRow(PortalTestCase):
    """The index() list builds entry_permissions keyed by entry.id — the
    real risk in that design is cross-row contamination (one entry's
    permissions leaking onto another's row), which a single-entry test
    cannot catch. This uses entries from two different owners, viewed by
    a third normal user who owns neither, to prove each row's permissions
    are independently correct."""

    def setUp(self):
        super().setUp()
        self.owner_a = self.make_user("entrypermrow_a", tools=["vault"])
        self.owner_b = self.make_user("entrypermrow_b", tools=["vault"])
        self.viewer = self.make_user("entrypermrow_viewer", tools=["vault"])

    def _entry(self, owner_id, shared, title):
        e = VaultEntry(
            title=title, category="server", username="svc",
            password_enc=encrypt("Synthetic-Entry-Password-1"),
            owner_id=owner_id, shared=shared,
        )
        db.session.add(e)
        db.session.commit()
        return e

    def test_viewers_own_entry_and_others_shared_entry_get_different_permissions_in_same_index_render(self):
        own = self._entry(self.viewer.id, shared=False, title="Viewer Own Entry")
        foreign_shared = self._entry(self.owner_a.id, shared=True, title="Foreign Shared Entry")
        self.login("entrypermrow_viewer")

        resp = self.client.get("/vault/")
        html = resp.get_data(as_text=True)

        self.assertIn(f'/vault/{own.id}/edit', html)
        self.assertNotIn(f'/vault/{foreign_shared.id}/edit', html)
        self.assertIn(f'data-entry-id="{own.id}"', html)
        self.assertNotIn(f'data-entry-id="{foreign_shared.id}"', html)


class TestNoDuplicatedAuthorizationExpressionInTemplates(PortalTestCase):
    """Structural check that the refactor actually removed the
    duplication debt #43 described — reads template SOURCE files
    directly (not rendered HTML), so this isn't a fragile full-page grep;
    it targets exactly the expression that used to be copy-pasted."""

    def test_detail_and_index_templates_no_longer_inline_the_expression(self):
        pattern = re.compile(r"current_user\.is_admin\s+or\s+entry\.owner_id\s*==\s*current_user\.id")
        for path in (
            "app/templates/vault/detail.html",
            "app/templates/vault/index.html",
        ):
            with open(path, encoding="utf-8") as f:
                source = f.read()
            self.assertNotRegex(
                source, pattern,
                f"{path} still inlines the duplicated can_edit/can_delete expression",
            )
