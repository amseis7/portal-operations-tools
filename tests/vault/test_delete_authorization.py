from tests.base import PortalTestCase
from app.extensions import db
from app.vault.models import VaultEntry, VaultEntryField  # noqa: F401
from app.vault.crypto import encrypt
from app.models.audit import AuditLog


class TestVaultDeleteAuthorization(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.owner = self.make_user("owner_user")

    def _make_entry(self, shared, with_custom_field=False):
        entry = VaultEntry(
            title="Entrada original",
            category="server",
            username="svc",
            password_enc=encrypt("Synthetic-Entry-Password-1"),
            owner_id=self.owner.id,
            shared=shared,
        )
        db.session.add(entry)
        db.session.flush()
        if with_custom_field:
            db.session.add(VaultEntryField(
                entry_id=entry.id,
                field_key="apikey",
                field_value_enc=encrypt("synthetic-field-value"),
                is_protected=True,
            ))
        db.session.commit()
        return entry

    def _csrf_token(self):
        page = self.client.get("/vault/")
        return self.extract_csrf(page.get_data(as_text=True))

    def _post_delete(self, entry, token):
        return self.client.post(
            f"/vault/{entry.id}/delete",
            data={"csrf_token": token},
        )

    # 1. owner can delete own entry
    def test_owner_can_delete_own_entry(self):
        entry = self._make_entry(shared=False)
        self.login("owner_user")
        token = self._csrf_token()

        resp = self._post_delete(entry, token)

        self.assertEqual(resp.status_code, 302)
        self.assertIsNone(db.session.get(VaultEntry, entry.id))

    # 2. admin can delete any entry
    def test_admin_can_delete_any_entry(self):
        entry = self._make_entry(shared=False)
        self.make_user("admin_user", is_admin=True)
        self.login("admin_user")
        token = self._csrf_token()

        resp = self._post_delete(entry, token)

        self.assertEqual(resp.status_code, 302)
        self.assertIsNone(db.session.get(VaultEntry, entry.id))

    # 3. non-owner, shared=False -> 403, entry remains
    def test_non_owner_non_shared_gets_403_and_entry_remains(self):
        entry = self._make_entry(shared=False)
        self.make_user("other_user")
        self.login("other_user")
        token = self._csrf_token()

        resp = self._post_delete(entry, token)

        self.assertEqual(resp.status_code, 403)
        self.assertIsNotNone(db.session.get(VaultEntry, entry.id))

    # 4. non-owner, shared=True -> 403, entry remains (shared != delete)
    def test_non_owner_shared_gets_403_and_entry_remains(self):
        entry = self._make_entry(shared=True)
        self.make_user("other_user")
        self.login("other_user")
        token = self._csrf_token()

        resp = self._post_delete(entry, token)

        self.assertEqual(resp.status_code, 403)
        self.assertIsNotNone(db.session.get(VaultEntry, entry.id))

    # 5. authorized delete cascades to VaultEntryField
    def test_authorized_delete_cascades_custom_fields(self):
        entry = self._make_entry(shared=False, with_custom_field=True)
        entry_id = entry.id
        self.assertEqual(VaultEntryField.query.filter_by(entry_id=entry_id).count(), 1)
        self.login("owner_user")
        token = self._csrf_token()

        self._post_delete(entry, token)

        self.assertIsNone(db.session.get(VaultEntry, entry_id))
        self.assertEqual(VaultEntryField.query.filter_by(entry_id=entry_id).count(), 0)

    # 6. unauthorized attempt produces no AuditLog(action="delete") for that entry
    def test_unauthorized_attempt_does_not_create_delete_audit_log(self):
        entry = self._make_entry(shared=True)
        entry_id = entry.id
        self.make_user("other_user")
        self.login("other_user")
        token = self._csrf_token()

        self._post_delete(entry, token)

        audit = AuditLog.query.filter_by(
            module="vault", action="delete", object_id=str(entry_id)
        ).first()
        self.assertIsNone(audit)

    # 7. "Eliminar" button visibility in detail.html
    def test_delete_button_visible_for_owner_in_detail(self):
        entry = self._make_entry(shared=False)
        self.login("owner_user")
        resp = self.client.get(f"/vault/{entry.id}")
        self.assertIn(f'/vault/{entry.id}/delete'.encode(), resp.data)

    def test_delete_button_visible_for_admin_in_detail(self):
        entry = self._make_entry(shared=False)
        self.make_user("admin_user", is_admin=True)
        self.login("admin_user")
        resp = self.client.get(f"/vault/{entry.id}")
        self.assertIn(f'/vault/{entry.id}/delete'.encode(), resp.data)

    def test_delete_button_hidden_for_non_owner_shared_viewer_in_detail(self):
        entry = self._make_entry(shared=True)
        self.make_user("other_user")
        self.login("other_user")
        resp = self.client.get(f"/vault/{entry.id}")
        self.assertEqual(resp.status_code, 200)  # still viewable
        self.assertNotIn(f'/vault/{entry.id}/delete'.encode(), resp.data)

    # 8. "Eliminar" button visibility in index.html
    # The per-row delete trigger has no literal /delete URL in the HTML (its
    # action is built in JS from data-entry-id), so presence of that
    # attribute is what indicates the button itself was rendered.
    def test_delete_button_visible_for_owner_in_index(self):
        entry = self._make_entry(shared=False)
        self.login("owner_user")
        resp = self.client.get("/vault/")
        self.assertIn(f'data-entry-id="{entry.id}"'.encode(), resp.data)

    def test_delete_button_hidden_for_non_owner_shared_viewer_in_index(self):
        entry = self._make_entry(shared=True)
        self.make_user("other_user")
        self.login("other_user")
        resp = self.client.get("/vault/")
        self.assertIn(b"Entrada original", resp.data)  # still listed
        self.assertNotIn(f'data-entry-id="{entry.id}"'.encode(), resp.data)
