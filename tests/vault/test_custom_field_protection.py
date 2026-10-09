from tests.base import PortalTestCase
from app.extensions import db
from app.vault.models import VaultEntry, VaultEntryField  # noqa: F401 — must load before setUp()'s db.create_all()
from app.vault.crypto import encrypt, decrypt


class TestVaultCustomFieldProtection(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.owner = self.make_user("vaultowner")
        self.login("vaultowner")

    def _make_entry(self, **field_specs):
        """field_specs: field_key -> list of (value, is_protected) tuples,
        to support duplicate keys."""
        entry = VaultEntry(
            title="Entrada de prueba",
            category="server",
            username="svc",
            password_enc=encrypt("Synthetic-Entry-Password-1"),
            owner_id=self.owner.id,
        )
        db.session.add(entry)
        db.session.flush()
        for key, specs in field_specs.items():
            for value, protected in specs:
                db.session.add(VaultEntryField(
                    entry_id=entry.id,
                    field_key=key,
                    field_value_enc=encrypt(value),
                    is_protected=protected,
                ))
        db.session.commit()
        return entry

    def _edit_csrf(self, entry_id):
        page = self.client.get(f"/vault/{entry_id}/edit")
        return self.extract_csrf(page.get_data(as_text=True))

    def _post_edit(self, entry, token, custom_fields_json):
        import json as json_mod
        return self.client.post(
            f"/vault/{entry.id}/edit",
            data={
                "title": entry.title,
                "category": entry.category,
                "username": entry.username,
                "password": "",
                "csrf_token": token,
                "custom_fields_json": json_mod.dumps(custom_fields_json),
            },
            follow_redirects=True,
        )

    def test_protected_field_not_leaked_in_edit_get(self):
        entry = self._make_entry(apikey=[("super-secret-synthetic-value", True)])

        resp = self.client.get(f"/vault/{entry.id}/edit")

        self.assertNotIn(b"super-secret-synthetic-value", resp.data)

    def test_unprotected_field_still_visible_in_edit_get(self):
        entry = self._make_entry(notes_field=[("plain-visible-value", False)])

        resp = self.client.get(f"/vault/{entry.id}/edit")

        self.assertIn(b"plain-visible-value", resp.data)

    def test_blank_protected_field_preserves_existing_secret(self):
        entry = self._make_entry(apikey=[("original-secret-value", True)])
        token = self._edit_csrf(entry.id)

        self._post_edit(entry, token, [{"key": "apikey", "value": "", "protected": True}])

        field = VaultEntryField.query.filter_by(entry_id=entry.id, field_key="apikey").first()
        self.assertEqual(decrypt(field.field_value_enc), "original-secret-value")
        self.assertTrue(field.is_protected)

    def test_nonblank_protected_field_replaces_secret(self):
        entry = self._make_entry(apikey=[("original-secret-value", True)])
        token = self._edit_csrf(entry.id)

        self._post_edit(entry, token, [{"key": "apikey", "value": "brand-new-value", "protected": True}])

        field = VaultEntryField.query.filter_by(entry_id=entry.id, field_key="apikey").first()
        self.assertEqual(decrypt(field.field_value_enc), "brand-new-value")

    def test_unchecking_protected_with_blank_value_preserves_secret_and_clears_flag(self):
        entry = self._make_entry(apikey=[("original-secret-value", True)])
        token = self._edit_csrf(entry.id)

        # User unchecked "Protegido" in the UI: protected=False submitted, value still blank.
        self._post_edit(entry, token, [{"key": "apikey", "value": "", "protected": False}])

        field = VaultEntryField.query.filter_by(entry_id=entry.id, field_key="apikey").first()
        self.assertEqual(decrypt(field.field_value_enc), "original-secret-value")
        self.assertFalse(field.is_protected)

    def test_create_with_protected_field_persists_encrypted(self):
        token_page = self.client.get("/vault/new")
        token = self.extract_csrf(token_page.get_data(as_text=True))
        import json as json_mod

        self.client.post(
            "/vault/new",
            data={
                "title": "Nueva entrada",
                "category": "server",
                "username": "svc2",
                "password": "Synthetic-New-Entry-Password",
                "csrf_token": token,
                "custom_fields_json": json_mod.dumps(
                    [{"key": "apikey", "value": "fresh-secret", "protected": True}]
                ),
            },
            follow_redirects=True,
        )

        entry = VaultEntry.query.filter_by(title="Nueva entrada").first()
        self.assertIsNotNone(entry)
        field = VaultEntryField.query.filter_by(entry_id=entry.id, field_key="apikey").first()
        self.assertEqual(decrypt(field.field_value_enc), "fresh-secret")

    def test_duplicate_key_blank_submissions_preserve_each_original_independently(self):
        # No UNIQUE(entry_id, field_key) exists today — two protected fields
        # can legitimately share the same key.
        entry = self._make_entry(apikey=[
            ("first-secret-value", True),
            ("second-secret-value", True),
        ])
        token = self._edit_csrf(entry.id)

        self._post_edit(entry, token, [
            {"key": "apikey", "value": "", "protected": True},
            {"key": "apikey", "value": "", "protected": True},
        ])

        values = sorted(
            decrypt(f.field_value_enc)
            for f in VaultEntryField.query.filter_by(entry_id=entry.id, field_key="apikey").all()
        )
        self.assertEqual(values, ["first-secret-value", "second-secret-value"])
