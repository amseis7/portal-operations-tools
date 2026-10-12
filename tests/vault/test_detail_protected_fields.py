from unittest.mock import patch

from tests.base import PortalTestCase
from app.extensions import db
from app.vault.models import VaultEntry, VaultEntryField  # noqa: F401 — must load before setUp()'s db.create_all()
from app.vault.crypto import encrypt, decrypt as real_decrypt


class TestVaultDetailProtectedFields(PortalTestCase):
    """Debt #46: detail() must not decrypt protected custom fields at all —
    the template already ignores their plaintext (masks with a badge), so
    decrypting them only lets the plaintext live longer than needed in
    process memory/Jinja context for no rendering benefit."""

    def setUp(self):
        super().setUp()
        self.owner = self.make_user("vaultowner")
        self.login("vaultowner")

    def _make_entry(self, shared=False, **field_specs):
        """field_specs: field_key -> list of (value, is_protected) tuples,
        to support duplicate keys."""
        entry = VaultEntry(
            title="Entrada de prueba",
            category="server",
            username="svc",
            password_enc=encrypt("Synthetic-Entry-Password-1"),
            owner_id=self.owner.id,
            shared=shared,
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

    def test_protected_field_not_decrypted_and_not_leaked(self):
        entry = self._make_entry(apikey=[("super-secret-synthetic-value", True)])

        with patch("app.vault.routes.decrypt", side_effect=real_decrypt) as mock_decrypt:
            resp = self.client.get(f"/vault/{entry.id}")

        self.assertEqual(resp.status_code, 200)
        mock_decrypt.assert_not_called()
        self.assertNotIn(b"super-secret-synthetic-value", resp.data)

    def test_unprotected_field_still_decrypted_and_rendered(self):
        entry = self._make_entry(notes_field=[("plain-visible-value", False)])
        field = VaultEntryField.query.filter_by(entry_id=entry.id, field_key="notes_field").first()

        with patch("app.vault.routes.decrypt", side_effect=real_decrypt) as mock_decrypt:
            resp = self.client.get(f"/vault/{entry.id}")

        self.assertEqual(resp.status_code, 200)
        mock_decrypt.assert_called_once_with(field.field_value_enc)
        self.assertIn(b"plain-visible-value", resp.data)

    def test_mixed_protected_and_unprotected_only_decrypts_unprotected(self):
        entry = self._make_entry(
            apikey=[("hidden-secret-value", True)],
            notes_field=[("visible-plain-value", False)],
        )
        unprotected_field = VaultEntryField.query.filter_by(entry_id=entry.id, field_key="notes_field").first()

        with patch("app.vault.routes.decrypt", side_effect=real_decrypt) as mock_decrypt:
            resp = self.client.get(f"/vault/{entry.id}")

        self.assertEqual(resp.status_code, 200)
        mock_decrypt.assert_called_once_with(unprotected_field.field_value_enc)
        self.assertNotIn(b"hidden-secret-value", resp.data)
        self.assertIn(b"visible-plain-value", resp.data)

    def test_duplicate_field_key_protected_and_unprotected_not_confused(self):
        entry = self._make_entry(TOKEN=[
            ("duplicate-key-secret", True),
            ("duplicate-key-visible", False),
        ])

        resp = self.client.get(f"/vault/{entry.id}")

        self.assertEqual(resp.status_code, 200)
        self.assertNotIn(b"duplicate-key-secret", resp.data)
        self.assertIn(b"duplicate-key-visible", resp.data)

    def test_authorization_unchanged_non_owner_non_shared_gets_403(self):
        entry = self._make_entry(shared=False, apikey=[("secret-value", True)])
        self.make_user("other_user")
        self.login("other_user")

        resp = self.client.get(f"/vault/{entry.id}")

        self.assertEqual(resp.status_code, 403)

    def test_authorization_unchanged_shared_entry_still_viewable(self):
        entry = self._make_entry(shared=True, apikey=[("secret-value", True)])
        self.make_user("other_user")
        self.login("other_user")

        resp = self.client.get(f"/vault/{entry.id}")

        self.assertEqual(resp.status_code, 200)
