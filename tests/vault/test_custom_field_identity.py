"""Tests for the pure id-based diff/validate algorithm that replaces
_save_custom_fields()'s field_key-string-matching behavior (debt #38).

These tests call _diff_custom_fields()/_apply_custom_fields() directly
against in-memory VaultEntry/VaultEntryField rows — no HTTP layer, no
routes. HTTP-level and end-to-end tests live in
tests/vault/test_custom_field_protection.py.
"""
import json as json_mod

from tests.base import PortalTestCase
from app.extensions import db
from app.vault.models import VaultEntry, VaultEntryField  # noqa: F401 — must load before setUp()'s db.create_all()
from app.vault.crypto import encrypt, decrypt
from app.vault.routes import (
    CustomFieldConflict,
    _diff_custom_fields,
    _apply_custom_fields,
)


class TestDiffCustomFields(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.owner = self.make_user("vaultowner2")
        self.login("vaultowner2")

    def _make_entry(self, **field_specs):
        """field_specs: field_key -> list of (value, is_protected) tuples,
        to support duplicate keys. Mirrors the helper in
        test_custom_field_protection.py."""
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

    def _field(self, entry, key):
        """Return the single VaultEntryField for a non-duplicated key."""
        matches = [f for f in entry.custom_fields if f.field_key == key]
        self.assertEqual(len(matches), 1, f"expected exactly one {key!r} field")
        return matches[0]

    def _fields(self, entry, key):
        return sorted(
            (f for f in entry.custom_fields if f.field_key == key),
            key=lambda f: f.id,
        )

    # -- rename ------------------------------------------------------------

    def test_rename_with_blank_value_preserves_ciphertext_and_id(self):
        entry = self._make_entry(TOKEN=[("original-secret", True)])
        field = self._field(entry, "TOKEN")
        original_id = field.id

        payload = json_mod.dumps([
            {"id": field.id, "key": "TOKEN2", "value": "", "protected": True},
        ])
        updates, new_items, delete_ids = _diff_custom_fields(entry, payload)

        self.assertEqual(len(updates), 1)
        self.assertEqual(new_items, [])
        self.assertEqual(delete_ids, set())
        _apply_custom_fields(entry, updates, new_items, delete_ids)
        db.session.commit()

        renamed = db.session.get(VaultEntryField, original_id)
        self.assertEqual(renamed.id, original_id)
        self.assertEqual(renamed.field_key, "TOKEN2")
        self.assertEqual(decrypt(renamed.field_value_enc), "original-secret")

    # -- duplicate keys ------------------------------------------------------

    def test_duplicate_key_delete_one_by_id_preserves_survivors_own_secret(self):
        entry = self._make_entry(TOKEN=[
            ("first-secret", True),
            ("second-secret", True),
        ])
        first, second = self._fields(entry, "TOKEN")
        first_id, second_id = first.id, second.id

        # Delete `first` by omitting it; keep `second` blank (preserve).
        payload = json_mod.dumps([
            {"id": second_id, "key": "TOKEN", "value": "", "protected": True},
        ])
        updates, new_items, delete_ids = _diff_custom_fields(entry, payload)

        self.assertEqual(delete_ids, {first_id})
        self.assertEqual([u[0].id for u in updates], [second_id])
        _apply_custom_fields(entry, updates, new_items, delete_ids)
        db.session.commit()

        survivor = db.session.get(VaultEntryField, second_id)
        self.assertEqual(decrypt(survivor.field_value_enc), "second-secret")
        self.assertIsNone(VaultEntryField.query.filter_by(id=first_id).first())

    def test_duplicate_key_delete_the_other_one_preserves_the_other_secret(self):
        """Mirror of the above, deleting `second` instead — the survivor
        must be `first` with its OWN secret, not the deleted sibling's."""
        entry = self._make_entry(TOKEN=[
            ("first-secret", True),
            ("second-secret", True),
        ])
        first, second = self._fields(entry, "TOKEN")
        first_id, second_id = first.id, second.id

        payload = json_mod.dumps([
            {"id": first_id, "key": "TOKEN", "value": "", "protected": True},
        ])
        updates, new_items, delete_ids = _diff_custom_fields(entry, payload)

        self.assertEqual(delete_ids, {second_id})
        _apply_custom_fields(entry, updates, new_items, delete_ids)
        db.session.commit()

        survivor = db.session.get(VaultEntryField, first_id)
        self.assertEqual(decrypt(survivor.field_value_enc), "first-secret")
        self.assertIsNone(VaultEntryField.query.filter_by(id=second_id).first())

    # -- id validation: unknown / foreign -----------------------------------

    def test_unknown_id_raises_conflict(self):
        entry = self._make_entry(TOKEN=[("secret", True)])
        payload = json_mod.dumps([
            {"id": 999999, "key": "TOKEN", "value": "", "protected": True},
        ])
        with self.assertRaises(CustomFieldConflict):
            _diff_custom_fields(entry, payload)

    def test_foreign_entry_id_raises_conflict(self):
        entry_a = self._make_entry(TOKEN=[("a-secret", True)])
        entry_b = self._make_entry(OTHER=[("b-secret", True)])
        foreign_field = self._field(entry_b, "OTHER")

        payload = json_mod.dumps([
            {"id": foreign_field.id, "key": "TOKEN", "value": "", "protected": True},
        ])
        with self.assertRaises(CustomFieldConflict):
            _diff_custom_fields(entry_a, payload)

    # -- duplicate id in payload ---------------------------------------------

    def test_duplicate_id_in_payload_raises_conflict(self):
        entry = self._make_entry(TOKEN=[("secret", True)])
        field = self._field(entry, "TOKEN")
        payload = json_mod.dumps([
            {"id": field.id, "key": "TOKEN", "value": "", "protected": True},
            {"id": field.id, "key": "TOKEN", "value": "", "protected": True},
        ])
        with self.assertRaises(CustomFieldConflict):
            _diff_custom_fields(entry, payload)

    def test_duplicate_id_with_one_blank_key_still_raises_conflict(self):
        """Codex-identified smuggling case: a blank-key occurrence must not
        exempt its id from the duplicate check."""
        entry = self._make_entry(TOKEN=[("secret", True)])
        field = self._field(entry, "TOKEN")
        payload = json_mod.dumps([
            {"id": field.id, "key": "TOKEN", "value": "", "protected": True},
            {"id": field.id, "key": "", "value": "", "protected": True},
        ])
        with self.assertRaises(CustomFieldConflict):
            _diff_custom_fields(entry, payload)

    def test_foreign_id_with_blank_key_still_raises_conflict(self):
        """Codex-identified smuggling case: a blank key must not let a
        foreign id slip past ownership validation."""
        entry_a = self._make_entry(TOKEN=[("a-secret", True)])
        entry_b = self._make_entry(OTHER=[("b-secret", True)])
        foreign_field = self._field(entry_b, "OTHER")

        payload = json_mod.dumps([
            {"id": foreign_field.id, "key": "", "value": "", "protected": True},
        ])
        with self.assertRaises(CustomFieldConflict):
            _diff_custom_fields(entry_a, payload)

    # -- strict id type validation -------------------------------------------

    def test_boolean_id_raises_conflict(self):
        entry = self._make_entry(TOKEN=[("secret", True)])
        field = self._field(entry, "TOKEN")
        # If `id: True` were coerced instead of type-checked, and field.id
        # happened to be 1, this would silently resolve instead of failing.
        payload = json_mod.dumps([
            {"id": True, "key": "TOKEN", "value": "", "protected": True},
        ])
        with self.assertRaises(CustomFieldConflict):
            _diff_custom_fields(entry, payload)

    def test_float_id_raises_conflict(self):
        entry = self._make_entry(TOKEN=[("secret", True)])
        field = self._field(entry, "TOKEN")
        payload = json_mod.dumps([
            {"id": float(field.id) + 0.9, "key": "TOKEN", "value": "", "protected": True},
        ])
        with self.assertRaises(CustomFieldConflict):
            _diff_custom_fields(entry, payload)

    def test_string_id_raises_conflict(self):
        entry = self._make_entry(TOKEN=[("secret", True)])
        field = self._field(entry, "TOKEN")
        payload = json_mod.dumps([
            {"id": str(field.id), "key": "TOKEN", "value": "", "protected": True},
        ])
        with self.assertRaises(CustomFieldConflict):
            _diff_custom_fields(entry, payload)

    # -- malformed payload ----------------------------------------------------

    def test_malformed_json_raises_conflict(self):
        entry = self._make_entry(TOKEN=[("secret", True)])
        with self.assertRaises(CustomFieldConflict):
            _diff_custom_fields(entry, "{not valid json")

    def test_non_list_payload_raises_conflict(self):
        entry = self._make_entry(TOKEN=[("secret", True)])
        with self.assertRaises(CustomFieldConflict):
            _diff_custom_fields(entry, json_mod.dumps({"key": "TOKEN"}))

    def test_non_dict_item_raises_conflict(self):
        entry = self._make_entry(TOKEN=[("secret", True)])
        with self.assertRaises(CustomFieldConflict):
            _diff_custom_fields(entry, json_mod.dumps(["not-a-dict"]))

    # -- blank value semantics ------------------------------------------------

    def test_blank_value_on_previously_unprotected_field_wipes_it(self):
        entry = self._make_entry(NOTE=[("visible-value", False)])
        field = self._field(entry, "NOTE")
        payload = json_mod.dumps([
            {"id": field.id, "key": "NOTE", "value": "", "protected": False},
        ])
        updates, new_items, delete_ids = _diff_custom_fields(entry, payload)
        _apply_custom_fields(entry, updates, new_items, delete_ids)
        db.session.commit()

        updated = db.session.get(VaultEntryField, field.id)
        self.assertEqual(decrypt(updated.field_value_enc), "")

    # -- new items -------------------------------------------------------------

    def test_new_item_with_null_id_is_not_matched_against_existing_row(self):
        entry = self._make_entry(TOKEN=[("existing-secret", True)])
        field = self._field(entry, "TOKEN")
        payload = json_mod.dumps([
            {"id": field.id, "key": "TOKEN", "value": "", "protected": True},
            {"id": None, "key": "FRESH", "value": "brand-new-value", "protected": False},
        ])
        updates, new_items, delete_ids = _diff_custom_fields(entry, payload)

        self.assertEqual([u[0].id for u in updates], [field.id])
        self.assertEqual(new_items, [("FRESH", "brand-new-value", False)])
        self.assertEqual(delete_ids, set())

    # -- all-blank-key payload --------------------------------------------------

    def test_all_blank_key_payload_deletes_every_existing_field(self):
        """Documented intended behavior: a payload with no key and no id
        referencing any existing row results in every existing field being
        deleted (same end state as the old delete-recreate implementation
        for this input shape) — not a surprise, not a partial no-op."""
        entry = self._make_entry(
            TOKEN=[("secret-a", True)],
            NOTE=[("secret-b", False)],
        )
        existing_ids = {f.id for f in entry.custom_fields}
        payload = json_mod.dumps([
            {"id": None, "key": "", "value": "", "protected": False},
        ])
        updates, new_items, delete_ids = _diff_custom_fields(entry, payload)

        self.assertEqual(updates, [])
        self.assertEqual(new_items, [])
        self.assertEqual(delete_ids, existing_ids)
