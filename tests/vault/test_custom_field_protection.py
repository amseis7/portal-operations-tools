import json as json_mod
import re

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

    def _field_id(self, entry, key):
        """Fetch the real id of a single non-duplicated field by key —
        used to build id-aware payloads the way the real page's JS would,
        without re-deriving it from a fresh query each time."""
        field = VaultEntryField.query.filter_by(entry_id=entry.id, field_key=key).first()
        self.assertIsNotNone(field, f"expected a {key!r} field to exist")
        return field.id

    def _edit_csrf(self, entry_id):
        page = self.client.get(f"/vault/{entry_id}/edit")
        return self.extract_csrf(page.get_data(as_text=True))

    def _rendered_fields(self, entry_id):
        """GET the real edit page and parse the actual `id`/`key`/`value`/
        `protected` JSON the server embedded for the JS to consume — proves
        the template round-trips real ids, rather than assuming the DB
        values the test already knows about."""
        page = self.client.get(f"/vault/{entry_id}/edit")
        html = page.get_data(as_text=True)
        match = re.search(r"var fields = (\[.*?\]);", html, re.DOTALL)
        self.assertIsNotNone(match, "could not find the embedded `fields` JSON in the edit page")
        return json_mod.loads(match.group(1))

    def _post_edit(self, entry, token, custom_fields_json, **extra_form):
        data = {
            "title": entry.title,
            "category": entry.category,
            "username": entry.username,
            "password": "",
            "csrf_token": token,
            "custom_fields_json": json_mod.dumps(custom_fields_json),
        }
        data.update(extra_form)
        return self.client.post(
            f"/vault/{entry.id}/edit",
            data=data,
            follow_redirects=False,
        )

    def _post_new(self, token, custom_fields_json, title="Nueva entrada"):
        return self.client.post(
            "/vault/new",
            data={
                "title": title,
                "category": "server",
                "username": "svc2",
                "password": "Synthetic-New-Entry-Password",
                "csrf_token": token,
                "custom_fields_json": json_mod.dumps(custom_fields_json),
            },
            follow_redirects=False,
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
        field_id = self._field_id(entry, "apikey")
        token = self._edit_csrf(entry.id)

        self._post_edit(entry, token, [{"id": field_id, "key": "apikey", "value": "", "protected": True}])

        field = VaultEntryField.query.filter_by(entry_id=entry.id, field_key="apikey").first()
        self.assertEqual(decrypt(field.field_value_enc), "original-secret-value")
        self.assertTrue(field.is_protected)
        self.assertEqual(field.id, field_id)

    def test_nonblank_protected_field_replaces_secret(self):
        entry = self._make_entry(apikey=[("original-secret-value", True)])
        field_id = self._field_id(entry, "apikey")
        token = self._edit_csrf(entry.id)

        self._post_edit(entry, token, [{"id": field_id, "key": "apikey", "value": "brand-new-value", "protected": True}])

        field = VaultEntryField.query.filter_by(entry_id=entry.id, field_key="apikey").first()
        self.assertEqual(decrypt(field.field_value_enc), "brand-new-value")

    def test_unchecking_protected_with_blank_value_preserves_secret_and_clears_flag(self):
        entry = self._make_entry(apikey=[("original-secret-value", True)])
        field_id = self._field_id(entry, "apikey")
        token = self._edit_csrf(entry.id)

        # User unchecked "Protegido" in the UI: protected=False submitted, value still blank.
        self._post_edit(entry, token, [{"id": field_id, "key": "apikey", "value": "", "protected": False}])

        field = VaultEntryField.query.filter_by(entry_id=entry.id, field_key="apikey").first()
        self.assertEqual(decrypt(field.field_value_enc), "original-secret-value")
        self.assertFalse(field.is_protected)

    def test_create_with_protected_field_persists_encrypted(self):
        token_page = self.client.get("/vault/new")
        token = self.extract_csrf(token_page.get_data(as_text=True))

        self._post_new(token, [{"key": "apikey", "value": "fresh-secret", "protected": True}])

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
        first_id, second_id = sorted(
            f.id for f in VaultEntryField.query.filter_by(entry_id=entry.id, field_key="apikey").all()
        )
        token = self._edit_csrf(entry.id)

        self._post_edit(entry, token, [
            {"id": first_id, "key": "apikey", "value": "", "protected": True},
            {"id": second_id, "key": "apikey", "value": "", "protected": True},
        ])

        # Assert the id -> ciphertext mapping, not a sorted-value-set
        # comparison — a set comparison cannot detect two siblings' values
        # being swapped between rows.
        first = db.session.get(VaultEntryField, first_id)
        second = db.session.get(VaultEntryField, second_id)
        self.assertEqual(decrypt(first.field_value_enc), "first-secret-value")
        self.assertEqual(decrypt(second.field_value_enc), "second-secret-value")

    # -- id stability (Codex finding #6: the property that distinguishes ----
    # -- this fix from the old delete-recreate implementation) --------------

    def test_normal_save_leaves_untouched_field_ids_unchanged(self):
        entry = self._make_entry(apikey=[("secret-value", True)])
        field_id = self._field_id(entry, "apikey")
        token = self._edit_csrf(entry.id)

        self._post_edit(entry, token, [{"id": field_id, "key": "apikey", "value": "", "protected": True}])

        field = VaultEntryField.query.filter_by(entry_id=entry.id, field_key="apikey").first()
        self.assertEqual(field.id, field_id)

    # -- foreign/unknown/duplicate id -> fail closed (409) -------------------

    def test_foreign_id_via_new_is_rejected_with_409_and_nothing_persisted(self):
        other_owner = self.make_user("otherowner")
        other_entry = VaultEntry(
            title="Otra entrada", category="server", username="other",
            password_enc=encrypt("Synthetic-Other-Password"), owner_id=other_owner.id,
        )
        db.session.add(other_entry)
        db.session.flush()
        foreign_field = VaultEntryField(
            entry_id=other_entry.id, field_key="secret", field_value_enc=encrypt("other-secret"), is_protected=True,
        )
        db.session.add(foreign_field)
        db.session.commit()
        foreign_field_id = foreign_field.id

        token_page = self.client.get("/vault/new")
        token = self.extract_csrf(token_page.get_data(as_text=True))

        resp = self._post_new(
            token,
            [{"id": foreign_field_id, "key": "apikey", "value": "", "protected": True}],
            title="Entrada maliciosa",
        )

        self.assertEqual(resp.status_code, 409)
        self.assertIsNone(VaultEntry.query.filter_by(title="Entrada maliciosa").first())
        # The foreign field itself must remain untouched.
        untouched = db.session.get(VaultEntryField, foreign_field_id)
        self.assertEqual(decrypt(untouched.field_value_enc), "other-secret")

    def test_stale_id_is_rejected_with_409(self):
        entry = self._make_entry(apikey=[("secret-value", True)])
        field_id = self._field_id(entry, "apikey")
        token = self._edit_csrf(entry.id)

        # Simulate a concurrent deletion between page load and submit.
        VaultEntryField.query.filter_by(id=field_id).delete()
        db.session.commit()

        resp = self._post_edit(entry, token, [{"id": field_id, "key": "apikey", "value": "", "protected": True}])

        self.assertEqual(resp.status_code, 409)

    def test_duplicate_id_in_edit_payload_is_rejected_with_409(self):
        entry = self._make_entry(apikey=[("secret-value", True)])
        field_id = self._field_id(entry, "apikey")
        token = self._edit_csrf(entry.id)

        resp = self._post_edit(entry, token, [
            {"id": field_id, "key": "apikey", "value": "new-1", "protected": True},
            {"id": field_id, "key": "apikey", "value": "new-2", "protected": True},
        ])

        self.assertEqual(resp.status_code, 409)
        field = VaultEntryField.query.filter_by(entry_id=entry.id, field_key="apikey").first()
        self.assertEqual(decrypt(field.field_value_enc), "secret-value")

    # -- atomicity / partial-apply --------------------------------------------

    def test_conflict_rolls_back_entry_attribute_changes_too(self):
        """A bogus id in the payload must not let the entry's own fields
        (title, etc.) silently persist while the custom field is rejected —
        the whole request is one atomic unit."""
        entry = self._make_entry(apikey=[("secret-value", True)])
        field_id = self._field_id(entry, "apikey")
        original_title = entry.title
        token = self._edit_csrf(entry.id)

        resp = self._post_edit(
            entry, token,
            [
                {"id": field_id, "key": "apikey", "value": "", "protected": True},
                {"id": 999999, "key": "bogus", "value": "x", "protected": False},
            ],
            title="Title Changed By Attacker Request",
        )

        self.assertEqual(resp.status_code, 409)
        refreshed = db.session.get(VaultEntry, entry.id)
        self.assertEqual(refreshed.title, original_title)
        field = VaultEntryField.query.filter_by(entry_id=entry.id, field_key="apikey").first()
        self.assertEqual(decrypt(field.field_value_enc), "secret-value")

    # -- delete semantics -------------------------------------------------------

    def test_empty_submission_deletes_all_custom_fields(self):
        entry = self._make_entry(
            apikey=[("secret-a", True)],
            note=[("secret-b", False)],
        )
        token = self._edit_csrf(entry.id)

        self._post_edit(entry, token, [])

        self.assertEqual(VaultEntryField.query.filter_by(entry_id=entry.id).count(), 0)

    # -- end-to-end reproductions of the /investigate findings, using ids -----
    # -- actually read off the rendered page (not just known from the DB) -----

    def test_end_to_end_rename_with_blank_value_preserves_secret(self):
        """Investigation Case A."""
        entry = self._make_entry(TOKEN=[("original-secret", True)])
        rendered = self._rendered_fields(entry.id)
        self.assertEqual(len(rendered), 1)
        field_id = rendered[0]["id"]
        token = self._edit_csrf(entry.id)

        self._post_edit(entry, token, [{"id": field_id, "key": "TOKEN2", "value": "", "protected": True}])

        field = VaultEntryField.query.filter_by(entry_id=entry.id, field_key="TOKEN2").first()
        self.assertIsNotNone(field)
        self.assertEqual(decrypt(field.field_value_enc), "original-secret")

    def test_end_to_end_duplicate_key_delete_older_keep_newer(self):
        """Investigation Case B, deleting the older occurrence."""
        entry = self._make_entry(TOKEN=[("first-secret", True), ("second-secret", True)])
        rendered = sorted(self._rendered_fields(entry.id), key=lambda f: f["id"])
        older_id, newer_id = rendered[0]["id"], rendered[1]["id"]
        token = self._edit_csrf(entry.id)

        self._post_edit(entry, token, [{"id": newer_id, "key": "TOKEN", "value": "", "protected": True}])

        survivor = VaultEntryField.query.filter_by(entry_id=entry.id, field_key="TOKEN").first()
        self.assertEqual(survivor.id, newer_id)
        self.assertEqual(decrypt(survivor.field_value_enc), "second-secret")
        self.assertIsNone(VaultEntryField.query.filter_by(id=older_id).first())

    def test_end_to_end_duplicate_key_delete_newer_keep_older(self):
        """Investigation Case B, deleting the newer occurrence (the
        direction most likely to expose a FIFO-order bug if one remained)."""
        entry = self._make_entry(TOKEN=[("first-secret", True), ("second-secret", True)])
        rendered = sorted(self._rendered_fields(entry.id), key=lambda f: f["id"])
        older_id, newer_id = rendered[0]["id"], rendered[1]["id"]
        token = self._edit_csrf(entry.id)

        self._post_edit(entry, token, [{"id": older_id, "key": "TOKEN", "value": "", "protected": True}])

        survivor = VaultEntryField.query.filter_by(entry_id=entry.id, field_key="TOKEN").first()
        self.assertEqual(survivor.id, older_id)
        self.assertEqual(decrypt(survivor.field_value_enc), "first-secret")
        self.assertIsNone(VaultEntryField.query.filter_by(id=newer_id).first())

    def test_end_to_end_duplicate_key_plus_new_same_key_field(self):
        """Investigation Case C: an untouched existing field keeps its
        ciphertext while a brand-new field with the same key gets its own
        fresh value — no FIFO queue stealing between them."""
        entry = self._make_entry(TOKEN=[("existing-secret", True)])
        rendered = self._rendered_fields(entry.id)
        existing_id = rendered[0]["id"]
        token = self._edit_csrf(entry.id)

        self._post_edit(entry, token, [
            {"id": existing_id, "key": "TOKEN", "value": "", "protected": True},
            {"id": None, "key": "TOKEN", "value": "fresh-new-secret", "protected": True},
        ])

        rows = VaultEntryField.query.filter_by(entry_id=entry.id, field_key="TOKEN").all()
        self.assertEqual(len(rows), 2)
        by_id = {r.id: decrypt(r.field_value_enc) for r in rows}
        self.assertEqual(by_id[existing_id], "existing-secret")
        new_row_id = next(rid for rid in by_id if rid != existing_id)
        self.assertEqual(by_id[new_row_id], "fresh-new-secret")

    def test_end_to_end_combined_rename_duplicate_delete_and_add(self):
        """The original /investigate ask's "full combo" case: rename +
        duplicate keys + delete + an add-after-delete in one submission."""
        entry = self._make_entry(
            TOKEN=[("token-a", True), ("token-b", True)],
            STABLE=[("stable-secret", True)],
        )
        rendered = self._rendered_fields(entry.id)
        token_ids = sorted(f["id"] for f in rendered if f["key"] == "TOKEN")
        stable_id = next(f["id"] for f in rendered if f["key"] == "STABLE")
        keep_token_id, deleted_token_id = token_ids[0], token_ids[1]
        token = self._edit_csrf(entry.id)

        self._post_edit(entry, token, [
            # Keep one TOKEN row, but rename it, blank value (preserve + rename).
            {"id": keep_token_id, "key": "TOKEN-RENAMED", "value": "", "protected": True},
            # The other TOKEN row is simply omitted -> deleted.
            # STABLE stays, untouched, same key, blank value (preserve).
            {"id": stable_id, "key": "STABLE", "value": "", "protected": True},
            # A brand new field added in the same submission.
            {"id": None, "key": "NEW", "value": "brand-new", "protected": False},
        ])

        remaining = {f.id: f for f in VaultEntryField.query.filter_by(entry_id=entry.id).all()}
        self.assertEqual(len(remaining), 3)
        self.assertNotIn(deleted_token_id, remaining)
        self.assertEqual(remaining[keep_token_id].field_key, "TOKEN-RENAMED")
        self.assertEqual(decrypt(remaining[keep_token_id].field_value_enc), "token-a" if keep_token_id == token_ids[0] else "token-b")
        self.assertEqual(decrypt(remaining[stable_id].field_value_enc), "stable-secret")
        new_row = next(f for f in remaining.values() if f.field_key == "NEW")
        self.assertEqual(decrypt(new_row.field_value_enc), "brand-new")

    # -- 409 response shape -------------------------------------------------------

    def test_409_response_has_correct_status_and_message_no_partial_persistence(self):
        entry = self._make_entry(apikey=[("secret-value", True)])
        token = self._edit_csrf(entry.id)

        resp = self._post_edit(entry, token, [{"id": 999999, "key": "bogus", "value": "x", "protected": False}])

        self.assertEqual(resp.status_code, 409)
        self.assertIn("cambiaron", resp.get_data(as_text=True))
        field = VaultEntryField.query.filter_by(entry_id=entry.id, field_key="apikey").first()
        self.assertEqual(decrypt(field.field_value_enc), "secret-value")
