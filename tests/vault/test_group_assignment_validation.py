"""ADR-005 Fase 2: server-side validation that a VaultEntry's group_id is
compatible with its shared flag and its REAL owner_id — never current_user,
because admin can edit other users' entries and the relevant identity for
personal-group compatibility is always the entry's own owner, not the actor.

    shared == True  => group is None or group.scope == "shared"
    shared == False => group is None or (group.scope == "personal"
                                           and group.owner_id == entry.owner_id)

Security must not depend on the dropdown only offering compatible options —
every test here manipulates group_id directly via POST, the way a tampered
client would.
"""
import json as json_mod

from sqlalchemy.exc import IntegrityError

from tests.base import PortalTestCase
from app.extensions import db
from app.vault.models import VaultEntry, VaultGroup  # noqa: F401 — must load before setUp()'s db.create_all()
from app.vault.crypto import encrypt
from app.vault.routes import VaultGroupAssignmentConflict, _validate_group_assignment


class TestValidateGroupAssignment(PortalTestCase):
    """Direct unit tests of the pure validation helper."""

    def setUp(self):
        super().setUp()
        self.user_a = self.make_user("groupuser_a")
        self.admin = self.make_user("groupadmin", is_admin=True)

    def _shared_group(self, name="Servidores"):
        g = VaultGroup(name=name, scope="shared")
        db.session.add(g)
        db.session.commit()
        return g

    def _personal_group(self, owner_id, name="Mis accesos"):
        g = VaultGroup(name=name, scope="personal", owner_id=owner_id)
        db.session.add(g)
        db.session.commit()
        return g

    # -- shared=True ----------------------------------------------------

    def test_shared_with_no_group_is_valid(self):
        result = _validate_group_assignment(self.user_a.id, True, None)
        self.assertIsNone(result)

    def test_shared_with_shared_group_is_valid(self):
        group = self._shared_group()
        result = _validate_group_assignment(self.user_a.id, True, group.id)
        self.assertEqual(result.id, group.id)

    def test_shared_with_personal_group_is_rejected(self):
        group = self._personal_group(self.user_a.id)
        with self.assertRaises(VaultGroupAssignmentConflict):
            _validate_group_assignment(self.user_a.id, True, group.id)

    # -- shared=False (personal) -----------------------------------------

    def test_personal_with_no_group_is_valid(self):
        result = _validate_group_assignment(self.user_a.id, False, None)
        self.assertIsNone(result)

    def test_personal_with_own_personal_group_is_valid(self):
        group = self._personal_group(self.user_a.id)
        result = _validate_group_assignment(self.user_a.id, False, group.id)
        self.assertEqual(result.id, group.id)

    def test_personal_with_shared_group_is_rejected(self):
        group = self._shared_group()
        with self.assertRaises(VaultGroupAssignmentConflict):
            _validate_group_assignment(self.user_a.id, False, group.id)

    def test_personal_with_other_owners_personal_group_is_rejected(self):
        other = self.make_user("groupuser_b")
        group = self._personal_group(other.id)
        with self.assertRaises(VaultGroupAssignmentConflict):
            _validate_group_assignment(self.user_a.id, False, group.id)

    # -- nonexistent id ----------------------------------------------------

    def test_nonexistent_group_id_is_rejected(self):
        with self.assertRaises(VaultGroupAssignmentConflict):
            _validate_group_assignment(self.user_a.id, False, 999999)

    def test_group_id_zero_is_rejected_not_treated_as_no_group(self):
        """The helper's "no group" case must be group_id is None
        specifically — 0 is a falsy int but not a real "blank" value, and
        must fail closed like any other nonexistent id, independent of
        whatever WTForms/SelectField does at the route layer."""
        with self.assertRaises(VaultGroupAssignmentConflict):
            _validate_group_assignment(self.user_a.id, False, 0)

    # -- actor (admin) must never substitute for the entry's real owner ----

    def test_entry_owner_a_actor_admin_personal_group_owned_by_admin_is_rejected(self):
        """The entry being validated belongs to user_a; an admin is the one
        editing it. The admin's OWN personal group must still be rejected
        — only group ownership by the ENTRY's owner (user_a) matters."""
        admin_personal_group = self._personal_group(self.admin.id)
        with self.assertRaises(VaultGroupAssignmentConflict):
            _validate_group_assignment(self.user_a.id, False, admin_personal_group.id)

    def test_entry_owner_a_personal_group_owned_by_a_is_valid_regardless_of_actor(self):
        """Mirror of the above: user_a's own personal group is valid when
        validating user_a's entry — the helper doesn't take an "actor" at
        all, by design, which is itself the point being tested here."""
        group = self._personal_group(self.user_a.id)
        result = _validate_group_assignment(self.user_a.id, False, group.id)
        self.assertEqual(result.id, group.id)


class TestVaultGroupAssignmentRoutes(PortalTestCase):
    """HTTP-level tests for new()/edit() — every group_id here is sent
    directly via POST, the way a tampered client would, never relying on
    what the (still unfiltered, Phase-3 concern) dropdown happens to
    offer."""

    def setUp(self):
        super().setUp()
        self.owner = self.make_user("rtgroupowner", tools=["vault"])
        self.other = self.make_user("rtgroupother", tools=["vault"])
        self.login("rtgroupowner")

    def _shared_group(self, name="Servidores"):
        g = VaultGroup(name=name, scope="shared")
        db.session.add(g)
        db.session.commit()
        return g

    def _personal_group(self, owner_id, name="Mis accesos"):
        g = VaultGroup(name=name, scope="personal", owner_id=owner_id)
        db.session.add(g)
        db.session.commit()
        return g

    def _make_entry(self, owner_id, shared, group_id=None, title="Entrada de prueba"):
        entry = VaultEntry(
            title=title,
            category="server",
            username="svc",
            password_enc=encrypt("Synthetic-Entry-Password-1"),
            owner_id=owner_id,
            shared=shared,
            group_id=group_id,
        )
        db.session.add(entry)
        db.session.commit()
        return entry

    def _csrf(self, url):
        page = self.client.get(url)
        return self.extract_csrf(page.get_data(as_text=True))

    def _post_new(self, shared, group_id, title="Nueva entrada"):
        token = self._csrf("/vault/new")
        data = {
            "title": title,
            "category": "server",
            "username": "svc",
            "password": "Synthetic-New-Password-1",
            "group_id": str(group_id) if group_id else "",
            "csrf_token": token,
            "custom_fields_json": "[]",
        }
        if shared:
            data["shared"] = "y"
        return self.client.post("/vault/new", data=data, follow_redirects=False)

    def _post_edit(self, entry, shared, group_id, title=None):
        token = self._csrf(f"/vault/{entry.id}/edit")
        data = {
            "title": title if title is not None else entry.title,
            "category": entry.category,
            "username": entry.username,
            "password": "",
            "group_id": str(group_id) if group_id else "",
            "csrf_token": token,
            "custom_fields_json": "[]",
        }
        if shared:
            data["shared"] = "y"
        return self.client.post(f"/vault/{entry.id}/edit", data=data, follow_redirects=False)

    # -- new() ----------------------------------------------------------

    def test_new_shared_entry_in_shared_group_succeeds(self):
        group = self._shared_group()
        resp = self._post_new(shared=True, group_id=group.id, title="Shared OK")

        self.assertEqual(resp.status_code, 302)
        entry = VaultEntry.query.filter_by(title="Shared OK").first()
        self.assertIsNotNone(entry)
        self.assertTrue(entry.shared)
        self.assertEqual(entry.group_id, group.id)

    def test_new_shared_entry_in_personal_group_is_rejected(self):
        own_personal = self._personal_group(self.owner.id)
        resp = self._post_new(shared=True, group_id=own_personal.id, title="Shared Bad")

        self.assertEqual(resp.status_code, 409)
        self.assertIsNone(VaultEntry.query.filter_by(title="Shared Bad").first())

    def test_new_personal_entry_in_own_personal_group_succeeds(self):
        group = self._personal_group(self.owner.id)
        resp = self._post_new(shared=False, group_id=group.id, title="Personal OK")

        self.assertEqual(resp.status_code, 302)
        entry = VaultEntry.query.filter_by(title="Personal OK").first()
        self.assertIsNotNone(entry)
        self.assertFalse(entry.shared)
        self.assertEqual(entry.group_id, group.id)

    def test_new_personal_entry_in_shared_group_is_rejected(self):
        group = self._shared_group()
        resp = self._post_new(shared=False, group_id=group.id, title="Personal Bad")

        self.assertEqual(resp.status_code, 409)
        self.assertIsNone(VaultEntry.query.filter_by(title="Personal Bad").first())

    def test_new_personal_entry_with_manipulated_other_users_group_is_rejected(self):
        """The dropdown would never offer this — sent directly via POST,
        exactly as a tampered client would."""
        foreign_group = self._personal_group(self.other.id)
        resp = self._post_new(shared=False, group_id=foreign_group.id, title="Manipulated")

        self.assertEqual(resp.status_code, 409)
        self.assertIsNone(VaultEntry.query.filter_by(title="Manipulated").first())

    def test_new_rejected_attempts_never_persist_any_entry(self):
        before = VaultEntry.query.count()
        shared_group = self._shared_group()
        personal_group = self._personal_group(self.owner.id)

        self._post_new(shared=True, group_id=personal_group.id, title="X1")
        self._post_new(shared=False, group_id=shared_group.id, title="X2")
        self._post_new(shared=False, group_id=999999, title="X3")

        self.assertEqual(VaultEntry.query.count(), before)

    # -- edit() -----------------------------------------------------------

    def test_edit_personal_entry_keeps_owners_personal_group_succeeds(self):
        group = self._personal_group(self.owner.id)
        entry = self._make_entry(self.owner.id, shared=False, group_id=group.id)

        resp = self._post_edit(entry, shared=False, group_id=group.id, title="Renamed")

        self.assertEqual(resp.status_code, 302)
        db.session.refresh(entry)
        self.assertEqual(entry.title, "Renamed")
        self.assertEqual(entry.group_id, group.id)

    def test_admin_editing_others_personal_entry_keeps_owners_group_succeeds(self):
        group = self._personal_group(self.owner.id)
        entry = self._make_entry(self.owner.id, shared=False, group_id=group.id)
        self.make_user("rtgroupadmin", is_admin=True)
        self.login("rtgroupadmin")

        resp = self._post_edit(entry, shared=False, group_id=group.id, title="Admin edit OK")

        self.assertEqual(resp.status_code, 302)
        db.session.refresh(entry)
        self.assertEqual(entry.title, "Admin edit OK")
        self.assertEqual(entry.group_id, group.id)

    def test_admin_cannot_switch_others_entry_to_admins_own_personal_group(self):
        owner_group = self._personal_group(self.owner.id)
        entry = self._make_entry(self.owner.id, shared=False, group_id=owner_group.id)
        admin = self.make_user("rtgroupadmin2", is_admin=True)
        admin_group = self._personal_group(admin.id)
        self.login("rtgroupadmin2")

        resp = self._post_edit(entry, shared=False, group_id=admin_group.id, title="Should not apply")

        self.assertEqual(resp.status_code, 409)
        db.session.refresh(entry)
        self.assertEqual(entry.group_id, owner_group.id)
        self.assertNotEqual(entry.title, "Should not apply")

    def test_edit_shared_to_personal_while_keeping_shared_group_is_rejected(self):
        shared_group = self._shared_group()
        entry = self._make_entry(self.owner.id, shared=True, group_id=shared_group.id)

        resp = self._post_edit(entry, shared=False, group_id=shared_group.id, title="Should not apply")

        self.assertEqual(resp.status_code, 409)
        db.session.refresh(entry)
        self.assertTrue(entry.shared)
        self.assertEqual(entry.group_id, shared_group.id)
        self.assertNotEqual(entry.title, "Should not apply")

    def test_edit_personal_to_shared_while_keeping_personal_group_is_rejected(self):
        personal_group = self._personal_group(self.owner.id)
        entry = self._make_entry(self.owner.id, shared=False, group_id=personal_group.id)

        resp = self._post_edit(entry, shared=True, group_id=personal_group.id, title="Should not apply")

        self.assertEqual(resp.status_code, 409)
        db.session.refresh(entry)
        self.assertFalse(entry.shared)
        self.assertEqual(entry.group_id, personal_group.id)
        self.assertNotEqual(entry.title, "Should not apply")

    def test_edit_with_nonexistent_group_id_is_rejected(self):
        """A group_id with no matching VaultGroup row at all is caught by
        the form's own SelectField choice validation before it ever
        reaches _validate_group_assignment() — a different layer than the
        409 path used for a real-but-incompatible group (see
        test_admin_cannot_switch_... / test_new_personal_entry_with_
        manipulated_other_users_group_is_rejected for that path), but the
        security property under test is the same either way: no mutation
        on an invalid group_id, regardless of which layer catches it."""
        entry = self._make_entry(self.owner.id, shared=False, group_id=None)

        resp = self._post_edit(entry, shared=False, group_id=999999, title="Should not apply")

        self.assertNotEqual(resp.status_code, 302)  # not a success redirect
        db.session.refresh(entry)
        self.assertIsNone(entry.group_id)
        self.assertNotEqual(entry.title, "Should not apply")

    def test_rejected_edit_changes_no_field_at_all(self):
        """Beyond shared/group_id: a rejected group assignment must not
        leave title/username/etc. partially applied either."""
        shared_group = self._shared_group()
        entry = self._make_entry(self.owner.id, shared=True, group_id=shared_group.id,
                                  title="Original Title")
        original_username = entry.username

        resp = self._post_edit(entry, shared=False, group_id=shared_group.id, title="Tampered Title")

        self.assertEqual(resp.status_code, 409)
        db.session.refresh(entry)
        self.assertEqual(entry.title, "Original Title")
        self.assertEqual(entry.username, original_username)
        self.assertTrue(entry.shared)
        self.assertEqual(entry.group_id, shared_group.id)
