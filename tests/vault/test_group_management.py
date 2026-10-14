"""ADR-005 Fase 3: creation/deletion authorization and parent/scope coherence
for VaultGroup itself (as opposed to Fase 2's entry<->group assignment
validation).

    Shared groups:   scope="shared", owner_id=NULL.
                     Create/delete: admin-only.
                     Parent must be None or another shared group.

    Personal groups: scope="personal", owner_id=<creator>, always
                     server-computed, never taken from form input.
                     Create: any user with the vault tool, for themselves
                     only (admin creating one still gets owner_id=admin.id,
                     never "on behalf of" another user).
                     Delete: owner or admin.
                     Parent must be None or another personal group owned by
                     the SAME owner.

Every POST here sends scope/parent_id/owner_id-adjacent fields directly,
the way a tampered client would — never relying on what the (still
unfiltered, Phase-4 concern) dropdown happens to offer.
"""
from tests.base import PortalTestCase
from app.extensions import db
from app.vault.models import VaultEntry, VaultGroup  # noqa: F401 — must load before setUp()'s db.create_all()
from app.vault.crypto import encrypt
from app.vault.routes import VaultGroupParentConflict, _validate_group_parent


class TestValidateGroupParent(PortalTestCase):
    """Direct unit tests of the pure parent-coherence helper. Does not take
    current_user at all by design — identity is whatever owner_id the
    caller passes in."""

    def setUp(self):
        super().setUp()
        self.user_a = self.make_user("groupparent_a")
        self.user_b = self.make_user("groupparent_b")

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

    # 1-3: shared
    def test_shared_with_no_parent_is_valid(self):
        result = _validate_group_parent("shared", None, None)
        self.assertIsNone(result)

    def test_shared_with_shared_parent_is_valid(self):
        parent = self._shared_group()
        result = _validate_group_parent("shared", None, parent.id)
        self.assertEqual(result.id, parent.id)

    def test_shared_with_personal_parent_is_rejected(self):
        parent = self._personal_group(self.user_a.id)
        with self.assertRaises(VaultGroupParentConflict):
            _validate_group_parent("shared", None, parent.id)

    # 4-7: personal
    def test_personal_with_no_parent_is_valid(self):
        result = _validate_group_parent("personal", self.user_a.id, None)
        self.assertIsNone(result)

    def test_personal_with_own_personal_parent_is_valid(self):
        parent = self._personal_group(self.user_a.id)
        result = _validate_group_parent("personal", self.user_a.id, parent.id)
        self.assertEqual(result.id, parent.id)

    def test_personal_with_shared_parent_is_rejected(self):
        parent = self._shared_group()
        with self.assertRaises(VaultGroupParentConflict):
            _validate_group_parent("personal", self.user_a.id, parent.id)

    def test_personal_with_other_owners_personal_parent_is_rejected(self):
        parent = self._personal_group(self.user_b.id)
        with self.assertRaises(VaultGroupParentConflict):
            _validate_group_parent("personal", self.user_a.id, parent.id)

    # 8: nonexistent
    def test_nonexistent_parent_id_is_rejected(self):
        with self.assertRaises(VaultGroupParentConflict):
            _validate_group_parent("shared", None, 999999)

    def test_parent_id_zero_is_rejected_not_treated_as_no_parent(self):
        with self.assertRaises(VaultGroupParentConflict):
            _validate_group_parent("personal", self.user_a.id, 0)


class TestGroupNew(PortalTestCase):
    """HTTP-level tests for POST /vault/grupos/nuevo."""

    def setUp(self):
        super().setUp()
        self.user = self.make_user("groupnew_user", tools=["vault"])
        self.other = self.make_user("groupnew_other", tools=["vault"])
        self.admin = self.make_user("groupnew_admin", is_admin=True)

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

    def _csrf(self):
        page = self.client.get("/vault/")
        return self.extract_csrf(page.get_data(as_text=True))

    def _post_group_new(self, name, scope, parent_id=None, extra=None):
        data = {
            "name": name,
            "scope": scope,
            "parent_id": str(parent_id) if parent_id else "",
            "csrf_token": self._csrf(),
        }
        if extra:
            data.update(extra)
        return self.client.post("/vault/grupos/nuevo", data=data, follow_redirects=False)

    def _post_group_new_raw_parent(self, name, scope, raw_parent_id):
        """Like _post_group_new(), but sends parent_id exactly as given —
        including a non-numeric or "0" string a tampered client might send,
        which str(parent_id) if parent_id else "" in _post_group_new()
        cannot represent (it collapses both None and 0 to "")."""
        data = {
            "name": name,
            "scope": scope,
            "parent_id": raw_parent_id,
            "csrf_token": self._csrf(),
        }
        return self.client.post("/vault/grupos/nuevo", data=data, follow_redirects=False)

    # -- shared --------------------------------------------------------

    def test_admin_creates_shared_root_succeeds(self):
        self.login("groupnew_admin")
        resp = self._post_group_new("Shared Root", "shared")

        self.assertEqual(resp.status_code, 302)
        group = VaultGroup.query.filter_by(name="Shared Root").first()
        self.assertIsNotNone(group)
        self.assertEqual(group.scope, "shared")
        self.assertIsNone(group.owner_id)

    def test_admin_creates_shared_child_under_shared_succeeds(self):
        self.login("groupnew_admin")
        parent = self._shared_group()
        resp = self._post_group_new("Shared Child", "shared", parent_id=parent.id)

        self.assertEqual(resp.status_code, 302)
        group = VaultGroup.query.filter_by(name="Shared Child").first()
        self.assertIsNotNone(group)
        self.assertEqual(group.parent_id, parent.id)

    def test_admin_shared_under_personal_parent_is_rejected(self):
        self.login("groupnew_admin")
        personal_parent = self._personal_group(self.admin.id)
        resp = self._post_group_new("Bad Shared", "shared", parent_id=personal_parent.id)

        self.assertEqual(resp.status_code, 409)
        self.assertIsNone(VaultGroup.query.filter_by(name="Bad Shared").first())

    def test_normal_user_creating_shared_is_rejected(self):
        self.login("groupnew_user")
        resp = self._post_group_new("User Shared Attempt", "shared")

        self.assertEqual(resp.status_code, 403)
        self.assertIsNone(VaultGroup.query.filter_by(name="User Shared Attempt").first())

    def test_manipulated_owner_id_on_shared_create_is_ignored(self):
        self.login("groupnew_admin")
        resp = self._post_group_new(
            "Shared Owner Attempt", "shared", extra={"owner_id": str(self.other.id)}
        )

        self.assertEqual(resp.status_code, 302)
        group = VaultGroup.query.filter_by(name="Shared Owner Attempt").first()
        self.assertIsNotNone(group)
        self.assertIsNone(group.owner_id)

    # -- personal --------------------------------------------------------

    def test_user_creates_personal_root_succeeds_with_own_owner_id(self):
        self.login("groupnew_user")
        resp = self._post_group_new("Personal Root", "personal")

        self.assertEqual(resp.status_code, 302)
        group = VaultGroup.query.filter_by(name="Personal Root").first()
        self.assertIsNotNone(group)
        self.assertEqual(group.scope, "personal")
        self.assertEqual(group.owner_id, self.user.id)

    def test_user_creates_personal_child_under_own_personal_succeeds(self):
        self.login("groupnew_user")
        parent = self._personal_group(self.user.id)
        resp = self._post_group_new("Personal Child", "personal", parent_id=parent.id)

        self.assertEqual(resp.status_code, 302)
        group = VaultGroup.query.filter_by(name="Personal Child").first()
        self.assertIsNotNone(group)
        self.assertEqual(group.parent_id, parent.id)

    def test_user_personal_under_shared_parent_is_rejected(self):
        self.login("groupnew_user")
        shared_parent = self._shared_group()
        resp = self._post_group_new("Bad Personal", "personal", parent_id=shared_parent.id)

        self.assertEqual(resp.status_code, 409)
        self.assertIsNone(VaultGroup.query.filter_by(name="Bad Personal").first())

    def test_user_personal_under_other_users_personal_parent_is_rejected(self):
        self.login("groupnew_user")
        foreign_parent = self._personal_group(self.other.id)
        resp = self._post_group_new("Manipulated Personal", "personal", parent_id=foreign_parent.id)

        self.assertEqual(resp.status_code, 409)
        self.assertIsNone(VaultGroup.query.filter_by(name="Manipulated Personal").first())

    def test_admin_creates_personal_group_owned_by_admin_not_another_user(self):
        self.login("groupnew_admin")
        resp = self._post_group_new("Admin Personal", "personal")

        self.assertEqual(resp.status_code, 302)
        group = VaultGroup.query.filter_by(name="Admin Personal").first()
        self.assertIsNotNone(group)
        self.assertEqual(group.owner_id, self.admin.id)

    def test_manipulated_owner_id_on_personal_create_is_ignored(self):
        self.login("groupnew_user")
        resp = self._post_group_new(
            "Personal Owner Attempt", "personal", extra={"owner_id": str(self.other.id)}
        )

        self.assertEqual(resp.status_code, 302)
        group = VaultGroup.query.filter_by(name="Personal Owner Attempt").first()
        self.assertIsNotNone(group)
        self.assertEqual(group.owner_id, self.user.id)

    # -- fail-closed / no partial persistence -----------------------------

    def test_rejected_create_with_incompatible_parent_persists_no_group(self):
        self.login("groupnew_user")
        shared_parent = self._shared_group()
        before = VaultGroup.query.count()

        self._post_group_new("Never Created", "personal", parent_id=shared_parent.id)

        self.assertEqual(VaultGroup.query.count(), before)

    # -- parent_id parsing must fail closed on malformed input -------------

    def test_parent_id_non_numeric_is_rejected(self):
        self.login("groupnew_user")
        before = VaultGroup.query.count()

        resp = self._post_group_new_raw_parent("Bad Parent String", "personal", "abc")

        self.assertEqual(resp.status_code, 400)
        self.assertEqual(VaultGroup.query.count(), before)
        self.assertIsNone(VaultGroup.query.filter_by(name="Bad Parent String").first())

    def test_parent_id_zero_is_rejected_not_treated_as_no_parent(self):
        self.login("groupnew_admin")
        before = VaultGroup.query.count()

        resp = self._post_group_new_raw_parent("Bad Parent Zero", "shared", "0")

        self.assertEqual(resp.status_code, 409)
        self.assertEqual(VaultGroup.query.count(), before)
        self.assertIsNone(VaultGroup.query.filter_by(name="Bad Parent Zero").first())

    def test_parent_id_empty_string_is_valid_root(self):
        self.login("groupnew_user")

        resp = self._post_group_new_raw_parent("Valid Root Via Empty String", "personal", "")

        self.assertEqual(resp.status_code, 302)
        group = VaultGroup.query.filter_by(name="Valid Root Via Empty String").first()
        self.assertIsNotNone(group)
        self.assertIsNone(group.parent_id)


class TestGroupDelete(PortalTestCase):
    """HTTP-level tests for POST /vault/grupos/<id>/eliminar."""

    def setUp(self):
        super().setUp()
        self.owner = self.make_user("groupdel_owner", tools=["vault"])
        self.other = self.make_user("groupdel_other", tools=["vault"])
        self.admin = self.make_user("groupdel_admin", is_admin=True)

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

    def _csrf(self):
        page = self.client.get("/vault/")
        return self.extract_csrf(page.get_data(as_text=True))

    def _post_delete(self, group_id):
        return self.client.post(
            f"/vault/grupos/{group_id}/eliminar",
            data={"csrf_token": self._csrf()},
            follow_redirects=False,
        )

    # -- shared --------------------------------------------------------

    def test_admin_deletes_shared_group_succeeds(self):
        group = self._shared_group()
        self.login("groupdel_admin")

        resp = self._post_delete(group.id)

        self.assertEqual(resp.status_code, 302)
        self.assertIsNone(db.session.get(VaultGroup, group.id))

    def test_normal_user_deleting_shared_group_is_rejected(self):
        group = self._shared_group()
        self.login("groupdel_owner")

        resp = self._post_delete(group.id)

        self.assertEqual(resp.status_code, 403)
        self.assertIsNotNone(db.session.get(VaultGroup, group.id))

    # -- personal --------------------------------------------------------

    def test_owner_deletes_own_personal_group_succeeds(self):
        group = self._personal_group(self.owner.id)
        self.login("groupdel_owner")

        resp = self._post_delete(group.id)

        self.assertEqual(resp.status_code, 302)
        self.assertIsNone(db.session.get(VaultGroup, group.id))

    def test_normal_user_deleting_other_users_personal_group_is_rejected(self):
        group = self._personal_group(self.owner.id)
        self.login("groupdel_other")

        resp = self._post_delete(group.id)

        self.assertEqual(resp.status_code, 403)
        self.assertIsNotNone(db.session.get(VaultGroup, group.id))

    def test_admin_deletes_other_users_personal_group_succeeds(self):
        group = self._personal_group(self.owner.id)
        self.login("groupdel_admin")

        resp = self._post_delete(group.id)

        self.assertEqual(resp.status_code, 302)
        self.assertIsNone(db.session.get(VaultGroup, group.id))

    # -- delete behavior (unchanged historical semantics) -------------------

    def _make_entry(self, owner_id, group_id):
        entry = VaultEntry(
            title="Entrada de prueba",
            category="server",
            username="svc",
            password_enc=encrypt("Synthetic-Entry-Password-1"),
            owner_id=owner_id,
            shared=(group_id is not None and db.session.get(VaultGroup, group_id).scope == "shared"),
            group_id=group_id,
        )
        db.session.add(entry)
        db.session.commit()
        return entry

    def test_deleting_group_does_not_delete_entries(self):
        group = self._shared_group()
        entry = self._make_entry(self.owner.id, group.id)
        self.login("groupdel_admin")

        self._post_delete(group.id)

        self.assertIsNotNone(db.session.get(VaultEntry, entry.id))

    def test_deleting_group_clears_group_id_on_its_entries(self):
        group = self._shared_group()
        entry = self._make_entry(self.owner.id, group.id)
        self.login("groupdel_admin")

        self._post_delete(group.id)

        db.session.refresh(entry)
        self.assertIsNone(entry.group_id)

    def test_deleting_group_clears_parent_id_on_direct_children(self):
        parent = self._shared_group("Parent")
        child = VaultGroup(name="Child", scope="shared", parent_id=parent.id)
        db.session.add(child)
        db.session.commit()
        self.login("groupdel_admin")

        self._post_delete(parent.id)

        db.session.refresh(child)
        self.assertIsNone(child.parent_id)

    def test_deleting_group_does_not_cascade_to_grandchildren(self):
        parent = self._shared_group("Parent")
        child = VaultGroup(name="Child", scope="shared", parent_id=parent.id)
        db.session.add(child)
        db.session.commit()
        grandchild = VaultGroup(name="Grandchild", scope="shared", parent_id=child.id)
        db.session.add(grandchild)
        db.session.commit()
        self.login("groupdel_admin")

        self._post_delete(parent.id)

        self.assertIsNotNone(db.session.get(VaultGroup, grandchild.id))
        db.session.refresh(grandchild)
        self.assertEqual(grandchild.parent_id, child.id)

    def test_deleting_group_leaves_unrelated_groups_untouched(self):
        group = self._shared_group("ToDelete")
        unrelated = self._shared_group("Unrelated")
        self.login("groupdel_admin")

        self._post_delete(group.id)

        self.assertIsNotNone(db.session.get(VaultGroup, unrelated.id))

    # -- fail-closed -----------------------------------------------------

    def test_rejected_delete_changes_nothing(self):
        group = self._personal_group(self.owner.id)
        entry = self._make_entry(self.owner.id, group.id)
        self.login("groupdel_other")

        self._post_delete(group.id)

        self.assertIsNotNone(db.session.get(VaultGroup, group.id))
        db.session.refresh(entry)
        self.assertEqual(entry.group_id, group.id)
