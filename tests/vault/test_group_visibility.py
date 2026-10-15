"""ADR-005 Fase 4: UI presentation and filtering of shared/personal groups.

This phase is UX only — it must never become the actual security boundary.
_validate_group_assignment(), _validate_group_parent(), group_new(), and
group_delete() (Fases 2-3) remain the authoritative checks regardless of
what the dropdown/tree happens to render. Tests here focus on what gets
rendered; a couple of explicit regression tests at the bottom confirm the
backend still rejects what the UI no longer offers.
"""
from tests.base import PortalTestCase
from app.extensions import db
from app.vault.models import VaultEntry, VaultGroup  # noqa: F401 — must load before setUp()'s db.create_all()
from app.vault.crypto import encrypt
from app.vault.routes import (
    _shared_group_tree,
    _personal_group_trees,
    _group_new_parent_choices,
    _populate_group_choices,
    VaultGroupAssignmentConflict,
    VaultGroupParentConflict,
    _validate_group_assignment,
    _validate_group_parent,
)
from app.vault.forms import VaultEntryForm


class _GroupFixtures(PortalTestCase):
    def _shared_group(self, name="Servidores", parent_id=None):
        g = VaultGroup(name=name, scope="shared", parent_id=parent_id)
        db.session.add(g)
        db.session.commit()
        return g

    def _personal_group(self, owner_id, name="Mis accesos", parent_id=None):
        g = VaultGroup(name=name, scope="personal", owner_id=owner_id, parent_id=parent_id)
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


class TestPersonalGroupTreesHelper(_GroupFixtures):
    """Direct unit tests of _personal_group_trees() — the piece responsible
    for never merging different owners' personal groups into one ambiguous
    tree."""

    def setUp(self):
        super().setUp()
        self.user_a = self.make_user("vistree_a", nombre_completo="Usuaria A", tools=["vault"])
        self.user_b = self.make_user("vistree_b", nombre_completo="Usuario B", tools=["vault"])
        self.admin = self.make_user("vistree_admin", is_admin=True)

    def test_normal_user_sees_only_own_personal_tree(self):
        own = self._personal_group(self.user_a.id, "Mine")
        self._personal_group(self.user_b.id, "Not Mine")

        trees = _personal_group_trees(self.user_a)

        self.assertEqual(len(trees), 1)
        owner_id, label, tree = trees[0]
        self.assertEqual(owner_id, self.user_a.id)
        self.assertEqual([g.id for g, _ in tree], [own.id])

    def test_normal_user_with_no_personal_groups_gets_empty_tree(self):
        trees = _personal_group_trees(self.user_a)

        self.assertEqual(len(trees), 1)
        _, _, tree = trees[0]
        self.assertEqual(tree, [])

    def test_admin_sees_separate_tree_per_owner(self):
        a_group = self._personal_group(self.user_a.id, "A Group")
        b_group = self._personal_group(self.user_b.id, "B Group")

        trees = _personal_group_trees(self.admin)
        by_owner = {owner_id: (label, tree) for owner_id, label, tree in trees}

        self.assertIn(self.user_a.id, by_owner)
        self.assertIn(self.user_b.id, by_owner)
        label_a, tree_a = by_owner[self.user_a.id]
        label_b, tree_b = by_owner[self.user_b.id]
        self.assertEqual([g.id for g, _ in tree_a], [a_group.id])
        self.assertEqual([g.id for g, _ in tree_b], [b_group.id])
        self.assertNotEqual(label_a, label_b)

    def test_admin_owners_never_share_a_tree(self):
        self._personal_group(self.user_a.id, "A Group")
        self._personal_group(self.user_b.id, "B Group")

        trees = _personal_group_trees(self.admin)

        owner_ids = [owner_id for owner_id, _, _ in trees]
        self.assertEqual(len(owner_ids), len(set(owner_ids)))

    def test_admin_label_uses_safe_human_identifier_not_raw_id(self):
        self._personal_group(self.user_a.id, "A Group")

        trees = _personal_group_trees(self.admin)
        labels = [label for _, label, _ in trees]

        self.assertIn("Usuaria A", labels)
        self.assertNotIn(str(self.user_a.id), " ".join(labels))


class TestGroupNewParentChoicesHelper(_GroupFixtures):
    def setUp(self):
        super().setUp()
        self.user = self.make_user("visparent_user", tools=["vault"])
        self.other = self.make_user("visparent_other", tools=["vault"])
        self.admin = self.make_user("visparent_admin", is_admin=True)

    def test_normal_user_gets_only_own_personal_choices(self):
        own = self._personal_group(self.user.id, "Own")
        self._personal_group(self.other.id, "Foreign")
        self._shared_group("Shared One")

        choices = _group_new_parent_choices(self.user)

        ids = [c[0] for c in choices]
        self.assertEqual(ids, [own.id])
        self.assertTrue(all(c[2] == "personal" for c in choices))

    def test_admin_gets_shared_and_own_personal_but_not_others_personal(self):
        shared = self._shared_group("Shared One")
        admin_personal = self._personal_group(self.admin.id, "Admin Own")
        self._personal_group(self.user.id, "Foreign")

        choices = _group_new_parent_choices(self.admin)

        ids = {c[0] for c in choices}
        self.assertIn(shared.id, ids)
        self.assertIn(admin_personal.id, ids)
        self.assertNotIn(
            VaultGroup.query.filter_by(name="Foreign").first().id, ids
        )


class TestPopulateGroupChoicesHelper(_GroupFixtures):
    def setUp(self):
        super().setUp()
        self.owner = self.make_user("vispopulate_owner", tools=["vault"])
        self.other = self.make_user("vispopulate_other", tools=["vault"])

    def _form(self):
        return VaultEntryForm(meta={"csrf": False})

    def test_shared_true_offers_only_shared_groups(self):
        shared = self._shared_group("Shared One")
        self._personal_group(self.owner.id, "Personal One")
        form = self._form()

        _populate_group_choices(form, self.owner.id, True)

        values = [v for v, _ in form.group_id.choices]
        self.assertIn(str(shared.id), values)
        self.assertEqual(len(values), 2)  # blank + the one shared group

    def test_shared_false_offers_only_owners_personal_groups(self):
        self._shared_group("Shared One")
        own = self._personal_group(self.owner.id, "Personal One")
        self._personal_group(self.other.id, "Foreign Personal")
        form = self._form()

        _populate_group_choices(form, self.owner.id, False)

        values = [v for v, _ in form.group_id.choices]
        self.assertIn(str(own.id), values)
        self.assertEqual(len(values), 2)  # blank + the one own-personal group


class TestIndexVisibilityNormalUser(_GroupFixtures):
    def setUp(self):
        super().setUp()
        self.user = self.make_user("visidx_user", tools=["vault"])
        self.other = self.make_user("visidx_other", tools=["vault"])
        self.login("visidx_user")

    def test_sees_shared_groups(self):
        self._shared_group("Shared Visible")
        resp = self.client.get("/vault/")
        self.assertIn(b"Shared Visible", resp.data)

    def test_sees_own_personal_groups(self):
        self._personal_group(self.user.id, "My Personal Group")
        resp = self.client.get("/vault/")
        self.assertIn(b"My Personal Group", resp.data)

    def test_does_not_see_other_users_personal_groups(self):
        self._personal_group(self.other.id, "Other's Personal Group")
        resp = self.client.get("/vault/")
        self.assertNotIn(b"Other&#39;s Personal Group", resp.data)
        self.assertNotIn(b"Other's Personal Group", resp.data)

    def test_shows_shared_and_personal_section_labels(self):
        resp = self.client.get("/vault/")
        self.assertIn(b"Compartidas", resp.data)
        self.assertIn(b"Personales", resp.data)


class TestIndexVisibilityAdmin(_GroupFixtures):
    def setUp(self):
        super().setUp()
        self.admin = self.make_user("visidx_admin", is_admin=True)
        self.user_a = self.make_user("visidx_a", nombre_completo="Usuaria Index A", tools=["vault"])
        self.user_b = self.make_user("visidx_b", nombre_completo="Usuario Index B", tools=["vault"])
        self.login("visidx_admin")

    def test_admin_sees_shared_groups(self):
        self._shared_group("Admin Visible Shared")
        resp = self.client.get("/vault/")
        self.assertIn(b"Admin Visible Shared", resp.data)

    def test_admin_sees_personal_groups_of_multiple_users(self):
        self._personal_group(self.user_a.id, "A Personal Group")
        self._personal_group(self.user_b.id, "B Personal Group")
        resp = self.client.get("/vault/")
        self.assertIn(b"A Personal Group", resp.data)
        self.assertIn(b"B Personal Group", resp.data)

    def test_admin_sees_per_user_labels(self):
        self._personal_group(self.user_a.id, "A Personal Group")
        self._personal_group(self.user_b.id, "B Personal Group")
        resp = self.client.get("/vault/")
        self.assertIn(b"Usuaria Index A", resp.data)
        self.assertIn(b"Usuario Index B", resp.data)


class TestEntryGroupDropdownNew(_GroupFixtures):
    def setUp(self):
        super().setUp()
        self.user = self.make_user("visnewdd_user", tools=["vault"])
        self.other = self.make_user("visnewdd_other", tools=["vault"])
        self.login("visnewdd_user")

    def test_new_shared_shows_only_shared_groups(self):
        self._shared_group("New Shared Choice")
        self._personal_group(self.user.id, "New Personal Choice")
        resp = self.client.get("/vault/new")
        self.assertIn(b"New Shared Choice", resp.data)
        self.assertNotIn(b"New Personal Choice", resp.data)


class TestEntryGroupDropdownEdit(_GroupFixtures):
    def setUp(self):
        super().setUp()
        self.owner = self.make_user("viseditdd_owner", tools=["vault"])
        self.admin = self.make_user("viseditdd_admin", is_admin=True)

    def test_shared_entry_shows_only_shared_groups_in_dropdown(self):
        shared = self._shared_group("Edit Shared Choice")
        self._personal_group(self.owner.id, "Edit Personal Choice")
        entry = self._make_entry(self.owner.id, shared=True, group_id=shared.id)
        self.login("viseditdd_owner")

        resp = self.client.get(f"/vault/{entry.id}/edit")

        self.assertIn(b"Edit Shared Choice", resp.data)
        self.assertNotIn(b"Edit Personal Choice", resp.data)

    def test_personal_entry_shows_only_owners_personal_groups_in_dropdown(self):
        self._shared_group("Edit Shared Choice 2")
        own = self._personal_group(self.owner.id, "Owner's Own Group")
        entry = self._make_entry(self.owner.id, shared=False, group_id=own.id)
        self.login("viseditdd_owner")

        resp = self.client.get(f"/vault/{entry.id}/edit")

        self.assertIn(b"Owner&#39;s Own Group", resp.data)
        self.assertNotIn(b"Edit Shared Choice 2", resp.data)

    def test_admin_editing_others_personal_entry_shows_owners_groups_not_admins(self):
        """The most important UX case in this phase: user A owns a personal
        entry and Grupo A; admin owns Grupo Admin. When admin opens edit()
        on user A's entry, the dropdown must show Grupo A and must NOT show
        Grupo Admin as a compatible option."""
        group_a = self._personal_group(self.owner.id, "Grupo A")
        self._personal_group(self.admin.id, "Grupo Admin")
        entry = self._make_entry(self.owner.id, shared=False, group_id=group_a.id)
        self.login("viseditdd_admin")

        resp = self.client.get(f"/vault/{entry.id}/edit")

        self.assertIn(b"Grupo A", resp.data)
        self.assertNotIn(b"Grupo Admin", resp.data)


class TestGroupNewParentDropdownUI(_GroupFixtures):
    def setUp(self):
        super().setUp()
        self.user = self.make_user("visparentui_user", tools=["vault"])
        self.other = self.make_user("visparentui_other", tools=["vault"])
        self.admin = self.make_user("visparentui_admin", is_admin=True)

    def _parent_select_html(self, resp):
        """Isolate the group_new parent_id <select> specifically — admin
        legitimately sees another user's personal group elsewhere on this
        same page (in the sidebar tree, per requirement #6), so a blanket
        "not anywhere in the page" assertion would be wrong for admin.
        Only the parent-choice options themselves are under test here."""
        html = resp.get_data(as_text=True)
        import re
        match = re.search(
            r'<select[^>]*id="groupParentSelect".*?</select>', html, re.DOTALL
        )
        self.assertIsNotNone(match, "groupParentSelect not found in page")
        return match.group(0)

    def test_normal_user_does_not_see_shared_as_parent_option(self):
        self._shared_group("Parent UI Shared")
        self.login("visparentui_user")
        resp = self.client.get("/vault/")
        self.assertNotIn(b'data-scope="shared"', resp.data)

    def test_normal_user_does_not_see_others_personal_as_parent_option(self):
        self._personal_group(self.other.id, "Parent UI Foreign")
        self.login("visparentui_user")
        resp = self.client.get("/vault/")
        self.assertNotIn(b"Parent UI Foreign", resp.data)

    def test_admin_personal_parent_options_exclude_other_users(self):
        self._personal_group(self.user.id, "Parent UI Foreign For Admin")
        self._personal_group(self.admin.id, "Parent UI Admin Own")
        self.login("visparentui_admin")
        resp = self.client.get("/vault/")
        parent_select = self._parent_select_html(resp)
        self.assertIn("Parent UI Admin Own", parent_select)
        self.assertNotIn("Parent UI Foreign For Admin", parent_select)

    def test_admin_sees_shared_parent_option(self):
        self._shared_group("Parent UI Shared For Admin")
        self.login("visparentui_admin")
        resp = self.client.get("/vault/")
        parent_select = self._parent_select_html(resp)
        self.assertIn("Parent UI Shared For Admin", parent_select)
        self.assertIn('data-scope="shared"', parent_select)


class TestDeleteControlsVisibility(_GroupFixtures):
    def setUp(self):
        super().setUp()
        self.owner = self.make_user("visdelctl_owner", tools=["vault"])
        self.admin = self.make_user("visdelctl_admin", is_admin=True)

    def _delete_action(self, group_id):
        return f'/vault/grupos/{group_id}/eliminar'.encode()

    def test_normal_user_does_not_see_delete_on_shared_group(self):
        group = self._shared_group("Del Ctl Shared")
        self.login("visdelctl_owner")
        resp = self.client.get("/vault/")
        self.assertNotIn(self._delete_action(group.id), resp.data)

    def test_normal_user_sees_delete_on_own_personal_group(self):
        group = self._personal_group(self.owner.id, "Del Ctl Own Personal")
        self.login("visdelctl_owner")
        resp = self.client.get("/vault/")
        self.assertIn(self._delete_action(group.id), resp.data)

    def test_admin_sees_delete_on_shared_group(self):
        group = self._shared_group("Del Ctl Shared For Admin")
        self.login("visdelctl_admin")
        resp = self.client.get("/vault/")
        self.assertIn(self._delete_action(group.id), resp.data)

    def test_admin_sees_delete_on_others_personal_group(self):
        group = self._personal_group(self.owner.id, "Del Ctl Foreign Personal")
        self.login("visdelctl_admin")
        resp = self.client.get("/vault/")
        self.assertIn(self._delete_action(group.id), resp.data)


class TestIndexGroupFilterDoesNotLeakForeignEntries(_GroupFixtures):
    """UI never became the security boundary: even though a foreign
    personal group no longer appears in the sidebar at all, manipulating
    ?group=<id> directly in the URL must not surface that owner's entries
    to a normal user — the existing index() base_q ownership/shared filter
    already guarantees this; this just proves it."""

    def setUp(self):
        super().setUp()
        self.owner = self.make_user("visleak_owner", tools=["vault"])
        self.other = self.make_user("visleak_other", tools=["vault"])

    def test_manipulated_group_id_for_foreign_personal_group_shows_no_entries(self):
        foreign_group = self._personal_group(self.owner.id, "Leak Test Group")
        self._make_entry(self.owner.id, shared=False, group_id=foreign_group.id, title="Leak Test Entry")
        self.login("visleak_other")

        resp = self.client.get(f"/vault/?group={foreign_group.id}")

        self.assertNotIn(b"Leak Test Entry", resp.data)


class TestBackendRegressionStillEnforced(_GroupFixtures):
    """UI filtering is not a substitute for Fase 2/3 backend validation —
    these two direct-helper checks confirm the authoritative checks still
    reject what the UI no longer renders as an option."""

    def setUp(self):
        super().setUp()
        self.owner = self.make_user("visregress_owner", tools=["vault"])
        self.other = self.make_user("visregress_other", tools=["vault"])

    def test_validate_group_assignment_still_rejects_unrendered_foreign_group(self):
        foreign_group = self._personal_group(self.other.id, "Regress Foreign")
        with self.assertRaises(VaultGroupAssignmentConflict):
            _validate_group_assignment(self.owner.id, False, foreign_group.id)

    def test_validate_group_parent_still_rejects_unrendered_foreign_parent(self):
        foreign_group = self._personal_group(self.other.id, "Regress Foreign Parent")
        with self.assertRaises(VaultGroupParentConflict):
            _validate_group_parent("personal", self.owner.id, foreign_group.id)
