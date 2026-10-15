"""ADR-005 Fase 5: KeePass must operate ONLY on shared data.

    export:   only VaultGroup.scope == "shared"; only VaultEntry.shared == True
    import:   only create/reuse VaultGroup.scope == "shared"; never a personal
              group; imported entries stay shared=True (already true before
              this phase — confirmed, not changed)

This crosses a secrets-exposure boundary: a personal credential or personal
group ending up in the shared .kdbx file would be a real leak to every
other Vault user who has the shared KeePass password. Tests here run the
real _export() against a real pykeepass-readable file and the real
_get_or_create_group_chain() helper — not mocks.
"""
import io
import os
import tempfile

from pykeepass import PyKeePass, create_database

from tests.base import PortalTestCase
from app.extensions import db
from app.vault.models import VaultEntry, VaultGroup, VaultSyncConfig  # noqa: F401 — must load before setUp()'s db.create_all()
from app.vault.crypto import encrypt
from app.vault.sync import vault_sync
from app.vault.routes import _get_or_create_group_chain
from app.vault import import_staging

SYNTHETIC_KDBX_PASSWORD = "Synthetic-KDBX-Export-Pass-1"
SYNTHETIC_KDBX_IMPORT_PASSWORD = "Synthetic-KDBX-Import-Pass-1"


def _make_synthetic_kdbx_with_group(title, group_name=None, password=SYNTHETIC_KDBX_IMPORT_PASSWORD):
    """Build a throwaway .kdbx with one entry, optionally inside a named
    subgroup — mirrors tests/vault/test_import_flow.py's helper, extended
    to exercise group_path."""
    fd, path = tempfile.mkstemp(suffix=".kdbx")
    os.close(fd)
    try:
        kp = create_database(path, password=password)
        target = kp.root_group
        if group_name:
            target = kp.add_group(kp.root_group, group_name)
        kp.add_entry(target, title, "svc_import", "Synthetic-Import-Secret-1")
        kp.save()
        with open(path, "rb") as f:
            return f.read()
    finally:
        if os.path.exists(path):
            os.remove(path)


class _SyncFixtures(PortalTestCase):
    def setUp(self):
        super().setUp()
        fd, self.kdbx_path = tempfile.mkstemp(suffix=".kdbx")
        os.close(fd)
        os.remove(self.kdbx_path)  # _export() creates it fresh via create_database

        cfg = VaultSyncConfig(
            kdbx_path=self.kdbx_path,
            kdbx_password_enc=encrypt(SYNTHETIC_KDBX_PASSWORD),
        )
        db.session.add(cfg)
        db.session.commit()

    def tearDown(self):
        if os.path.exists(self.kdbx_path):
            try:
                os.chmod(self.kdbx_path, 0o600)
                os.remove(self.kdbx_path)
            except OSError:
                pass
        super().tearDown()

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

    def _entry(self, owner_id, shared, group_id=None, title="Entry"):
        e = VaultEntry(
            title=title,
            category="server",
            username="svc",
            password_enc=encrypt("Synthetic-Secret-Value-1"),
            owner_id=owner_id,
            shared=shared,
            group_id=group_id,
        )
        db.session.add(e)
        db.session.commit()
        return e

    def _run_export(self):
        vault_sync._export()
        # A silently-swallowed internal exception must not masquerade as
        # "the filter worked" — every test here asserts the export actually
        # succeeded, not just that the file doesn't contain what it shouldn't.
        self.assertTrue(vault_sync.last_sync_ok, "export reported failure")

    def _open_exported(self):
        return PyKeePass(self.kdbx_path, password=SYNTHETIC_KDBX_PASSWORD)

    def _all_group_names(self, kp):
        return {g.name for g in kp.groups}

    def _all_entry_titles(self, kp):
        return {e.title for e in kp.entries}


class TestExportGroups(_SyncFixtures):
    def setUp(self):
        super().setUp()
        self.owner = self.make_user("exportgrp_owner", tools=["vault"])

    def test_shared_group_appears_in_export(self):
        self._shared_group("Export Shared Group")
        self._run_export()
        kp = self._open_exported()
        self.assertIn("Export Shared Group", self._all_group_names(kp))

    def test_personal_group_does_not_appear_in_export(self):
        self._personal_group(self.owner.id, "Export Personal Group")
        self._run_export()
        kp = self._open_exported()
        self.assertNotIn("Export Personal Group", self._all_group_names(kp))

    def test_nested_shared_groups_are_preserved(self):
        parent = self._shared_group("Export Shared Parent")
        self._shared_group("Export Shared Child", parent_id=parent.id)
        self._run_export()
        kp = self._open_exported()
        names = self._all_group_names(kp)
        self.assertIn("Export Shared Parent", names)
        self.assertIn("Export Shared Child", names)
        child_kp = kp.find_groups(name="Export Shared Child", first=True)
        parent_kp = kp.find_groups(name="Export Shared Parent", first=True)
        self.assertEqual(child_kp.parentgroup.name, parent_kp.name)

    def test_personal_subtree_entirely_excluded(self):
        parent = self._personal_group(self.owner.id, "Export Personal Parent")
        self._personal_group(self.owner.id, "Export Personal Child", parent_id=parent.id)
        self._run_export()
        kp = self._open_exported()
        names = self._all_group_names(kp)
        self.assertNotIn("Export Personal Parent", names)
        self.assertNotIn("Export Personal Child", names)


class TestExportEntries(_SyncFixtures):
    def setUp(self):
        super().setUp()
        self.owner = self.make_user("exportent_owner", tools=["vault"])

    def test_shared_entry_appears_in_export(self):
        self._entry(self.owner.id, shared=True, title="Export Shared Entry")
        self._run_export()
        kp = self._open_exported()
        self.assertIn("Export Shared Entry", self._all_entry_titles(kp))

    def test_personal_entry_does_not_appear_in_export(self):
        self._entry(self.owner.id, shared=False, title="Export Personal Entry")
        self._run_export()
        kp = self._open_exported()
        self.assertNotIn("Export Personal Entry", self._all_entry_titles(kp))

    def test_personal_entry_without_group_does_not_appear(self):
        self._entry(self.owner.id, shared=False, group_id=None, title="Export Personal No Group")
        self._run_export()
        kp = self._open_exported()
        self.assertNotIn("Export Personal No Group", self._all_entry_titles(kp))

    def test_personal_entry_in_personal_group_does_not_appear(self):
        group = self._personal_group(self.owner.id, "Export Personal Group For Entry")
        self._entry(self.owner.id, shared=False, group_id=group.id, title="Export Personal In Group")
        self._run_export()
        kp = self._open_exported()
        self.assertNotIn("Export Personal In Group", self._all_entry_titles(kp))
        self.assertNotIn("Export Personal Group For Entry", self._all_group_names(kp))

    def test_shared_entry_without_group_still_exports_under_ungrouped(self):
        self._entry(self.owner.id, shared=True, group_id=None, title="Export Shared No Group")
        self._run_export()
        kp = self._open_exported()
        entry_kp = kp.find_entries(title="Export Shared No Group", first=True)
        self.assertIsNotNone(entry_kp)
        self.assertEqual(entry_kp.group.name, "Sin Grupo")


class TestExportDefensiveInconsistentData(_SyncFixtures):
    """A shared entry whose group_id (due to historical/inconsistent data —
    this should never happen through the validated new()/edit() routes,
    but the exporter must not assume it can't) points at a personal group.
    The personal group must never be exported; the entry (shared=True)
    still exports, placed under the ungrouped bucket rather than under the
    personal group it happens to point to. No DB mutation to "fix" the
    inconsistency — the exporter only reads."""

    def setUp(self):
        super().setUp()
        self.owner = self.make_user("exportincon_owner", tools=["vault"])

    def test_shared_entry_pointing_at_personal_group_exports_ungrouped_not_under_personal_group(self):
        personal_group = self._personal_group(self.owner.id, "Inconsistent Personal Group")
        # Bypasses _validate_group_assignment() on purpose — simulating
        # historical/inconsistent data, not a path a real user can submit.
        self._entry(self.owner.id, shared=True, group_id=personal_group.id, title="Inconsistent Shared Entry")

        self._run_export()

        kp = self._open_exported()
        self.assertNotIn("Inconsistent Personal Group", self._all_group_names(kp))
        entry_kp = kp.find_entries(title="Inconsistent Shared Entry", first=True)
        self.assertIsNotNone(entry_kp)
        self.assertEqual(entry_kp.group.name, "Sin Grupo")

        # Defensive: the DB row itself is untouched by the export (read-only).
        db.session.refresh(
            VaultEntry.query.filter_by(title="Inconsistent Shared Entry").first()
        )
        entry = VaultEntry.query.filter_by(title="Inconsistent Shared Entry").first()
        self.assertEqual(entry.group_id, personal_group.id)


class TestImportGroupChain(PortalTestCase):
    """Direct unit tests of _get_or_create_group_chain() — KeePass import
    must only ever create/reuse scope="shared" groups."""

    def setUp(self):
        super().setUp()
        self.user = self.make_user("importchain_user", tools=["vault"])

    def test_new_path_creates_shared_groups_with_null_owner(self):
        leaf_id = _get_or_create_group_chain(["Import New Path"])

        group = db.session.get(VaultGroup, leaf_id)
        self.assertEqual(group.scope, "shared")
        self.assertIsNone(group.owner_id)

    def test_existing_shared_group_with_same_path_is_reused(self):
        first_id = _get_or_create_group_chain(["Import Reuse Path"])
        second_id = _get_or_create_group_chain(["Import Reuse Path"])

        self.assertEqual(first_id, second_id)
        self.assertEqual(VaultGroup.query.filter_by(name="Import Reuse Path").count(), 1)

    def test_existing_personal_group_with_same_name_is_not_reused(self):
        personal = VaultGroup(name="Import Ambiguous Name", scope="personal", owner_id=self.user.id)
        db.session.add(personal)
        db.session.commit()

        leaf_id = _get_or_create_group_chain(["Import Ambiguous Name"])

        self.assertNotEqual(leaf_id, personal.id)
        created = db.session.get(VaultGroup, leaf_id)
        self.assertEqual(created.scope, "shared")
        self.assertIsNone(created.owner_id)

    def test_shared_group_reused_over_personal_when_both_exist(self):
        personal = VaultGroup(name="Import Both Exist", scope="personal", owner_id=self.user.id)
        db.session.add(personal)
        db.session.commit()
        shared = VaultGroup(name="Import Both Exist", scope="shared")
        db.session.add(shared)
        db.session.commit()

        leaf_id = _get_or_create_group_chain(["Import Both Exist"])

        self.assertEqual(leaf_id, shared.id)
        self.assertNotEqual(leaf_id, personal.id)

    def test_full_parent_chain_created_by_import_is_entirely_shared(self):
        leaf_id = _get_or_create_group_chain(["Import Root", "Import Mid", "Import Leaf"])

        leaf = db.session.get(VaultGroup, leaf_id)
        mid = db.session.get(VaultGroup, leaf.parent_id)
        root = db.session.get(VaultGroup, mid.parent_id)

        for g in (leaf, mid, root):
            self.assertEqual(g.scope, "shared")
            self.assertIsNone(g.owner_id)
        self.assertIsNone(root.parent_id)


class TestImportEntries(PortalTestCase):
    """Real HTTP upload -> confirm flow, mirroring
    tests/vault/test_import_flow.py's established pattern — not a direct
    call to the private helper, which would need current_user faked."""

    def setUp(self):
        super().setUp()
        import_staging._staging.clear()
        self.admin = self.make_user("importentry_admin", is_admin=True)
        self.login("importentry_admin")

    def tearDown(self):
        import_staging._staging.clear()
        super().tearDown()

    def _csrf(self, url="/vault/import"):
        page = self.client.get(url)
        return self.extract_csrf(page.get_data(as_text=True))

    def _upload_and_confirm(self, title, group_name=None):
        token_csrf = self._csrf()
        kdbx_bytes = _make_synthetic_kdbx_with_group(title, group_name)
        upload_resp = self.client.post(
            "/vault/import",
            data={
                "kdbx_file": (io.BytesIO(kdbx_bytes), "test.kdbx"),
                "kdbx_password": SYNTHETIC_KDBX_IMPORT_PASSWORD,
                "csrf_token": token_csrf,
            },
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        with self.client.session_transaction() as sess:
            import_token = sess.get("vault_import_token")
        staged = import_staging.retrieve(import_token)
        new_uuid = staged["new"][0]["uuid"]
        confirm_csrf = self.extract_csrf(upload_resp.get_data(as_text=True))
        self.client.post(
            "/vault/import/confirm",
            data={"csrf_token": confirm_csrf, "import_new": new_uuid},
            follow_redirects=True,
        )

    def test_imported_entry_is_shared(self):
        title = "Imported Entry Shared Check"
        self.assertEqual(VaultEntry.query.filter_by(title=title).count(), 0)

        self._upload_and_confirm(title)

        matches = VaultEntry.query.filter_by(title=title).all()
        self.assertEqual(len(matches), 1)
        entry = matches[0]
        self.assertTrue(entry.shared)

    def test_imported_entry_with_group_path_is_associated_with_a_shared_group(self):
        title = "Imported Entry With Group"
        self.assertEqual(VaultEntry.query.filter_by(title=title).count(), 0)

        self._upload_and_confirm(title, group_name="Imported Group Path")

        matches = VaultEntry.query.filter_by(title=title).all()
        self.assertEqual(len(matches), 1)
        entry = matches[0]
        self.assertTrue(entry.shared)
        self.assertIsNotNone(entry.group_id)
        group = db.session.get(VaultGroup, entry.group_id)
        self.assertEqual(group.scope, "shared")
        self.assertIsNone(group.owner_id)

    def test_import_never_assigns_a_pre_existing_personal_group(self):
        title = "Imported Entry Must Not Get Personal Group"
        personal = VaultGroup(name="Same Name As Import Path", scope="personal", owner_id=self.admin.id)
        db.session.add(personal)
        db.session.commit()
        self.assertEqual(VaultEntry.query.filter_by(title=title).count(), 0)

        self._upload_and_confirm(title, group_name="Same Name As Import Path")

        matches = VaultEntry.query.filter_by(title=title).all()
        self.assertEqual(len(matches), 1)
        entry = matches[0]
        self.assertNotEqual(entry.group_id, personal.id)
        assigned_group = db.session.get(VaultGroup, entry.group_id)
        self.assertEqual(assigned_group.scope, "shared")
        self.assertIsNone(assigned_group.owner_id)

        # Exactly two groups now share this name: the pre-existing personal
        # one, untouched, and the shared one import created/reused.
        same_name_groups = VaultGroup.query.filter_by(name="Same Name As Import Path").all()
        self.assertEqual(len(same_name_groups), 2)
        scopes = {g.scope for g in same_name_groups}
        self.assertEqual(scopes, {"personal", "shared"})


class TestExportSecretsBoundaryRegression(_SyncFixtures):
    """Cross-cutting regression: build a DB with a mix of shared and
    personal data, run the real export, and confirm the resulting .kdbx
    contains ONLY shared data. This is the test that matters most in this
    phase — it crosses an actual secrets-exposure boundary."""

    def setUp(self):
        super().setUp()
        self.owner = self.make_user("boundary_owner", tools=["vault"])

    def test_export_contains_only_shared_data(self):
        shared_group = self._shared_group("Boundary Shared Group")
        personal_group = self._personal_group(self.owner.id, "Boundary Personal Group")
        self._entry(self.owner.id, shared=True, group_id=shared_group.id, title="Boundary Shared Entry")
        self._entry(self.owner.id, shared=False, group_id=personal_group.id, title="Boundary Personal Entry")

        self._run_export()

        kp = self._open_exported()
        group_names = self._all_group_names(kp)
        entry_titles = self._all_entry_titles(kp)

        self.assertIn("Boundary Shared Group", group_names)
        self.assertNotIn("Boundary Personal Group", group_names)
        self.assertIn("Boundary Shared Entry", entry_titles)
        self.assertNotIn("Boundary Personal Entry", entry_titles)
