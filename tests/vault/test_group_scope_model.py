"""ADR-005: VaultGroup.scope/owner_id and ck_vault_group_scope_owner.

Exercises the CheckConstraint directly against the current model (via
PortalTestCase's db.create_all(), which emits the constraint's DDL) rather
than through any route — no route touches scope/owner_id yet (Phase 1 is
model + migration only)."""
from sqlalchemy.exc import IntegrityError

from tests.base import PortalTestCase
from app.extensions import db
from app.vault.models import VaultGroup


class TestVaultGroupScopeConstraint(PortalTestCase):
    def setUp(self):
        super().setUp()
        self.owner = self.make_user("groupowner")

    def test_shared_group_with_owner_id_is_rejected(self):
        db.session.add(VaultGroup(name="Servidores", scope="shared", owner_id=self.owner.id))
        with self.assertRaises(IntegrityError):
            db.session.commit()

    def test_personal_group_without_owner_id_is_rejected(self):
        db.session.add(VaultGroup(name="Mis accesos", scope="personal", owner_id=None))
        with self.assertRaises(IntegrityError):
            db.session.commit()

    def test_personal_group_with_owner_id_is_allowed(self):
        db.session.add(VaultGroup(name="Mis accesos", scope="personal", owner_id=self.owner.id))
        db.session.commit()  # must not raise

        saved = VaultGroup.query.filter_by(name="Mis accesos").first()
        self.assertEqual(saved.scope, "personal")
        self.assertEqual(saved.owner_id, self.owner.id)

    def test_shared_group_with_null_owner_is_allowed(self):
        db.session.add(VaultGroup(name="Servidores", scope="shared", owner_id=None))
        db.session.commit()  # must not raise

        saved = VaultGroup.query.filter_by(name="Servidores").first()
        self.assertEqual(saved.scope, "shared")
        self.assertIsNone(saved.owner_id)

    def test_omitting_scope_defaults_to_shared_via_server_default(self):
        """No Python-side default= is set (only server_default, applied at
        the DB level) — confirms a plain VaultGroup(name=...) still lands
        as scope="shared" without the caller specifying it explicitly."""
        group = VaultGroup(name="Redes")
        db.session.add(group)
        db.session.commit()

        db.session.refresh(group)
        self.assertEqual(group.scope, "shared")
        self.assertIsNone(group.owner_id)
