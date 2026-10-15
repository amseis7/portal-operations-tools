"""Technical debt #7: VaultAuditLog (and the vault_audit_log table it
backed) is removed — it had no active writer or reader; Vault's real
audit trail is the global AuditLog via log_audit(). These are small ORM/
runtime confirmation checks, not a re-test of log_audit() itself (already
covered elsewhere wherever Vault routes call it)."""
from tests.base import PortalTestCase
from app.extensions import db
from app.models.audit import AuditLog, log_audit


class TestVaultAuditLogRemoved(PortalTestCase):
    def test_vault_audit_log_is_not_importable_from_models(self):
        import app.vault.models as vault_models
        self.assertFalse(hasattr(vault_models, "VaultAuditLog"))

    def test_vault_entry_no_longer_exposes_audit_logs_relationship(self):
        from app.vault.models import VaultEntry
        self.assertFalse(hasattr(VaultEntry, "audit_logs"))

    def test_user_no_longer_exposes_vault_audit_logs_backref(self):
        from app.models.user import User
        self.assertFalse(hasattr(User, "vault_audit_logs"))

    def test_vault_audit_log_table_not_in_metadata(self):
        self.assertNotIn("vault_audit_log", db.metadata.tables)

    def test_db_create_all_still_works_without_vault_audit_log(self):
        """setUp()'s db.create_all() already ran by the time this test
        body executes — reaching this point at all is the assertion."""
        from app.vault.models import VaultEntry, VaultGroup  # noqa: F401
        self.assertIn("vault_entry", db.metadata.tables)
        self.assertIn("vault_group", db.metadata.tables)

    def test_audit_log_and_log_audit_are_unaffected(self):
        """The real, active audit system — untouched by this debt's
        remediation."""
        admin = self.make_user("auditlogremoved_admin", is_admin=True)
        with self.client:
            self.login("auditlogremoved_admin")
            self.client.get("/vault/")
            log_audit("vault", "view", "entry", 1, "Synthetic Entry")
            db.session.commit()

        row = AuditLog.query.filter_by(module="vault", action="view", object_id="1").first()
        self.assertIsNotNone(row)
        self.assertEqual(row.user_id, admin.id)
