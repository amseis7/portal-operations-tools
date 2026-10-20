"""Exercises the actual Alembic upgrade()/downgrade() for dropping the
unused vault_audit_log table (technical-debt #7) — not db.create_all()
(which builds the CURRENT model, which no longer defines VaultAuditLog at
all, and so could never prove the migration's own guard logic runs).

Same technique as tests/vault/test_group_scope_migration.py: build the
CURRENT schema via db.create_all(), stamp it at head, use THIS migration's
own downgrade() to recreate vault_audit_log, insert historical-shaped
rows, then re-run upgrade()/downgrade() to prove behavior.

The most important property under test: this migration must NEVER drop a
table that still contains rows. vault_audit_log had no active writer or
reader since 2026-06-10 (Vault's real audit trail is the global AuditLog
via log_audit()), but it did have a brief real writer right after Vault's
initial release — an unexpected row in some other environment must abort
the migration, not be silently destroyed.
"""
import os
import shutil
import tempfile
import unittest

import sqlalchemy as sa
from flask_migrate import downgrade, stamp, upgrade

from app import create_app
from tests.base import TestConfig

PREVIOUS_HEAD_REVISION = "1edf6bb9b43e"  # add_scope_owner_to_vault_group, before vault_audit_log was dropped
REVISION_UNDER_TEST = "d50ebdbf500a"  # drop_unused_vault_audit_log_table


class MigrationTestConfig(TestConfig):
    pass


def _build_app_with_vault_audit_log_present(prefix="portal-test-instance-auditlog-"):
    """Stamp at head (current model, no vault_audit_log) then run THIS
    migration's own downgrade() to recreate vault_audit_log — the same
    "build current, then downgrade to get the 'before' shape" technique
    used for the VaultGroup scope/owner_id migration tests."""
    instance_dir = tempfile.mkdtemp(prefix=prefix)
    db_path = os.path.join(instance_dir, "migration_test.db")
    MigrationTestConfig.SQLALCHEMY_DATABASE_URI = "sqlite:///" + db_path
    MigrationTestConfig.KB_ATTACHMENTS_DIR = os.path.join(instance_dir, "kb_attachments")
    app = create_app(config_class=MigrationTestConfig, instance_path=instance_dir)
    with app.app_context():
        from app.extensions import db

        db.create_all()
        stamp(revision="head")
        downgrade(revision=PREVIOUS_HEAD_REVISION)
    return app, instance_dir


def _alembic_version(engine):
    with engine.connect() as conn:
        return conn.execute(sa.text("SELECT version_num FROM alembic_version")).scalar()


def _table_exists(engine, name):
    with engine.connect() as conn:
        return bool(conn.execute(sa.text(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=:name"
        ), {"name": name}).scalar())


def _vault_audit_log_columns(engine):
    with engine.connect() as conn:
        return {c[1] for c in conn.execute(sa.text("PRAGMA table_info(vault_audit_log)")).fetchall()}


def _seed_synthetic_audit_row(engine, suffix):
    """A historical-shaped row: a real user (to satisfy user_id NOT NULL
    + FK) and one vault_audit_log row referencing it, entry_id left NULL
    (the shape a log row takes once its entry was deleted — the exact
    reason entry_id was made nullable in migration 7c7c366d70ca)."""
    with engine.begin() as conn:
        conn.execute(sa.text(
            "INSERT INTO user (username, password_hash, is_admin, must_change_password, nombre_completo) "
            f"VALUES ('{suffix}user', 'x', 0, 0, 'Seed User')"
        ))
        user_id = conn.execute(sa.text(f"SELECT id FROM user WHERE username='{suffix}user'")).scalar()
        conn.execute(sa.text(
            "INSERT INTO vault_audit_log (user_id, action, timestamp, entry_title) "
            "VALUES (:user_id, 'view', CURRENT_TIMESTAMP, 'Synthetic Historical Entry')"
        ), {"user_id": user_id})
    return user_id


class TestVaultAuditLogMigrationUpgradeHappyPath(unittest.TestCase):
    def test_upgrade_drops_empty_table_and_advances_revision(self):
        app, instance_dir = _build_app_with_vault_audit_log_present()
        try:
            with app.app_context():
                from app.extensions import db

                self.assertTrue(_table_exists(db.engine, "vault_audit_log"))

                upgrade(revision=REVISION_UNDER_TEST)

                self.assertFalse(_table_exists(db.engine, "vault_audit_log"))
                self.assertEqual(_alembic_version(db.engine), REVISION_UNDER_TEST)
        finally:
            app.apscheduler.shutdown(wait=False)
            shutil.rmtree(instance_dir, ignore_errors=True)

    def test_other_vault_tables_remain_intact_after_upgrade(self):
        app, instance_dir = _build_app_with_vault_audit_log_present()
        try:
            with app.app_context():
                from app.extensions import db

                with db.engine.begin() as conn:
                    conn.execute(sa.text(
                        "INSERT INTO vault_group (uuid, name, created_at, scope) "
                        "VALUES ('44444444-4444-4444-4444-444444444444', 'Servidores', CURRENT_TIMESTAMP, 'shared')"
                    ))

                upgrade()

                with db.engine.connect() as conn:
                    group_row = conn.execute(sa.text(
                        "SELECT name FROM vault_group WHERE name='Servidores'"
                    )).fetchone()
                self.assertIsNotNone(group_row)
                self.assertTrue(_table_exists(db.engine, "vault_entry"))
                self.assertTrue(_table_exists(db.engine, "vault_group"))
        finally:
            app.apscheduler.shutdown(wait=False)
            shutil.rmtree(instance_dir, ignore_errors=True)


class TestVaultAuditLogMigrationFailClosed(unittest.TestCase):
    """The single most important behavior in this migration: it must
    never drop a table that still contains rows."""

    def test_upgrade_aborts_when_table_has_rows(self):
        app, instance_dir = _build_app_with_vault_audit_log_present(
            "portal-test-instance-auditlog-failclosed-"
        )
        try:
            with app.app_context():
                from app.extensions import db

                _seed_synthetic_audit_row(db.engine, "failclosed")
                version_before = _alembic_version(db.engine)

                with self.assertRaises(SystemExit) as cm:
                    upgrade()
                self.assertEqual(cm.exception.code, 1)

                self.assertTrue(_table_exists(db.engine, "vault_audit_log"))
                with db.engine.connect() as conn:
                    row = conn.execute(sa.text(
                        "SELECT entry_title FROM vault_audit_log"
                    )).fetchone()
                self.assertIsNotNone(row)
                self.assertEqual(row[0], "Synthetic Historical Entry")
                self.assertEqual(_alembic_version(db.engine), version_before)
                self.assertEqual(_alembic_version(db.engine), PREVIOUS_HEAD_REVISION)
        finally:
            app.apscheduler.shutdown(wait=False)
            shutil.rmtree(instance_dir, ignore_errors=True)


class TestVaultAuditLogMigrationDowngrade(unittest.TestCase):
    def test_downgrade_recreates_table_with_expected_columns_and_empty(self):
        app, instance_dir = _build_app_with_vault_audit_log_present(
            "portal-test-instance-auditlog-downgrade-"
        )
        try:
            with app.app_context():
                from app.extensions import db

                upgrade()
                self.assertFalse(_table_exists(db.engine, "vault_audit_log"))

                downgrade(revision=PREVIOUS_HEAD_REVISION)

                self.assertTrue(_table_exists(db.engine, "vault_audit_log"))
                columns = _vault_audit_log_columns(db.engine)
                self.assertEqual(
                    columns,
                    {"id", "entry_id", "entry_title", "user_id", "action", "timestamp", "ip_address"},
                )
                with db.engine.connect() as conn:
                    count = conn.execute(sa.text("SELECT COUNT(*) FROM vault_audit_log")).scalar()
                self.assertEqual(count, 0)
                self.assertEqual(_alembic_version(db.engine), PREVIOUS_HEAD_REVISION)
        finally:
            app.apscheduler.shutdown(wait=False)
            shutil.rmtree(instance_dir, ignore_errors=True)


class TestVaultAuditLogMigrationRetryAfterFix(unittest.TestCase):
    """Proves the guard doesn't leave anything broken: fix the offending
    data and the exact same upgrade() call succeeds."""

    def test_retry_succeeds_after_removing_offending_row(self):
        app, instance_dir = _build_app_with_vault_audit_log_present(
            "portal-test-instance-auditlog-retry-"
        )
        try:
            with app.app_context():
                from app.extensions import db

                _seed_synthetic_audit_row(db.engine, "retry")

                with self.assertRaises(SystemExit):
                    upgrade(revision=REVISION_UNDER_TEST)
                self.assertEqual(_alembic_version(db.engine), PREVIOUS_HEAD_REVISION)

                with db.engine.begin() as conn:
                    conn.execute(sa.text("DELETE FROM vault_audit_log"))

                upgrade(revision=REVISION_UNDER_TEST)

                self.assertFalse(_table_exists(db.engine, "vault_audit_log"))
                self.assertEqual(_alembic_version(db.engine), REVISION_UNDER_TEST)
        finally:
            app.apscheduler.shutdown(wait=False)
            shutil.rmtree(instance_dir, ignore_errors=True)
