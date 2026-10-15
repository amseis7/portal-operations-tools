"""Exercises the actual Alembic upgrade()/downgrade() for VaultGroup's
scope/owner_id columns (ADR-005) — not db.create_all() (which every other
Vault test uses and which would just build the CURRENT model, never proving
the migration's backfill logic runs against a pre-existing row).

Same technique as tests/knowledge_base/test_attachment_kind_migration.py:
build the CURRENT schema via db.create_all(), stamp it at head, use this
migration's own downgrade() to strip scope/owner_id back off, insert
historical-shaped rows, then re-run upgrade()/downgrade() to prove behavior.

Strategy (final, after two rounds of Codex review on an earlier FK-toggling
design): this project always runs migrations with PRAGMA foreign_keys=OFF —
nothing in the codebase ever sets it ON. Rather than transparently support
foreign_keys=ON inside this one revision (which required PRAGMA toggling
and autocommit_block(), and still left an unsafe window between the schema
commit and the alembic_version update), the migration now requires
foreign_keys=OFF and a clean PRAGMA foreign_key_check as explicit
preconditions, checked BEFORE any DDL. If either fails, nothing has been
touched yet — no rollback, no PRAGMA restoration, no retry guard needed."""
import os
import shutil
import tempfile
import unittest

import sqlalchemy as sa
from sqlalchemy import event
from flask_migrate import downgrade, stamp, upgrade

from app import create_app
from tests.base import TestConfig

PREVIOUS_HEAD_REVISION = "12f29f00be60"  # add_kind_to_knowledge_attachment, before scope/owner_id existed
REVISION_UNDER_TEST = "1edf6bb9b43e"  # add_scope_owner_to_vault_group


class MigrationTestConfig(TestConfig):
    pass


def _build_app_with_downgraded_schema(prefix="portal-test-instance-groupscope-"):
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


def _vault_group_columns(engine):
    with engine.connect() as conn:
        return {c[1] for c in conn.execute(sa.text("PRAGMA table_info(vault_group)")).fetchall()}


def _temp_batch_tables(engine):
    with engine.connect() as conn:
        rows = conn.execute(sa.text(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '_alembic_tmp_%'"
        )).fetchall()
        return [r[0] for r in rows]


def _seed_parent_child_and_entry(engine, suffix):
    """Historical-shaped rows (no scope/owner_id columns yet): a shared
    parent group, a child group under it, a user, and a VaultEntry pointing
    at the child group. Returns (parent_id, child_id)."""
    with engine.begin() as conn:
        conn.execute(sa.text(
            "INSERT INTO vault_group (uuid, name, created_at) "
            f"VALUES ('{suffix}-0000-0000-0000-000000000001', 'Padre', CURRENT_TIMESTAMP)"
        ))
        parent_id = conn.execute(sa.text("SELECT id FROM vault_group WHERE name='Padre'")).scalar()
        conn.execute(sa.text(
            "INSERT INTO vault_group (uuid, name, parent_id, created_at) "
            f"VALUES ('{suffix}-0000-0000-0000-000000000002', 'Hijo', :parent_id, CURRENT_TIMESTAMP)"
        ), {"parent_id": parent_id})
        child_id = conn.execute(sa.text("SELECT id FROM vault_group WHERE name='Hijo'")).scalar()
        conn.execute(sa.text(
            "INSERT INTO user (username, password_hash, is_admin, must_change_password, nombre_completo) "
            f"VALUES ('{suffix}owner', 'x', 0, 0, 'Seed Owner')"
        ))
        owner_id = conn.execute(sa.text(f"SELECT id FROM user WHERE username='{suffix}owner'")).scalar()
        conn.execute(sa.text(
            "INSERT INTO vault_entry "
            "(uuid, title, category, username, password_enc, shared, owner_id, group_id, created_at, updated_at) "
            f"VALUES ('{suffix}-0000-0000-0000-000000000003', 'Entrada', 'server', 'svc', 'ciphertext', 0, "
            ":owner_id, :group_id, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
        ), {"owner_id": owner_id, "group_id": child_id})
    return parent_id, child_id


class TestVaultGroupScopeMigrationSuccess(unittest.TestCase):
    """FK=OFF — this project's only real mode. upgrade()/downgrade() must
    succeed normally, preserve parent/child/entry links, and advance/revert
    alembic_version."""

    def test_upgrade_with_populated_data_preserves_links_and_advances_revision(self):
        app, instance_dir = _build_app_with_downgraded_schema()
        try:
            with app.app_context():
                from app.extensions import db

                parent_id, child_id = _seed_parent_child_and_entry(db.engine, "success-up")

                upgrade(revision=REVISION_UNDER_TEST)

                self.assertEqual(_alembic_version(db.engine), REVISION_UNDER_TEST)
                with db.engine.connect() as conn:
                    fk_errors = conn.execute(sa.text("PRAGMA foreign_key_check")).fetchall()
                    parent_row = conn.execute(sa.text(
                        "SELECT parent_id, scope, owner_id FROM vault_group WHERE name='Padre'"
                    )).fetchone()
                    child_row = conn.execute(sa.text(
                        "SELECT parent_id, scope, owner_id FROM vault_group WHERE name='Hijo'"
                    )).fetchone()
                    entry_row = conn.execute(sa.text(
                        "SELECT group_id FROM vault_entry WHERE title='Entrada'"
                    )).fetchone()

                self.assertEqual(fk_errors, [])
                self.assertIsNone(parent_row[0])
                self.assertEqual(parent_row[1], "shared")
                self.assertIsNone(parent_row[2])
                self.assertEqual(child_row[0], parent_id)
                self.assertEqual(child_row[1], "shared")
                self.assertEqual(entry_row[0], child_id)
        finally:
            app.apscheduler.shutdown(wait=False)
            shutil.rmtree(instance_dir, ignore_errors=True)

    def test_downgrade_with_populated_data_preserves_links_and_reverts_revision(self):
        app, instance_dir = _build_app_with_downgraded_schema()
        try:
            with app.app_context():
                from app.extensions import db

                parent_id, child_id = _seed_parent_child_and_entry(db.engine, "success-down")
                upgrade(revision=REVISION_UNDER_TEST)

                downgrade(revision=PREVIOUS_HEAD_REVISION)

                self.assertEqual(_alembic_version(db.engine), PREVIOUS_HEAD_REVISION)
                columns = _vault_group_columns(db.engine)
                self.assertNotIn("scope", columns)
                self.assertNotIn("owner_id", columns)
                with db.engine.connect() as conn:
                    fk_errors = conn.execute(sa.text("PRAGMA foreign_key_check")).fetchall()
                    child_row = conn.execute(sa.text(
                        "SELECT parent_id FROM vault_group WHERE name='Hijo'"
                    )).fetchone()
                    entry_row = conn.execute(sa.text(
                        "SELECT group_id FROM vault_entry WHERE title='Entrada'"
                    )).fetchone()

                self.assertEqual(fk_errors, [])
                self.assertEqual(child_row[0], parent_id)
                self.assertEqual(entry_row[0], child_id)
        finally:
            app.apscheduler.shutdown(wait=False)
            shutil.rmtree(instance_dir, ignore_errors=True)

    def test_existing_groups_migrate_to_shared_with_null_owner(self):
        app, instance_dir = _build_app_with_downgraded_schema()
        try:
            with app.app_context():
                # A historical row, created before scope/owner_id existed —
                # exactly the shape upgrade() must be able to backfill.
                engine = sa.create_engine(MigrationTestConfig.SQLALCHEMY_DATABASE_URI)
                with engine.begin() as conn:
                    conn.execute(sa.text(
                        "INSERT INTO vault_group (uuid, name, created_at) "
                        "VALUES ('11111111-1111-1111-1111-111111111111', 'Servidores', CURRENT_TIMESTAMP)"
                    ))
                engine.dispose()

                upgrade(revision=REVISION_UNDER_TEST)

                engine = sa.create_engine(MigrationTestConfig.SQLALCHEMY_DATABASE_URI)
                with engine.begin() as conn:
                    row = conn.execute(sa.text(
                        "SELECT scope, owner_id FROM vault_group WHERE name='Servidores'"
                    )).fetchone()
                engine.dispose()
                self.assertEqual(row[0], "shared")
                self.assertIsNone(row[1])
        finally:
            app.apscheduler.shutdown(wait=False)
            shutil.rmtree(instance_dir, ignore_errors=True)

    def test_downgrade_drops_scope_owner_without_destroying_groups_or_entries(self):
        app, instance_dir = _build_app_with_downgraded_schema()
        try:
            with app.app_context():
                from app.extensions import db

                upgrade(revision=REVISION_UNDER_TEST)

                engine = sa.create_engine(MigrationTestConfig.SQLALCHEMY_DATABASE_URI)
                with engine.begin() as conn:
                    conn.execute(sa.text(
                        "INSERT INTO vault_group (uuid, name, created_at, scope) "
                        "VALUES ('22222222-2222-2222-2222-222222222222', 'Redes', CURRENT_TIMESTAMP, 'shared')"
                    ))
                    conn.execute(sa.text(
                        "INSERT INTO user (username, password_hash, is_admin, must_change_password, nombre_completo) "
                        "VALUES ('migowner', 'x', 0, 0, 'Migration Owner')"
                    ))
                    owner_id = conn.execute(sa.text("SELECT id FROM user WHERE username='migowner'")).scalar()
                    group_id = conn.execute(sa.text("SELECT id FROM vault_group WHERE name='Redes'")).scalar()
                    conn.execute(sa.text(
                        "INSERT INTO vault_entry "
                        "(uuid, title, category, username, password_enc, shared, owner_id, group_id, created_at, updated_at) "
                        "VALUES ('33333333-3333-3333-3333-333333333333', 'Entrada', 'server', 'svc', 'ciphertext', 0, "
                        ":owner_id, :group_id, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                    ), {"owner_id": owner_id, "group_id": group_id})
                engine.dispose()

                downgrade(revision=PREVIOUS_HEAD_REVISION)

                engine = sa.create_engine(MigrationTestConfig.SQLALCHEMY_DATABASE_URI)
                with engine.begin() as conn:
                    columns = {c[1] for c in conn.execute(sa.text("PRAGMA table_info(vault_group)")).fetchall()}
                    group_row = conn.execute(sa.text("SELECT name FROM vault_group WHERE name='Redes'")).fetchone()
                    entry_row = conn.execute(sa.text("SELECT title FROM vault_entry WHERE title='Entrada'")).fetchone()
                engine.dispose()

                self.assertNotIn("scope", columns)
                self.assertNotIn("owner_id", columns)
                self.assertIsNotNone(group_row)  # the VaultGroup row itself survives
                self.assertIsNotNone(entry_row)  # the referencing VaultEntry row survives too
        finally:
            app.apscheduler.shutdown(wait=False)
            shutil.rmtree(instance_dir, ignore_errors=True)


class TestVaultGroupScopeMigrationForeignKeysOnFailsFast(unittest.TestCase):
    """foreign_keys=ON is never set anywhere in this project, but if a
    future connection/session had it on, this migration must refuse to run
    — and, critically, must NOT try to flip the pragma itself. Nothing may
    be touched: no DDL, no schema change, no pragma mutation."""

    def _enable_sqlite_fk_enforcement(self, engine):
        def _set_fk_pragma(dbapi_connection, connection_record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

        event.listen(engine, "connect", _set_fk_pragma)
        engine.dispose()

    def test_upgrade_aborts_before_any_ddl_when_foreign_keys_on(self):
        app, instance_dir = _build_app_with_downgraded_schema("portal-test-instance-groupscope-fkon-")
        try:
            with app.app_context():
                from app.extensions import db

                self._enable_sqlite_fk_enforcement(db.engine)
                with db.engine.connect() as conn:
                    self.assertEqual(conn.execute(sa.text("PRAGMA foreign_keys")).scalar(), 1)

                parent_id, child_id = _seed_parent_child_and_entry(db.engine, "fkon-up")
                version_before = _alembic_version(db.engine)

                with self.assertRaises(SystemExit) as cm:
                    upgrade(revision=REVISION_UNDER_TEST)
                self.assertEqual(cm.exception.code, 1)

                columns = _vault_group_columns(db.engine)
                version_after = _alembic_version(db.engine)
                with db.engine.connect() as conn:
                    pragma_after = conn.execute(sa.text("PRAGMA foreign_keys")).scalar()
                    child_row = conn.execute(sa.text(
                        "SELECT parent_id FROM vault_group WHERE name='Hijo'"
                    )).fetchone()
                    entry_row = conn.execute(sa.text(
                        "SELECT group_id FROM vault_entry WHERE title='Entrada'"
                    )).fetchone()

                self.assertNotIn("scope", columns)
                self.assertNotIn("owner_id", columns)
                self.assertEqual(version_after, version_before)
                self.assertEqual(version_after, PREVIOUS_HEAD_REVISION)
                self.assertEqual(child_row[0], parent_id)
                self.assertEqual(entry_row[0], child_id)
                # The migration must not have touched the pragma at all.
                self.assertEqual(pragma_after, 1)
        finally:
            app.apscheduler.shutdown(wait=False)
            shutil.rmtree(instance_dir, ignore_errors=True)

    def test_downgrade_aborts_before_any_ddl_when_foreign_keys_on(self):
        app, instance_dir = _build_app_with_downgraded_schema("portal-test-instance-groupscope-fkon-")
        try:
            with app.app_context():
                from app.extensions import db

                upgrade(revision=REVISION_UNDER_TEST)  # reach the revision under test first, with foreign_keys still OFF
                self._enable_sqlite_fk_enforcement(db.engine)
                with db.engine.connect() as conn:
                    self.assertEqual(conn.execute(sa.text("PRAGMA foreign_keys")).scalar(), 1)

                version_before = _alembic_version(db.engine)

                with self.assertRaises(SystemExit) as cm:
                    downgrade(revision=PREVIOUS_HEAD_REVISION)
                self.assertEqual(cm.exception.code, 1)

                columns = _vault_group_columns(db.engine)
                version_after = _alembic_version(db.engine)
                with db.engine.connect() as conn:
                    pragma_after = conn.execute(sa.text("PRAGMA foreign_keys")).scalar()

                # Still at the upgraded shape — downgrade never started.
                self.assertIn("scope", columns)
                self.assertIn("owner_id", columns)
                self.assertEqual(version_after, version_before)
                self.assertEqual(version_after, REVISION_UNDER_TEST)
                self.assertEqual(pragma_after, 1)
        finally:
            app.apscheduler.shutdown(wait=False)
            shutil.rmtree(instance_dir, ignore_errors=True)


class TestVaultGroupScopeMigrationOrphanPreflight(unittest.TestCase):
    """A pre-existing orphan (foreign_keys is OFF, exactly as it is
    everywhere in this project, so this kind of row can exist) must make
    the migration abort via the preflight check — before any DDL runs, not
    merely detected afterward."""

    def test_preexisting_orphan_aborts_before_any_ddl_then_retry_succeeds_after_fix(self):
        app, instance_dir = _build_app_with_downgraded_schema("portal-test-instance-groupscope-orphan-")
        try:
            with app.app_context():
                from app.extensions import db

                version_before = _alembic_version(db.engine)

                with db.engine.begin() as conn:
                    conn.execute(sa.text(
                        "INSERT INTO user (username, password_hash, is_admin, must_change_password, nombre_completo) "
                        "VALUES ('orphanowner', 'x', 0, 0, 'Orphan Owner')"
                    ))
                    owner_id = conn.execute(sa.text("SELECT id FROM user WHERE username='orphanowner'")).scalar()
                    # group_id points at a VaultGroup row that does not
                    # exist — only possible because foreign_keys is OFF,
                    # exactly as it is everywhere in this project today.
                    conn.execute(sa.text(
                        "INSERT INTO vault_entry "
                        "(uuid, title, category, username, password_enc, shared, owner_id, group_id, created_at, updated_at) "
                        "VALUES ('cccccccc-0000-0000-0000-000000000001', 'Entrada Huerfana', 'server', 'svc', "
                        "'ciphertext', 0, :owner_id, 999999, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                    ), {"owner_id": owner_id})

                with self.assertRaises(SystemExit) as cm:
                    upgrade(revision=REVISION_UNDER_TEST)
                self.assertEqual(cm.exception.code, 1)

                columns = _vault_group_columns(db.engine)
                temp_tables = _temp_batch_tables(db.engine)
                version_after = _alembic_version(db.engine)
                with db.engine.connect() as conn:
                    orphan_row = conn.execute(sa.text(
                        "SELECT group_id FROM vault_entry WHERE title='Entrada Huerfana'"
                    )).fetchone()

                # Preflight ran before any DDL — no temp table was ever
                # created, not even transiently.
                self.assertEqual(temp_tables, [])
                self.assertNotIn("scope", columns)
                self.assertNotIn("owner_id", columns)
                self.assertEqual(version_after, version_before)
                self.assertEqual(version_after, PREVIOUS_HEAD_REVISION)
                # The orphan itself is untouched — the migration must not
                # try to "fix" it, only refuse to proceed past it.
                self.assertIsNotNone(orphan_row)
                self.assertEqual(orphan_row[0], 999999)

                # Retry after fixing the orphan must succeed cleanly.
                with db.engine.begin() as conn:
                    conn.execute(sa.text("DELETE FROM vault_entry WHERE title='Entrada Huerfana'"))

                upgrade(revision=REVISION_UNDER_TEST)

                retry_columns = _vault_group_columns(db.engine)
                retry_version = _alembic_version(db.engine)
                with db.engine.connect() as conn:
                    retry_fk_errors = conn.execute(sa.text("PRAGMA foreign_key_check")).fetchall()

                self.assertIn("scope", retry_columns)
                self.assertIn("owner_id", retry_columns)
                self.assertEqual(retry_version, REVISION_UNDER_TEST)
                self.assertEqual(retry_fk_errors, [])
        finally:
            app.apscheduler.shutdown(wait=False)
            shutil.rmtree(instance_dir, ignore_errors=True)


class TestVaultGroupScopeMigrationInjectedFailureThenRetry(unittest.TestCase):
    """A failure during the batch recreate itself (unrelated to foreign
    keys — e.g. a transient error) must leave vault_group's own data fully
    intact and alembic_version unchanged, relying only on Alembic's normal
    per-migration transaction handling. Injected at rename_table()
    specifically — the true point-of-no-return with no Alembic-side
    cleanup at all (unlike drop_table(), which Alembic's own _create()
    wraps in its own try/except) — the strongest evidence this generalizes
    to any realistic failure, not just one specific injection point.

    SQLite/pysqlite's DDL-vs-DML autobegin split (see
    _cleanup_stale_empty_batch_table()'s docstring in the migration itself)
    means a failure here can leave an EMPTY _alembic_tmp_vault_group behind
    even though vault_group's own data rolls back correctly — confirmed
    empirically with two independent failure injection points. This test
    proves the migration's own cleanup guard makes a retry safe despite
    that leftover."""

    def test_upgrade_injected_failure_then_retry_completes_successfully(self):
        app, instance_dir = _build_app_with_downgraded_schema("portal-test-instance-groupscope-injfail-")
        try:
            with app.app_context():
                from app.extensions import db

                parent_id, child_id = _seed_parent_child_and_entry(db.engine, "injfail")
                version_before = _alembic_version(db.engine)

                import alembic.ddl.impl as alembic_impl
                original_rename_table = alembic_impl.DefaultImpl.rename_table

                def _failing_rename_table(self, old_name, new_name, **kw):
                    raise RuntimeError("Injected failure: simulated rename_table failure (point of no return)")

                alembic_impl.DefaultImpl.rename_table = _failing_rename_table
                try:
                    with self.assertRaises(SystemExit) as cm:
                        upgrade(revision=REVISION_UNDER_TEST)
                    self.assertEqual(cm.exception.code, 1)
                finally:
                    alembic_impl.DefaultImpl.rename_table = original_rename_table

                # --- state right after the failure ---
                columns = _vault_group_columns(db.engine)
                version_after = _alembic_version(db.engine)
                temp_tables = _temp_batch_tables(db.engine)
                with db.engine.connect() as conn:
                    fk_errors = conn.execute(sa.text("PRAGMA foreign_key_check")).fetchall()
                    parent_row = conn.execute(sa.text(
                        "SELECT id, parent_id FROM vault_group WHERE name='Padre'"
                    )).fetchone()
                    child_row = conn.execute(sa.text(
                        "SELECT id, parent_id FROM vault_group WHERE name='Hijo'"
                    )).fetchone()
                    entry_row = conn.execute(sa.text(
                        "SELECT group_id FROM vault_entry WHERE title='Entrada'"
                    )).fetchone()
                    if temp_tables:
                        temp_rows = conn.execute(sa.text(
                            "SELECT COUNT(*) FROM _alembic_tmp_vault_group"
                        )).scalar()

                self.assertNotIn("scope", columns)
                self.assertNotIn("owner_id", columns)
                self.assertEqual(version_after, version_before)
                self.assertEqual(version_after, PREVIOUS_HEAD_REVISION)
                self.assertIsNotNone(parent_row)
                self.assertEqual(parent_row[0], parent_id)
                self.assertIsNotNone(child_row)
                self.assertEqual(child_row[0], child_id)
                self.assertEqual(child_row[1], parent_id)
                self.assertIsNotNone(entry_row)
                self.assertEqual(entry_row[0], child_id)
                self.assertEqual(fk_errors, [])
                # If a temp table was left behind, it must be empty — the
                # guard's entire safety argument depends on this.
                if temp_tables:
                    self.assertEqual(temp_rows, 0)

                # --- retry (injection removed) must now succeed cleanly ---
                upgrade(revision=REVISION_UNDER_TEST)

                retry_columns = _vault_group_columns(db.engine)
                retry_version = _alembic_version(db.engine)
                retry_temp_tables = _temp_batch_tables(db.engine)
                with db.engine.connect() as conn:
                    retry_fk_errors = conn.execute(sa.text("PRAGMA foreign_key_check")).fetchall()
                    retry_parent = conn.execute(sa.text(
                        "SELECT parent_id, scope, owner_id FROM vault_group WHERE name='Padre'"
                    )).fetchone()
                    retry_child = conn.execute(sa.text(
                        "SELECT parent_id, scope, owner_id FROM vault_group WHERE name='Hijo'"
                    )).fetchone()
                    retry_entry = conn.execute(sa.text(
                        "SELECT group_id FROM vault_entry WHERE title='Entrada'"
                    )).fetchone()

                self.assertIn("scope", retry_columns)
                self.assertIn("owner_id", retry_columns)
                self.assertEqual(retry_temp_tables, [])
                self.assertEqual(retry_version, REVISION_UNDER_TEST)
                self.assertEqual(retry_fk_errors, [])
                self.assertIsNone(retry_parent[0])
                self.assertEqual(retry_parent[1], "shared")
                self.assertEqual(retry_child[0], parent_id)
                self.assertEqual(retry_child[1], "shared")
                self.assertEqual(retry_entry[0], child_id)
        finally:
            app.apscheduler.shutdown(wait=False)
            shutil.rmtree(instance_dir, ignore_errors=True)


class TestVaultGroupScopeMigrationStaleBatchTableGuard(unittest.TestCase):
    """Direct, isolated tests of _cleanup_stale_empty_batch_table()'s
    decision table, without needing a real failure injection to produce
    each shape."""

    def test_non_empty_stale_temp_table_aborts_without_touching_anything(self):
        app, instance_dir = _build_app_with_downgraded_schema("portal-test-instance-groupscope-stale-nonempty-")
        try:
            with app.app_context():
                from app.extensions import db

                parent_id, child_id = _seed_parent_child_and_entry(db.engine, "stalenonempty")
                version_before = _alembic_version(db.engine)

                # A leftover temp table that is NOT empty — must never be
                # silently deleted.
                with db.engine.begin() as conn:
                    conn.execute(sa.text(
                        "CREATE TABLE _alembic_tmp_vault_group ("
                        "id INTEGER NOT NULL, uuid VARCHAR(36) NOT NULL, name VARCHAR(120) NOT NULL, "
                        "parent_id INTEGER, icon_id INTEGER, created_at DATETIME NOT NULL, "
                        "scope VARCHAR(10) NOT NULL DEFAULT 'shared', owner_id INTEGER, "
                        "PRIMARY KEY (id))"
                    ))
                    conn.execute(sa.text(
                        "INSERT INTO _alembic_tmp_vault_group (uuid, name, created_at, scope) "
                        "VALUES ('stale-0000-0000-0000-000000000099', 'StaleRow', CURRENT_TIMESTAMP, 'shared')"
                    ))

                with self.assertRaises(SystemExit) as cm:
                    upgrade(revision=REVISION_UNDER_TEST)
                self.assertEqual(cm.exception.code, 1)

                columns = _vault_group_columns(db.engine)
                version_after = _alembic_version(db.engine)
                with db.engine.connect() as conn:
                    temp_row_count = conn.execute(sa.text(
                        "SELECT COUNT(*) FROM _alembic_tmp_vault_group"
                    )).scalar()
                    parent_row = conn.execute(sa.text(
                        "SELECT id, parent_id FROM vault_group WHERE name='Padre'"
                    )).fetchone()
                    entry_row = conn.execute(sa.text(
                        "SELECT group_id FROM vault_entry WHERE title='Entrada'"
                    )).fetchone()

                self.assertNotIn("scope", columns)  # vault_group itself untouched
                self.assertEqual(version_after, version_before)
                self.assertEqual(version_after, PREVIOUS_HEAD_REVISION)
                # The non-empty temp table was NOT deleted.
                self.assertEqual(temp_row_count, 1)
                # vault_group's own data untouched.
                self.assertEqual(parent_row[0], parent_id)
                self.assertEqual(entry_row[0], child_id)
        finally:
            app.apscheduler.shutdown(wait=False)
            shutil.rmtree(instance_dir, ignore_errors=True)

    def test_temp_table_without_vault_group_aborts_without_deleting_temp(self):
        app, instance_dir = _build_app_with_downgraded_schema("portal-test-instance-groupscope-stale-missing-")
        try:
            with app.app_context():
                from app.extensions import db

                version_before = _alembic_version(db.engine)

                # Ambiguous state: temp table exists, but vault_group
                # itself is gone (simulating a scenario this migration
                # should never guess about).
                with db.engine.begin() as conn:
                    conn.execute(sa.text(
                        "CREATE TABLE _alembic_tmp_vault_group ("
                        "id INTEGER NOT NULL, uuid VARCHAR(36) NOT NULL, name VARCHAR(120) NOT NULL, "
                        "parent_id INTEGER, icon_id INTEGER, created_at DATETIME NOT NULL, "
                        "scope VARCHAR(10) NOT NULL DEFAULT 'shared', owner_id INTEGER, "
                        "PRIMARY KEY (id))"
                    ))
                    conn.execute(sa.text("DROP TABLE vault_group"))

                with self.assertRaises(SystemExit) as cm:
                    upgrade(revision=REVISION_UNDER_TEST)
                self.assertEqual(cm.exception.code, 1)

                version_after = _alembic_version(db.engine)
                with db.engine.connect() as conn:
                    temp_still_exists = conn.execute(sa.text(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name='_alembic_tmp_vault_group'"
                    )).scalar()

                self.assertEqual(version_after, version_before)
                self.assertEqual(version_after, PREVIOUS_HEAD_REVISION)
                self.assertIsNotNone(temp_still_exists)  # not deleted
        finally:
            app.apscheduler.shutdown(wait=False)
            shutil.rmtree(instance_dir, ignore_errors=True)
