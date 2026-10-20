"""Exercises the actual Alembic upgrade()/downgrade() for dropping
KnowledgeArticle.client (product decision: KB must not store
customer-identifying information).

Same technique as tests/vault/test_vault_audit_log_migration.py: build the
CURRENT schema via db.create_all() (client already gone), stamp it at head,
use THIS migration's own downgrade() to recreate the `client` column, then
re-run upgrade() to prove the column (and its index) are dropped again.
"""
import os
import shutil
import tempfile
import unittest

import sqlalchemy as sa
from flask_migrate import downgrade, stamp, upgrade

from app import create_app
from tests.base import TestConfig

PREVIOUS_HEAD_REVISION = "d50ebdbf500a"  # drop_unused_vault_audit_log_table, before client was dropped
REVISION_UNDER_TEST = "1b5fd7e825ed"  # remove_client_from_knowledge_article


class MigrationTestConfig(TestConfig):
    pass


def _build_app_with_client_present(prefix="portal-test-instance-kbclient-"):
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


def _columns(engine, table):
    with engine.connect() as conn:
        return {c[1] for c in conn.execute(sa.text(f"PRAGMA table_info({table})")).fetchall()}


def _indexes(engine, table):
    with engine.connect() as conn:
        return {r[1] for r in conn.execute(sa.text(f"PRAGMA index_list({table})")).fetchall()}


def _alembic_version(engine):
    with engine.connect() as conn:
        return conn.execute(sa.text("SELECT version_num FROM alembic_version")).scalar()


class TestRemoveClientMigration(unittest.TestCase):
    def setUp(self):
        self.app, self.instance_dir = _build_app_with_client_present()
        self.addCleanup(shutil.rmtree, self.instance_dir, ignore_errors=True)

    def test_downgrade_recreates_client_column_and_index(self):
        with self.app.app_context():
            from app.extensions import db

            cols = _columns(db.engine, "knowledge_article")
            self.assertIn("client", cols)
            self.assertIn("ix_knowledge_article_client", _indexes(db.engine, "knowledge_article"))
            self.assertEqual(_alembic_version(db.engine), PREVIOUS_HEAD_REVISION)

    def test_upgrade_drops_client_column_and_index(self):
        with self.app.app_context():
            from app.extensions import db

            upgrade(revision=REVISION_UNDER_TEST)

            cols = _columns(db.engine, "knowledge_article")
            self.assertNotIn("client", cols)
            self.assertIn("platform", cols)  # untouched by this migration
            self.assertNotIn("ix_knowledge_article_client", _indexes(db.engine, "knowledge_article"))
            self.assertEqual(_alembic_version(db.engine), REVISION_UNDER_TEST)

    def test_upgrade_preserves_other_knowledge_article_rows(self):
        with self.app.app_context():
            from app.extensions import db

            # Insert a row shaped like the "before" schema (client populated)
            # to prove the drop doesn't touch unrelated columns/rows.
            with db.engine.begin() as conn:
                conn.execute(sa.text(
                    "INSERT INTO user (id, username, nombre_completo, password_hash, is_admin, must_change_password) "
                    "VALUES (1, 'autor', 'Autor', 'x', 0, 0)"
                ))
                conn.execute(sa.text(
                    "INSERT INTO knowledge_article "
                    "(id, title, problem_md, solution_md, client, platform, author_id, created_at, updated_at) "
                    "VALUES (1, 'T', 'P', 'S', 'ClienteX', 'Marca', 1, '2026-01-01', '2026-01-01')"
                ))

            upgrade(revision=REVISION_UNDER_TEST)

            with db.engine.connect() as conn:
                row = conn.execute(sa.text(
                    "SELECT title, platform FROM knowledge_article WHERE id = 1"
                )).fetchone()
            self.assertEqual(row[0], "T")
            self.assertEqual(row[1], "Marca")

    def test_downgrade_after_upgrade_recreates_column_empty(self):
        with self.app.app_context():
            from app.extensions import db

            upgrade(revision=REVISION_UNDER_TEST)
            downgrade(revision=PREVIOUS_HEAD_REVISION)

            cols = _columns(db.engine, "knowledge_article")
            self.assertIn("client", cols)
            self.assertIn("ix_knowledge_article_client", _indexes(db.engine, "knowledge_article"))
