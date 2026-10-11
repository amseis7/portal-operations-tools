"""Exercises the actual Alembic upgrade()/downgrade() for the `kind`
column — not db.create_all() (which every other test uses and which
would just build the CURRENT model, never proving the migration's
backfill logic runs correctly against a pre-existing row).

Replaying the full historical migration chain from an empty DB was tried
and hits an unrelated, pre-existing bug in a much older migration
(632d7ad28dd9 attempts `DROP TABLE manual_check`, a table that doesn't
exist on a from-scratch DB) — out of scope here, not touched, not fixed.
Instead this builds the CURRENT schema via db.create_all(), stamps it at
head, then uses this migration's own downgrade() to strip the `kind`
column back off (also exercising the downgrade path), inserts a
historical-shaped row, and re-runs upgrade() to prove the backfill."""
import os
import shutil
import tempfile
import unittest

import sqlalchemy as sa
from flask_migrate import downgrade, stamp, upgrade

from app import create_app
from tests.base import TestConfig

PREVIOUS_HEAD_REVISION = "36c6bc7ea6fa"  # add_knowledge_attachment_table, before `kind` existed


class MigrationTestConfig(TestConfig):
    pass


class TestKindColumnMigrationBackfill(unittest.TestCase):
    def test_existing_rows_backfill_to_attachment_on_upgrade(self):
        instance_dir = tempfile.mkdtemp(prefix="portal-test-instance-kindmigration-")
        db_path = os.path.join(instance_dir, "migration_test.db")
        MigrationTestConfig.SQLALCHEMY_DATABASE_URI = "sqlite:///" + db_path
        MigrationTestConfig.KB_ATTACHMENTS_DIR = os.path.join(instance_dir, "kb_attachments")
        app = create_app(config_class=MigrationTestConfig, instance_path=instance_dir)
        try:
            with app.app_context():
                from app.extensions import db

                # 1. Build the CURRENT schema directly (includes `kind`),
                # mark it as being at head, then use this migration's own
                # downgrade() to strip just the `kind` column/constraint
                # back off — reproducing the pre-existing-row shape
                # without replaying the broken historical chain.
                db.create_all()
                stamp(revision="head")
                downgrade(revision=PREVIOUS_HEAD_REVISION)

                engine = sa.create_engine(MigrationTestConfig.SQLALCHEMY_DATABASE_URI)
                with engine.begin() as conn:
                    conn.execute(sa.text(
                        "INSERT INTO user (username, password_hash, is_admin, must_change_password, nombre_completo) "
                        "VALUES ('miguser', 'x', 0, 0, 'Migration User')"
                    ))
                    user_id = conn.execute(sa.text("SELECT id FROM user WHERE username='miguser'")).scalar()
                    conn.execute(sa.text(
                        "INSERT INTO knowledge_article (title, problem_md, solution_md, author_id, created_at, updated_at) "
                        "VALUES ('t', 'p', 's', :author_id, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)"
                    ), {"author_id": user_id})
                    article_id = conn.execute(sa.text("SELECT id FROM knowledge_article WHERE title='t'")).scalar()
                    # A historical row, created before `kind` existed —
                    # exactly the shape upgrade() must be able to backfill.
                    conn.execute(sa.text(
                        "INSERT INTO knowledge_attachment "
                        "(article_id, original_filename, stored_filename, mime_type, extension, "
                        " size_bytes, sha256, is_image, uploaded_by, created_at, scan_status) "
                        "VALUES (:article_id, 'historic.png', 'historic-stored.png', 'image/png', 'png', "
                        " 10, 'deadbeef', 1, :uploaded_by, CURRENT_TIMESTAMP, 'clean')"
                    ), {"article_id": article_id, "uploaded_by": user_id})
                engine.dispose()

                # 2. Apply the new migration under test.
                upgrade()

                engine = sa.create_engine(MigrationTestConfig.SQLALCHEMY_DATABASE_URI)
                with engine.begin() as conn:
                    kind = conn.execute(sa.text(
                        "SELECT kind FROM knowledge_attachment WHERE original_filename='historic.png'"
                    )).scalar()
                engine.dispose()
                self.assertEqual(kind, "attachment")
        finally:
            app.apscheduler.shutdown(wait=False)
            shutil.rmtree(instance_dir, ignore_errors=True)
