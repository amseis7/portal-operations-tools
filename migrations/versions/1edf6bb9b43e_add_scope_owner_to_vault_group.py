"""add scope/owner to vault_group

Revision ID: 1edf6bb9b43e
Revises: 12f29f00be60
Create Date: 2026-10-14 10:20:00.000000

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1edf6bb9b43e'
down_revision = '12f29f00be60'
branch_labels = None
depends_on = None


def _require_foreign_keys_off():
    """SQLite batch table recreation (needed here for the CheckConstraint —
    SQLite can't add one via plain ALTER TABLE) drops and recreates
    vault_group, which vault_entry.group_id and vault_group.parent_id both
    reference. This project always runs with foreign_keys=OFF (verified:
    nothing in the codebase ever sets it ON) — fail fast instead of trying
    to toggle the pragma automatically."""
    bind = op.get_bind()
    enabled = bind.execute(sa.text("PRAGMA foreign_keys")).scalar()
    if enabled:
        raise RuntimeError(
            "This migration requires PRAGMA foreign_keys=OFF "
            "for SQLite batch table recreation. "
            "Disable foreign key enforcement for the migration "
            "session and retry."
        )


def _require_clean_foreign_key_check():
    """Preflight only — refuse to migrate a database that already has
    broken references rather than silently carrying them forward."""
    bind = op.get_bind()
    errors = bind.execute(sa.text("PRAGMA foreign_key_check")).fetchall()
    if errors:
        raise RuntimeError(
            f"Pre-existing foreign-key integrity violation(s) found before "
            f"migrating vault_group: {errors!r}. Fix the underlying data "
            f"before retrying this migration."
        )


def _cleanup_stale_empty_batch_table():
    """A failed SQLite batch recreate of vault_group (e.g. a crash
    mid-recreate) can leave `_alembic_tmp_vault_group` behind: pysqlite's
    legacy autobegin only starts an implicit transaction before
    INSERT/UPDATE/DELETE/REPLACE, not before CREATE/DROP/ALTER — so the
    temp table's own CREATE runs before any transaction exists and
    survives any later rollback, while the INSERT that copies rows into
    it runs inside the transaction that failure/rollback opened and does
    get undone. Confirmed empirically with two independent failure
    injection points (drop_table and rename_table): in both cases
    vault_group itself reappears with all its original data intact, and
    the leftover temp table is always empty.

    Only clean it up when that exact, verified-safe state is found. Any
    other shape (a non-empty temp table, or vault_group itself missing)
    aborts instead of guessing — this never reconstructs, copies, or
    renames anything on its own."""
    bind = op.get_bind()
    temp_exists = bind.execute(sa.text(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='_alembic_tmp_vault_group'"
    )).scalar()
    if not temp_exists:
        return

    vault_group_exists = bind.execute(sa.text(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='vault_group'"
    )).scalar()
    if not vault_group_exists:
        raise RuntimeError(
            "_alembic_tmp_vault_group exists but vault_group itself does not. "
            "This is an ambiguous state this migration will not guess about — "
            "inspect the database manually before retrying."
        )

    row_count = bind.execute(sa.text("SELECT COUNT(*) FROM _alembic_tmp_vault_group")).scalar()
    if row_count:
        raise RuntimeError(
            f"_alembic_tmp_vault_group exists and contains {row_count} row(s). "
            f"This migration will not delete a non-empty leftover table — "
            f"inspect and resolve it manually before retrying."
        )

    bind.execute(sa.text("DROP TABLE _alembic_tmp_vault_group"))


def upgrade():
    _require_foreign_keys_off()
    _require_clean_foreign_key_check()
    _cleanup_stale_empty_batch_table()

    # Autogenerate detects the new columns (scope has a server_default so
    # the NOT NULL column can be added against a table that may already
    # have rows) but does not detect CheckConstraints — added here by hand,
    # same pattern as ck_knowledge_attachment_kind (12f29f00be60). Every
    # existing row gets scope="shared" via the column default and
    # owner_id stays NULL (ADR-005: no ownership inference for historical
    # groups), which already satisfies the constraint below.
    with op.batch_alter_table('vault_group', schema=None) as batch_op:
        batch_op.add_column(sa.Column('scope', sa.String(length=10), server_default='shared', nullable=False))
        batch_op.add_column(sa.Column('owner_id', sa.Integer(), nullable=True))
        batch_op.create_foreign_key('fk_vault_group_owner_id', 'user', ['owner_id'], ['id'])
        batch_op.create_check_constraint(
            'ck_vault_group_scope_owner',
            "(scope = 'shared' AND owner_id IS NULL) OR (scope = 'personal' AND owner_id IS NOT NULL)",
        )


def downgrade():
    _require_foreign_keys_off()
    _require_clean_foreign_key_check()
    _cleanup_stale_empty_batch_table()

    # Drops the scope/personal distinction entirely — every VaultGroup row
    # and every VaultEntry row is left untouched otherwise. This is an
    # intentional, acknowledged loss of the scope/owner_id distinction
    # (ADR-005), not data destruction: no VaultGroup or VaultEntry row is
    # deleted, only these two columns and their constraints.
    with op.batch_alter_table('vault_group', schema=None) as batch_op:
        batch_op.drop_constraint('ck_vault_group_scope_owner', type_='check')
        batch_op.drop_constraint('fk_vault_group_owner_id', type_='foreignkey')
        batch_op.drop_column('owner_id')
        batch_op.drop_column('scope')
