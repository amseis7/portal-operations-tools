"""drop unused vault_audit_log table

Revision ID: d50ebdbf500a
Revises: 1edf6bb9b43e
Create Date: 2026-10-15 15:44:14.658160

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd50ebdbf500a'
down_revision = '1edf6bb9b43e'
branch_labels = None
depends_on = None


def _vault_audit_log_exists(bind):
    return bool(bind.execute(sa.text(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='vault_audit_log'"
    )).scalar())


def _require_empty_vault_audit_log(bind):
    """Fail closed if vault_audit_log contains any row (technical-debt
    #7). This table has had no active writer or reader since 2026-06-10
    — Vault's real audit trail is the global AuditLog via log_audit() —
    but it did have a real writer for a short window right after the
    Vault feature's initial release, so an unexpected row surviving in
    some other environment must never be silently destroyed. This
    migration only ever drops a table it has itself just confirmed is
    empty; it never inspects row content, migrates rows, or deletes
    rows — only a human can decide what to do with unexpected data."""
    count = bind.execute(sa.text("SELECT COUNT(*) FROM vault_audit_log")).scalar()
    if count:
        raise RuntimeError(
            f"vault_audit_log contains {count} historical row(s); refusing "
            f"to drop table. This table has no active writer or reader — "
            f"Vault's real audit trail is the global AuditLog via "
            f"log_audit() — but this migration will not destroy "
            f"unexpected data automatically. Review the row(s) manually "
            f"before retrying this migration."
        )


def upgrade():
    bind = op.get_bind()
    if not _vault_audit_log_exists(bind):
        # Already in the expected end state (e.g. a fresh install that
        # never had this table) — nothing to do, not a failure.
        return
    _require_empty_vault_audit_log(bind)
    op.drop_table('vault_audit_log')


def downgrade():
    # Recreates the table's final historical schema, empty. This reverts
    # schema only — any rows that existed before upgrade() dropped the
    # table are not, and cannot be, restored by this downgrade.
    op.create_table(
        'vault_audit_log',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('entry_id', sa.Integer(), nullable=True),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('action', sa.String(length=30), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('entry_title', sa.String(length=120), nullable=True),
        sa.ForeignKeyConstraint(
            ['entry_id'], ['vault_entry.id'],
            name='fk_vault_audit_log_entry_id', ondelete='SET NULL',
        ),
        sa.ForeignKeyConstraint(['user_id'], ['user.id']),
        sa.PrimaryKeyConstraint('id'),
    )
