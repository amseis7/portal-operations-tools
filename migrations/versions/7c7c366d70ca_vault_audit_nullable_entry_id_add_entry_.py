"""vault_audit_nullable_entry_id_add_entry_title

Revision ID: 7c7c366d70ca
Revises: df3aeaa9dd65
Create Date: 2026-06-09 09:23:53.051757

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '7c7c366d70ca'
down_revision = 'df3aeaa9dd65'
branch_labels = None
depends_on = None


def upgrade():
    # SQLite batch mode recreates the table; use recreate='always' to avoid
    # unnamed-constraint errors while picking up the nullable change cleanly.
    with op.batch_alter_table('vault_audit_log', schema=None, recreate='always') as batch_op:
        batch_op.add_column(sa.Column('entry_title', sa.String(length=120), nullable=True))
        batch_op.alter_column('entry_id',
               existing_type=sa.INTEGER(),
               nullable=True)


def downgrade():
    with op.batch_alter_table('vault_audit_log', schema=None, recreate='always') as batch_op:
        batch_op.alter_column('entry_id',
               existing_type=sa.INTEGER(),
               nullable=False)
        batch_op.drop_column('entry_title')
