"""remove client from knowledge_article

Revision ID: 1b5fd7e825ed
Revises: d50ebdbf500a
Create Date: 2026-10-20 12:30:00.000000

Product decision: Knowledge Base must not store customer-identifying
information. `client` was a plain free-text column (debt item #37) with no
FK/relationship and no reader outside the now-removed form field, filter,
and list/detail display — safe to drop outright, no data transform needed.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '1b5fd7e825ed'
down_revision = 'd50ebdbf500a'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('knowledge_article', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_knowledge_article_client'))
        batch_op.drop_column('client')


def downgrade():
    # Schema-only restore — the column's prior data is not recoverable here
    # (same pattern as d50ebdbf500a's downgrade), consistent with this being
    # a deliberate, non-reversible-by-design data removal.
    with op.batch_alter_table('knowledge_article', schema=None) as batch_op:
        batch_op.add_column(sa.Column('client', sa.String(length=120), nullable=True))
        batch_op.create_index(batch_op.f('ix_knowledge_article_client'), ['client'], unique=False)
