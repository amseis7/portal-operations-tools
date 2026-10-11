"""add kind to knowledge attachment

Revision ID: 12f29f00be60
Revises: 36c6bc7ea6fa
Create Date: 2026-10-09 23:25:21.918641

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '12f29f00be60'
down_revision = '36c6bc7ea6fa'
branch_labels = None
depends_on = None


def upgrade():
    # Autogenerate correctly detects the new column (with its server_default,
    # required so the NOT NULL column can be added against a table that may
    # already have rows) but does not detect CheckConstraints — added here
    # by hand, mirroring the existing ck_knowledge_attachment_exactly_one_owner
    # already on this same table. No Markdown parsing: every existing row
    # simply gets kind="attachment" via the column default.
    with op.batch_alter_table('knowledge_attachment', schema=None) as batch_op:
        batch_op.add_column(sa.Column('kind', sa.String(length=20), server_default='attachment', nullable=False))
        batch_op.create_check_constraint(
            'ck_knowledge_attachment_kind', "kind IN ('attachment', 'inline')"
        )


def downgrade():
    with op.batch_alter_table('knowledge_attachment', schema=None) as batch_op:
        batch_op.drop_constraint('ck_knowledge_attachment_kind', type_='check')
        batch_op.drop_column('kind')
