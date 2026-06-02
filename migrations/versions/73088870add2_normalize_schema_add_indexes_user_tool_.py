"""normalize_schema_add_indexes_user_tool_notification_user_id

Revision ID: 73088870add2
Revises: 3cf82448f25f
Create Date: 2026-05-15 02:25:13.070441

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '73088870add2'
down_revision = '3cf82448f25f'
branch_labels = None
depends_on = None


def upgrade():
    # 1. Create user_tool table (many-to-many for authorized tools) - idempotent
    conn = op.get_bind()
    tables = [row[0] for row in conn.execute(sa.text("SELECT name FROM sqlite_master WHERE type='table'")).fetchall()]
    if 'user_tool' not in tables:
        op.create_table(
            'user_tool',
            sa.Column('user_id', sa.Integer(), nullable=False),
            sa.Column('tool_name', sa.String(length=50), nullable=False),
            sa.ForeignKeyConstraint(['user_id'], ['user.id']),
            sa.PrimaryKeyConstraint('user_id', 'tool_name')
        )

    # 2. Migrate data from authorized_tools CSV -> user_tool rows
    # Check if authorized_tools column exists (may have been dropped by create_all)
    user_cols = [row[1] for row in conn.execute(sa.text("PRAGMA table_info('user')")).fetchall()]
    if 'authorized_tools' in user_cols:
        tools_config_keys = ['csirt', 'virustotal']
        users = conn.execute(sa.text('SELECT id, authorized_tools FROM "user"')).fetchall()
        for user_row in users:
            raw = user_row[1] or ''
            if raw.strip() == '' or raw is None:
                continue
            tool_names = [t.strip() for t in raw.split(',') if t.strip()]
            if 'all' in [t.lower() for t in tool_names]:
                tool_names = tools_config_keys
            for tool_name in tool_names:
                conn.execute(
                    sa.text('INSERT OR IGNORE INTO user_tool (user_id, tool_name) VALUES (:uid, :tn)'),
                    {'uid': user_row[0], 'tn': tool_name}
                )

    # 3. Add new columns and indexes
    with op.batch_alter_table('alerta', schema=None) as batch_op:
        batch_op.add_column(sa.Column('user_id', sa.Integer(), nullable=True))
        batch_op.create_index(batch_op.f('ix_alerta_fecha_realizacion'), ['fecha_realizacion'], unique=False)
        batch_op.create_index(batch_op.f('ix_alerta_nombre_alerta'), ['nombre_alerta'], unique=False)
        batch_op.create_index(batch_op.f('ix_alerta_responsable'), ['responsable'], unique=False)
        batch_op.create_index(batch_op.f('ix_alerta_ticket'), ['ticket'], unique=False)
        batch_op.create_index('ix_alerta_ticket_tipo', ['ticket', 'tipo_alerta'], unique=False)
        batch_op.create_index(batch_op.f('ix_alerta_tipo_alerta'), ['tipo_alerta'], unique=False)
        batch_op.create_foreign_key('fk_alerta_user_id', 'user', ['user_id'], ['id'])

    with op.batch_alter_table('export_template', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_export_template_nombre_plataforma'), ['nombre_plataforma'], unique=False)
        batch_op.create_index(batch_op.f('ix_export_template_vt_engine_name'), ['vt_engine_name'], unique=False)

    with op.batch_alter_table('ioc', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_ioc_alerta_id'), ['alerta_id'], unique=False)

    with op.batch_alter_table('notification', schema=None) as batch_op:
        batch_op.add_column(sa.Column('user_id', sa.Integer(), nullable=True))
        batch_op.create_index(batch_op.f('ix_notification_category'), ['category'], unique=False)
        batch_op.create_index('ix_notification_read', ['is_read', 'timestamp'], unique=False)
        batch_op.create_foreign_key('fk_notification_user_id', 'user', ['user_id'], ['id'])

    # 4. Drop authorized_tools column (data already migrated to user_tool)
    #    Idempotent: only drop if column still exists
    user_cols = [row[1] for row in conn.execute(sa.text("PRAGMA table_info('user')")).fetchall()]
    if 'authorized_tools' in user_cols:
        with op.batch_alter_table('user', schema=None) as batch_op:
            batch_op.drop_column('authorized_tools')

    with op.batch_alter_table('vt_ioc', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_vt_ioc_ticket_id'), ['ticket_id'], unique=False)

    with op.batch_alter_table('vt_ticket', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_vt_ticket_fecha_creacion'), ['fecha_creacion'], unique=False)
        batch_op.create_index(batch_op.f('ix_vt_ticket_usuario_id'), ['usuario_id'], unique=False)


def downgrade():
    # 1. Drop new indexes and columns
    with op.batch_alter_table('vt_ticket', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_vt_ticket_usuario_id'))
        batch_op.drop_index(batch_op.f('ix_vt_ticket_fecha_creacion'))

    with op.batch_alter_table('vt_ioc', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_vt_ioc_ticket_id'))

    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('authorized_tools', sa.VARCHAR(length=200), nullable=True))

    # Reconstruct authorized_tools CSV from user_tool table
    conn = op.get_bind()
    conn.execute(sa.text(
        'UPDATE "user" SET authorized_tools = '
        '(SELECT GROUP_CONCAT(ut.tool_name) FROM user_tool ut WHERE ut.user_id = "user".id)'
    ))

    with op.batch_alter_table('notification', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.drop_index('ix_notification_read')
        batch_op.drop_index(batch_op.f('ix_notification_category'))
        batch_op.drop_column('user_id')

    with op.batch_alter_table('ioc', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_ioc_alerta_id'))

    with op.batch_alter_table('export_template', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_export_template_vt_engine_name'))
        batch_op.drop_index(batch_op.f('ix_export_template_nombre_plataforma'))

    with op.batch_alter_table('alerta', schema=None) as batch_op:
        batch_op.drop_constraint(None, type_='foreignkey')
        batch_op.drop_index(batch_op.f('ix_alerta_tipo_alerta'))
        batch_op.drop_index('ix_alerta_ticket_tipo')
        batch_op.drop_index(batch_op.f('ix_alerta_ticket'))
        batch_op.drop_index(batch_op.f('ix_alerta_responsable'))
        batch_op.drop_index(batch_op.f('ix_alerta_nombre_alerta'))
        batch_op.drop_index(batch_op.f('ix_alerta_fecha_realizacion'))
        batch_op.drop_column('user_id')

    # 2. Drop user_tool table
    op.drop_table('user_tool')