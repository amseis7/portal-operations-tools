"""add slug to umbrella_herramienta

Revision ID: 2eb8bf6e14a4
Revises: 6b9cfbbdf5f7
Create Date: 2026-06-04 00:00:00.000000

"""
import re
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect


revision = '2eb8bf6e14a4'
down_revision = '6b9cfbbdf5f7'
branch_labels = None
depends_on = None


def _make_slug(nombre: str) -> str:
    s = nombre.lower().strip()
    s = re.sub(r'[^\w\s-]', '', s)
    s = re.sub(r'[\s_]+', '-', s)
    s = re.sub(r'-+', '-', s).strip('-')
    return s[:100]


def upgrade():
    conn = op.get_bind()

    # Add column only if it doesn't exist yet
    existing_cols = [col['name'] for col in inspect(conn).get_columns('umbrella_herramienta')]
    if 'slug' not in existing_cols:
        op.add_column('umbrella_herramienta',
            sa.Column('slug', sa.String(length=120), nullable=True))

    # Populate slugs for any rows that have NULL slug
    rows = conn.execute(
        sa.text("SELECT id, nombre FROM umbrella_herramienta WHERE slug IS NULL")
    ).fetchall()

    used = set(
        r[0] for r in conn.execute(
            sa.text("SELECT slug FROM umbrella_herramienta WHERE slug IS NOT NULL")
        ).fetchall()
    )

    for row_id, nombre in rows:
        base = _make_slug(nombre)
        slug, n = base, 1
        while slug in used:
            slug = f"{base}-{n}"
            n += 1
        used.add(slug)
        conn.execute(
            sa.text("UPDATE umbrella_herramienta SET slug=:s WHERE id=:i"),
            {"s": slug, "i": row_id}
        )

    # Add unique index only if not already present (SQLite uses unique indexes, not named constraints)
    existing_indexes = [idx['name'] for idx in inspect(conn).get_indexes('umbrella_herramienta')]
    if 'ix_umbrella_herramienta_slug' not in existing_indexes:
        op.create_index('ix_umbrella_herramienta_slug', 'umbrella_herramienta', ['slug'], unique=True)


def downgrade():
    op.drop_index('ix_umbrella_herramienta_slug', table_name='umbrella_herramienta')
    op.drop_column('umbrella_herramienta', 'slug')
