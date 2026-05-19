"""add role and identityrole tables; backfill from identity.roles

Revision ID: k6f7g8h9i0j1
Revises: j5e6f7g8h9i0
Create Date: 2026-05-19 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'k6f7g8h9i0j1'
down_revision: Union[str, Sequence[str], None] = 'j5e6f7g8h9i0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    if not inspector.has_table('role'):
        op.create_table(
            'role',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('name', sa.String, nullable=False),
            sa.UniqueConstraint('name', name='uq_role_name'),
        )

    if not inspector.has_table('identityrole'):
        op.create_table(
            'identityrole',
            sa.Column(
                'identity_id',
                sa.Integer,
                sa.ForeignKey('identity.id', ondelete='CASCADE'),
                primary_key=True,
            ),
            sa.Column(
                'role_id',
                sa.Integer,
                sa.ForeignKey('role.id', ondelete='CASCADE'),
                primary_key=True,
            ),
        )

    # Backfill from the legacy identity.roles ARRAY column if it still exists.
    identity_columns = {c['name'] for c in inspector.get_columns('identity')}
    if 'roles' in identity_columns:
        # Collect every distinct role name currently assigned to any identity.
        distinct_names = conn.execute(
            sa.text(
                "SELECT DISTINCT unnest(roles) AS name "
                "FROM identity WHERE roles IS NOT NULL"
            )
        ).all()
        for (name,) in distinct_names:
            conn.execute(
                sa.text(
                    "INSERT INTO role (name) VALUES (:name) "
                    "ON CONFLICT (name) DO NOTHING"
                ),
                {"name": name},
            )

        # Materialize (identity_id, role_id) pairs from the ARRAY column.
        conn.execute(
            sa.text(
                "INSERT INTO identityrole (identity_id, role_id) "
                "SELECT i.id, r.id "
                "FROM identity i, role r "
                "WHERE i.roles IS NOT NULL AND r.name = ANY(i.roles) "
                "ON CONFLICT DO NOTHING"
            )
        )

        op.drop_column('identity', 'roles')


def downgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    identity_columns = {c['name'] for c in inspector.get_columns('identity')}
    if 'roles' not in identity_columns:
        op.add_column(
            'identity',
            sa.Column(
                'roles',
                sa.ARRAY(sa.String),
                nullable=True,
            ),
        )

        if inspector.has_table('identityrole') and inspector.has_table('role'):
            conn.execute(
                sa.text(
                    "UPDATE identity i SET roles = sub.names "
                    "FROM ("
                    "  SELECT ir.identity_id, array_agg(r.name) AS names "
                    "  FROM identityrole ir "
                    "  JOIN role r ON r.id = ir.role_id "
                    "  GROUP BY ir.identity_id"
                    ") sub WHERE i.id = sub.identity_id"
                )
            )

    if inspector.has_table('identityrole'):
        op.drop_table('identityrole')
    if inspector.has_table('role'):
        op.drop_table('role')
