"""add prm_uri and required_scopes to oauth_client

Revision ID: i4d5e6f7g8h9
Revises: h3c4d5e6f7g8
Create Date: 2026-04-12 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'i4d5e6f7g8h9'
down_revision: Union[str, Sequence[str], None] = 'h3c4d5e6f7g8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    columns = [c['name'] for c in inspector.get_columns('oauth_client')]
    if 'prm_uri' not in columns:
        op.add_column('oauth_client', sa.Column('prm_uri', sa.String, nullable=True))
    if 'required_scopes' not in columns:
        op.add_column(
            'oauth_client',
            sa.Column('required_scopes', sa.ARRAY(sa.String), nullable=True),
        )


def downgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    columns = [c['name'] for c in inspector.get_columns('oauth_client')]
    if 'required_scopes' in columns:
        op.drop_column('oauth_client', 'required_scopes')
    if 'prm_uri' in columns:
        op.drop_column('oauth_client', 'prm_uri')
