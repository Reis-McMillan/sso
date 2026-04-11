"""add userinfo_endpoint to external_provider and make subject non-nullable on external_token

Revision ID: g2b3c4d5e6f7
Revises: f1a2b3c4d5e6
Create Date: 2026-04-10 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'g2b3c4d5e6f7'
down_revision: Union[str, Sequence[str], None] = 'f1a2b3c4d5e6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    # Add userinfo_endpoint to external_provider
    ep_columns = [c['name'] for c in inspector.get_columns('external_provider')]
    if 'userinfo_endpoint' not in ep_columns:
        op.add_column(
            'external_provider',
            sa.Column('userinfo_endpoint', sa.String, nullable=True),
        )

    # Make subject non-nullable on external_token
    et_columns = {c['name']: c for c in inspector.get_columns('external_token')}
    if 'subject' in et_columns and et_columns['subject']['nullable']:
        op.alter_column('external_token', 'subject', nullable=False)


def downgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    # Make subject nullable again
    et_columns = {c['name']: c for c in inspector.get_columns('external_token')}
    if 'subject' in et_columns and not et_columns['subject']['nullable']:
        op.alter_column('external_token', 'subject', nullable=True)

    # Drop userinfo_endpoint from external_provider
    ep_columns = [c['name'] for c in inspector.get_columns('external_provider')]
    if 'userinfo_endpoint' in ep_columns:
        op.drop_column('external_provider', 'userinfo_endpoint')
