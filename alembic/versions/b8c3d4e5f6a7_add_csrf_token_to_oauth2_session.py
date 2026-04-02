"""add csrf_token to oauth2_session

Revision ID: b8c3d4e5f6a7
Revises: a7f2b3d4e5c6
Create Date: 2026-03-29 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b8c3d4e5f6a7'
down_revision: Union[str, Sequence[str], None] = 'a7f2b3d4e5c6'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('oauth2_session', sa.Column('csrf_token', sa.String, nullable=True))


def downgrade() -> None:
    op.drop_column('oauth2_session', 'csrf_token')
