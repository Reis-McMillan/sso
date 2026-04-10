"""add jwks_uri to external_provider and subject to external_token

Revision ID: e0f1a2b3c4d5
Revises: d9e4f5a6b7c8
Create Date: 2026-04-09 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e0f1a2b3c4d5'
down_revision: Union[str, Sequence[str], None] = 'd9e4f5a6b7c8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add jwks_uri to external_provider
    op.add_column(
        'external_provider',
        sa.Column('jwks_uri', sa.String, nullable=True),
    )

    # Add subject to external_token
    op.add_column(
        'external_token',
        sa.Column('subject', sa.String, nullable=True),
    )

    # Drop old uniqueness constraint and create new one
    op.drop_constraint('uq_external_token_user_provider', 'external_token', type_='unique')
    op.create_unique_constraint(
        'uq_external_token_user_subject_provider',
        'external_token',
        ['identity_email', 'subject', 'provider_id'],
    )


def downgrade() -> None:
    # Restore old uniqueness constraint
    op.drop_constraint('uq_external_token_user_subject_provider', 'external_token', type_='unique')
    op.create_unique_constraint(
        'uq_external_token_user_provider',
        'external_token',
        ['identity_email', 'provider_id'],
    )

    # Drop subject from external_token
    op.drop_column('external_token', 'subject')

    # Drop jwks_uri from external_provider
    op.drop_column('external_provider', 'jwks_uri')
