"""add federation tables

Revision ID: a7f2b3d4e5c6
Revises: c31a392c3871
Create Date: 2026-03-28 02:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'a7f2b3d4e5c6'
down_revision: Union[str, Sequence[str], None] = 'c31a392c3871'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    # Create scope table
    if not inspector.has_table('scope'):
        op.create_table(
            'scope',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('name', sa.String, unique=True, index=True, nullable=False),
            sa.Column('description', sa.String, nullable=False),
            sa.Column('provider_id', sa.String, index=True, nullable=True),
            sa.Column('provider_scopes', sa.ARRAY(sa.String), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        )

        # Seed standard OIDC scopes
        op.execute(
            sa.text(
                "INSERT INTO scope (name, description, created_at) VALUES "
                "('openid', 'Verify your identity', NOW()), "
                "('profile', 'View your profile information', NOW()), "
                "('email', 'View your email address', NOW())"
            )
        )

    # Create external_provider table
    if not inspector.has_table('external_provider'):
        op.create_table(
            'external_provider',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('provider_id', sa.String, unique=True, index=True, nullable=False),
            sa.Column('display_name', sa.String, nullable=False),
            sa.Column('client_id', sa.String, nullable=False),
            sa.Column('client_secret_encrypted', sa.String, nullable=False),
            sa.Column('authorization_endpoint', sa.String, nullable=False),
            sa.Column('token_endpoint', sa.String, nullable=False),
            sa.Column('enabled', sa.Boolean, nullable=False, server_default='true'),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        )

    # Create external_token table
    if not inspector.has_table('external_token'):
        op.create_table(
            'external_token',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('identity_email', sa.String, index=True, nullable=False),
            sa.Column('provider_id', sa.String, index=True, nullable=False),
            sa.Column('access_token_encrypted', sa.String, nullable=False),
            sa.Column('refresh_token_encrypted', sa.String, nullable=True),
            sa.Column('token_type', sa.String, nullable=False, server_default='Bearer'),
            sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('scopes_granted', sa.ARRAY(sa.String), nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
            sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
            sa.UniqueConstraint('identity_email', 'provider_id', name='uq_external_token_user_provider'),
        )

    # Create federation_session table
    if not inspector.has_table('federation_session'):
        op.create_table(
            'federation_session',
            sa.Column('id', sa.Integer, primary_key=True),
            sa.Column('session_id', sa.String, unique=True, index=True, nullable=False),
            sa.Column('identity_email', sa.String, nullable=False),
            sa.Column('provider_id', sa.String, nullable=False),
            sa.Column('scopes_requested', sa.ARRAY(sa.String), nullable=True),
            sa.Column('oauth2_session_id', sa.String, nullable=True),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        )


def downgrade() -> None:
    op.drop_table('federation_session')
    op.drop_table('external_token')
    op.drop_table('external_provider')
    op.drop_table('scope')
