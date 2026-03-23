"""add oidc models and last_auth_time

Revision ID: c31a392c3871
Revises:
Create Date: 2026-03-23 12:42:59.804083

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c31a392c3871'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add last_auth_time to identity table
    op.add_column(
        'identity',
        sa.Column('last_auth_time', sa.DateTime(timezone=True), nullable=True),
    )

    # Create oauth_client table
    op.create_table(
        'oauth_client',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('client_id', sa.String, unique=True, index=True, nullable=False),
        sa.Column('client_secret_hash', sa.String, nullable=True),
        sa.Column('client_name', sa.String, nullable=False),
        sa.Column('redirect_uris', sa.ARRAY(sa.String), nullable=True),
        sa.Column('allowed_scopes', sa.ARRAY(sa.String), nullable=True),
        sa.Column('grant_types', sa.ARRAY(sa.String), nullable=True),
        sa.Column('response_types', sa.ARRAY(sa.String), nullable=True),
        sa.Column('token_endpoint_auth_method', sa.String, nullable=False, server_default='client_secret_basic'),
        sa.Column('is_public', sa.Boolean, nullable=False, server_default='false'),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('owner_email', sa.String, nullable=True),
    )

    # Create authorization_code table
    op.create_table(
        'authorization_code',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('code', sa.String, unique=True, index=True, nullable=False),
        sa.Column('client_id', sa.String, nullable=False),
        sa.Column('identity_email', sa.String, nullable=False),
        sa.Column('redirect_uri', sa.String, nullable=False),
        sa.Column('scopes', sa.ARRAY(sa.String), nullable=True),
        sa.Column('nonce', sa.String, nullable=True),
        sa.Column('code_challenge', sa.String, nullable=True),
        sa.Column('code_challenge_method', sa.String, nullable=True),
        sa.Column('auth_time', sa.DateTime(timezone=True), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('used', sa.Boolean, nullable=False, server_default='false'),
    )

    # Create refresh_token table
    op.create_table(
        'refresh_token',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('token', sa.String, unique=True, index=True, nullable=False),
        sa.Column('client_id', sa.String, nullable=False),
        sa.Column('identity_email', sa.String, nullable=False),
        sa.Column('scopes', sa.ARRAY(sa.String), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
        sa.Column('revoked', sa.Boolean, nullable=False, server_default='false'),
        sa.Column('replaced_by', sa.String, nullable=True),
    )

    # Create consent table
    op.create_table(
        'consent',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('identity_email', sa.String, nullable=False),
        sa.Column('client_id', sa.String, nullable=False),
        sa.Column('scopes', sa.ARRAY(sa.String), nullable=True),
        sa.Column('granted_at', sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint('identity_email', 'client_id', name='uq_consent_user_client'),
    )

    # Create oauth2_session table
    op.create_table(
        'oauth2_session',
        sa.Column('id', sa.Integer, primary_key=True),
        sa.Column('session_id', sa.String, unique=True, index=True, nullable=False),
        sa.Column('client_id', sa.String, nullable=False),
        sa.Column('redirect_uri', sa.String, nullable=False),
        sa.Column('response_type', sa.String, nullable=False),
        sa.Column('scope', sa.String, nullable=False),
        sa.Column('state', sa.String, nullable=True),
        sa.Column('nonce', sa.String, nullable=True),
        sa.Column('code_challenge', sa.String, nullable=True),
        sa.Column('code_challenge_method', sa.String, nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_table('oauth2_session')
    op.drop_table('consent')
    op.drop_table('refresh_token')
    op.drop_table('authorization_code')
    op.drop_table('oauth_client')
    op.drop_column('identity', 'last_auth_time')
