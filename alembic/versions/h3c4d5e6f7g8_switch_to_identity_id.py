"""switch external_token, refresh_token, federation_session to identity_id; add first_name, last_name, email_verified to identity

Revision ID: h3c4d5e6f7g8
Revises: g2b3c4d5e6f7
Create Date: 2026-04-11 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'h3c4d5e6f7g8'
down_revision: Union[str, Sequence[str], None] = 'g2b3c4d5e6f7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _columns(inspector, table):
    return {c['name']: c for c in inspector.get_columns(table)}


def _unique_constraint_names(inspector, table):
    return {c['name'] for c in inspector.get_unique_constraints(table)}


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    # --- Identity table: add first_name, last_name, email_verified if missing ---
    id_cols = _columns(inspector, 'identity')
    if 'first_name' not in id_cols:
        op.add_column('identity', sa.Column('first_name', sa.String, nullable=True))
        conn.execute(sa.text("UPDATE identity SET first_name = '' WHERE first_name IS NULL"))
        op.alter_column('identity', 'first_name', nullable=False)
    if 'last_name' not in id_cols:
        op.add_column('identity', sa.Column('last_name', sa.String, nullable=True))
        conn.execute(sa.text("UPDATE identity SET last_name = '' WHERE last_name IS NULL"))
        op.alter_column('identity', 'last_name', nullable=False)
    if 'email_verified' not in id_cols:
        op.add_column(
            'identity',
            sa.Column('email_verified', sa.Boolean, nullable=False, server_default=sa.text('false')),
        )

    # --- external_token: identity_email -> identity_id ---
    et_cols = _columns(inspector, 'external_token')
    if 'identity_id' not in et_cols:
        op.add_column('external_token', sa.Column('identity_id', sa.Integer, nullable=True))
    if 'identity_email' in et_cols:
        conn.execute(sa.text(
            "UPDATE external_token SET identity_id = (SELECT id FROM identity WHERE identity.email = external_token.identity_email) "
            "WHERE identity_id IS NULL"
        ))
        # Drop rows that failed to backfill (orphans). Safer than leaving NULLs.
        conn.execute(sa.text("DELETE FROM external_token WHERE identity_id IS NULL"))
        op.alter_column('external_token', 'identity_id', nullable=False)
        # Drop old unique constraint before dropping the column
        et_constraints = _unique_constraint_names(inspector, 'external_token')
        if 'uq_external_token_user_subject_provider' in et_constraints:
            op.drop_constraint('uq_external_token_user_subject_provider', 'external_token', type_='unique')
        op.drop_column('external_token', 'identity_email')
    # Refresh inspector-derived constraints (after drops)
    inspector = sa.inspect(conn)
    et_constraints = _unique_constraint_names(inspector, 'external_token')
    if 'uq_external_token_user_subject_provider' not in et_constraints:
        op.create_unique_constraint(
            'uq_external_token_user_subject_provider',
            'external_token',
            ['identity_id', 'subject', 'provider_id'],
        )

    # --- refresh_token: identity_email -> identity_id ---
    inspector = sa.inspect(conn)
    rt_cols = _columns(inspector, 'refresh_token')
    if 'identity_id' not in rt_cols:
        op.add_column('refresh_token', sa.Column('identity_id', sa.Integer, nullable=True))
    if 'identity_email' in rt_cols:
        conn.execute(sa.text(
            "UPDATE refresh_token SET identity_id = (SELECT id FROM identity WHERE identity.email = refresh_token.identity_email) "
            "WHERE identity_id IS NULL"
        ))
        conn.execute(sa.text("DELETE FROM refresh_token WHERE identity_id IS NULL"))
        op.alter_column('refresh_token', 'identity_id', nullable=False)
        op.drop_column('refresh_token', 'identity_email')

    # --- federation_session: identity_email -> identity_id ---
    inspector = sa.inspect(conn)
    fs_cols = _columns(inspector, 'federation_session')
    if 'identity_id' not in fs_cols:
        op.add_column('federation_session', sa.Column('identity_id', sa.Integer, nullable=True))
    if 'identity_email' in fs_cols:
        conn.execute(sa.text(
            "UPDATE federation_session SET identity_id = (SELECT id FROM identity WHERE identity.email = federation_session.identity_email) "
            "WHERE identity_id IS NULL"
        ))
        conn.execute(sa.text("DELETE FROM federation_session WHERE identity_id IS NULL"))
        op.alter_column('federation_session', 'identity_id', nullable=False)
        op.drop_column('federation_session', 'identity_email')


def downgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    # federation_session
    fs_cols = _columns(inspector, 'federation_session')
    if 'identity_email' not in fs_cols:
        op.add_column('federation_session', sa.Column('identity_email', sa.String, nullable=True))
        conn.execute(sa.text(
            "UPDATE federation_session SET identity_email = (SELECT email FROM identity WHERE identity.id = federation_session.identity_id)"
        ))
        op.alter_column('federation_session', 'identity_email', nullable=False)
    if 'identity_id' in fs_cols:
        op.drop_column('federation_session', 'identity_id')

    # refresh_token
    inspector = sa.inspect(conn)
    rt_cols = _columns(inspector, 'refresh_token')
    if 'identity_email' not in rt_cols:
        op.add_column('refresh_token', sa.Column('identity_email', sa.String, nullable=True))
        conn.execute(sa.text(
            "UPDATE refresh_token SET identity_email = (SELECT email FROM identity WHERE identity.id = refresh_token.identity_id)"
        ))
        op.alter_column('refresh_token', 'identity_email', nullable=False)
    if 'identity_id' in rt_cols:
        op.drop_column('refresh_token', 'identity_id')

    # external_token
    inspector = sa.inspect(conn)
    et_cols = _columns(inspector, 'external_token')
    et_constraints = _unique_constraint_names(inspector, 'external_token')
    if 'uq_external_token_user_subject_provider' in et_constraints:
        op.drop_constraint('uq_external_token_user_subject_provider', 'external_token', type_='unique')
    if 'identity_email' not in et_cols:
        op.add_column('external_token', sa.Column('identity_email', sa.String, nullable=True))
        conn.execute(sa.text(
            "UPDATE external_token SET identity_email = (SELECT email FROM identity WHERE identity.id = external_token.identity_id)"
        ))
        op.alter_column('external_token', 'identity_email', nullable=False)
    if 'identity_id' in et_cols:
        op.drop_column('external_token', 'identity_id')
    op.create_unique_constraint(
        'uq_external_token_user_subject_provider',
        'external_token',
        ['identity_email', 'subject', 'provider_id'],
    )

    # identity: leave first_name/last_name/email_verified in place (safe default)
