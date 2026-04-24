"""add email to external_token; make scope.provider_id unique

Revision ID: j5e6f7g8h9i0
Revises: i4d5e6f7g8h9
Create Date: 2026-04-17 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'j5e6f7g8h9i0'
down_revision: Union[str, Sequence[str], None] = 'i4d5e6f7g8h9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    # --- external_token: add email column (NOT NULL) ---
    et_columns = {c['name']: c for c in inspector.get_columns('external_token')}
    if 'email' not in et_columns:
        # Add nullable first so existing rows don't violate the constraint.
        op.add_column('external_token', sa.Column('email', sa.String, nullable=True))
        # Purge any rows we can't backfill (orphaned / pre-email tokens).
        conn.execute(sa.text("DELETE FROM external_token WHERE email IS NULL"))
        op.alter_column('external_token', 'email', nullable=False)
    elif et_columns['email'].get('nullable'):
        # Column exists but is nullable (interrupted prior upgrade).
        conn.execute(sa.text("DELETE FROM external_token WHERE email IS NULL"))
        op.alter_column('external_token', 'email', nullable=False)

    # --- scope.provider_id: add UNIQUE constraint ---
    scope_uniques = {c['name'] for c in inspector.get_unique_constraints('scope')}
    if 'uq_scope_provider_id' not in scope_uniques:
        op.create_unique_constraint(
            'uq_scope_provider_id',
            'scope',
            ['provider_id'],
        )


def downgrade() -> None:
    conn = op.get_bind()
    inspector = sa.inspect(conn)

    # Drop UNIQUE on scope.provider_id
    scope_uniques = {c['name'] for c in inspector.get_unique_constraints('scope')}
    if 'uq_scope_provider_id' in scope_uniques:
        op.drop_constraint('uq_scope_provider_id', 'scope', type_='unique')

    # Drop email from external_token
    et_columns = [c['name'] for c in inspector.get_columns('external_token')]
    if 'email' in et_columns:
        op.drop_column('external_token', 'email')
