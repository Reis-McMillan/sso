"""move provider_scopes from scope to external_provider

Revision ID: d9e4f5a6b7c8
Revises: b8c3d4e5f6a7
Create Date: 2026-04-02 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd9e4f5a6b7c8'
down_revision: Union[str, Sequence[str], None] = 'b8c3d4e5f6a7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add scopes column to external_provider
    op.add_column(
        'external_provider',
        sa.Column('scopes', sa.ARRAY(sa.String), nullable=True),
    )

    # Migrate data: aggregate provider_scopes from scope table into external_provider
    conn = op.get_bind()
    rows = conn.execute(sa.text(
        "SELECT DISTINCT provider_id FROM scope WHERE provider_id IS NOT NULL"
    )).fetchall()
    for (pid,) in rows:
        scope_rows = conn.execute(sa.text(
            "SELECT provider_scopes FROM scope WHERE provider_id = :pid AND provider_scopes IS NOT NULL"
        ), {"pid": pid}).fetchall()
        all_scopes = set()
        for (ps,) in scope_rows:
            if ps:
                all_scopes.update(ps)
        if all_scopes:
            conn.execute(sa.text(
                "UPDATE external_provider SET scopes = :scopes WHERE provider_id = :pid"
            ), {"scopes": list(all_scopes), "pid": pid})

    # Drop provider_scopes column from scope
    op.drop_column('scope', 'provider_scopes')


def downgrade() -> None:
    # Add provider_scopes column back to scope
    op.add_column(
        'scope',
        sa.Column('provider_scopes', sa.ARRAY(sa.String), nullable=True),
    )

    # Migrate data back: copy provider scopes to all scopes with that provider_id
    conn = op.get_bind()
    rows = conn.execute(sa.text(
        "SELECT provider_id, scopes FROM external_provider WHERE scopes IS NOT NULL"
    )).fetchall()
    for pid, scopes in rows:
        if scopes:
            conn.execute(sa.text(
                "UPDATE scope SET provider_scopes = :scopes WHERE provider_id = :pid"
            ), {"scopes": scopes, "pid": pid})

    # Drop scopes column from external_provider
    op.drop_column('external_provider', 'scopes')
