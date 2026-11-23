"""add user approval fields

Revision ID: 0d2e7804abf4
Revises: 344306bdefdd
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = '0d2e7804abf4'
down_revision: Union[str, Sequence[str], None] = '344306bdefdd'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'users',
        sa.Column('approved_by_id', sa.Integer(), nullable=True)
    )

    op.add_column(
        'users',
        sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True)
    )

    op.add_column(
        'users',
        sa.Column('rejection_reason', sa.String(length=500), nullable=True)
    )

    op.create_foreign_key(
        'fk_users_approved_by',
        'users',
        'users',
        ['approved_by_id'],
        ['id']
    )


def downgrade() -> None:
    op.drop_constraint(
        'fk_users_approved_by',
        'users',
        type_='foreignkey'
    )

    op.drop_column('users', 'rejection_reason')
    op.drop_column('users', 'approved_at')
    op.drop_column('users', 'approved_by_id')