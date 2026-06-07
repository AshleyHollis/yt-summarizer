"""Add label column to Segments table.

Revision ID: 015
Revises: 014
Create Date: 2026-04-06

"""

import sqlalchemy as sa

from alembic import op

revision = "015"
down_revision = "014"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "Segments",
        sa.Column("label", sa.String(200), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("Segments", "label")
