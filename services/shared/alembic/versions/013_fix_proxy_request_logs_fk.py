"""Fix proxy_request_logs job_id FK to reference Jobs.job_id

Revision ID: 013
Revises: 012
Create Date: 2026-02-22

The initial migration 012 created the proxy_request_logs.job_id column
with a FK referencing 'jobs.id', but the Jobs table PK column is 'job_id',
not 'id'. This migration drops and recreates the table with the correct FK.
The table contains only telemetry data (no business data) so recreation is safe.
"""

import sqlalchemy as sa
from alembic import op

revision = "013"
down_revision = "012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Drop the table created by migration 012 with the wrong FK
    op.drop_index("ix_proxy_request_logs_job_id", table_name="proxy_request_logs")
    op.drop_index("ix_proxy_request_logs_created_at", table_name="proxy_request_logs")
    op.drop_table("proxy_request_logs")

    # Recreate with the correct FK: Jobs.job_id
    op.create_table(
        "proxy_request_logs",
        sa.Column(
            "id",
            sa.String(36),
            nullable=False,
            server_default=sa.text("NEWID()"),
        ),
        sa.Column("job_id", sa.String(36), nullable=True),
        sa.Column("service", sa.String(64), nullable=False),
        sa.Column("operation", sa.String(128), nullable=False),
        sa.Column("proxy_url_masked", sa.String(512), nullable=True),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("duration_ms", sa.Integer(), nullable=True),
        sa.Column("bytes_used", sa.Integer(), nullable=True),
        sa.Column("error_type", sa.String(128), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("SYSUTCDATETIME()"),
        ),
        sa.ForeignKeyConstraint(
            ["job_id"],
            ["Jobs.job_id"],
            name="fk_proxy_request_logs_job_id",
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_proxy_request_logs"),
    )
    op.create_index(
        "ix_proxy_request_logs_created_at",
        "proxy_request_logs",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        "ix_proxy_request_logs_job_id",
        "proxy_request_logs",
        ["job_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_proxy_request_logs_job_id", table_name="proxy_request_logs")
    op.drop_index("ix_proxy_request_logs_created_at", table_name="proxy_request_logs")
    op.drop_table("proxy_request_logs")
