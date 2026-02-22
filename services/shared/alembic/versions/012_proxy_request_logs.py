"""Add proxy_request_logs table.

Revision ID: 012
Revises: 011
Create Date: 2026-02-22

"""

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "012"
down_revision = "011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create the proxy_request_logs table."""
    op.create_table(
        "proxy_request_logs",
        sa.Column(
            "id",
            sa.String(36),
            nullable=False,
            server_default=sa.text("NEWID()"),
            comment="Primary key (UUID).",
        ),
        sa.Column(
            "job_id",
            sa.String(36),
            sa.ForeignKey("jobs.id", ondelete="SET NULL"),
            nullable=True,
            comment="FK to the Job that triggered this call (nullable for API-originated calls).",
        ),
        sa.Column(
            "service",
            sa.String(64),
            nullable=False,
            server_default="unknown",
            comment="Originating service name, e.g. 'transcribe-worker'.",
        ),
        sa.Column(
            "operation",
            sa.String(128),
            nullable=False,
            server_default="unknown",
            comment="High-level operation label, e.g. 'fetch_transcript'.",
        ),
        sa.Column(
            "proxy_url_masked",
            sa.String(512),
            nullable=False,
            server_default="",
            comment="Proxy URL with password replaced by '***'.",
        ),
        sa.Column(
            "success",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("0"),
            comment="True if the yt-dlp call completed without exception.",
        ),
        sa.Column(
            "duration_ms",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
            comment="Wall-clock time for the call in milliseconds.",
        ),
        sa.Column(
            "error_type",
            sa.String(128),
            nullable=True,
            comment="Exception class name on failure.",
        ),
        sa.Column(
            "bytes_used",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
            comment="Approximate bytes consumed (0 when unknown).",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("SYSUTCDATETIME()"),
            comment="UTC timestamp when the record was inserted.",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_proxy_request_logs_job_id", "proxy_request_logs", ["job_id"])
    op.create_index("ix_proxy_request_logs_created_at", "proxy_request_logs", ["created_at"])


def downgrade() -> None:
    """Drop the proxy_request_logs table."""
    op.drop_index("ix_proxy_request_logs_created_at", table_name="proxy_request_logs")
    op.drop_index("ix_proxy_request_logs_job_id", table_name="proxy_request_logs")
    op.drop_table("proxy_request_logs")
