"""Add users, usage_records, expedite_requests tables and quota fields on Jobs.

Revision ID: 014
Revises: 013
Create Date: 2026-03-01

"""

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "014"
down_revision = "013"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create quota-related tables and add quota fields to Jobs."""
    # Users table
    op.create_table(
        "Users",
        sa.Column(
            "user_id",
            sa.String(36),
            nullable=False,
            server_default=sa.text("NEWID()"),
        ),
        sa.Column(
            "auth0_id",
            sa.String(255),
            nullable=False,
            comment="Auth0 'sub' claim",
        ),
        sa.Column("email", sa.String(255), nullable=True),
        sa.Column("display_name", sa.String(255), nullable=True),
        sa.Column(
            "quota_tier",
            sa.String(50),
            nullable=False,
            server_default="free",
            comment="Quota tier: 'free' or 'admin'",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("SYSUTCDATETIME()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("SYSUTCDATETIME()"),
        ),
        sa.PrimaryKeyConstraint("user_id"),
        sa.UniqueConstraint("auth0_id", name="uq_users_auth0_id"),
    )
    op.create_index("ix_users_auth0_id", "Users", ["auth0_id"], unique=True)
    op.create_index("ix_users_email", "Users", ["email"])

    # UsageRecords table
    op.create_table(
        "UsageRecords",
        sa.Column(
            "usage_id",
            sa.String(36),
            nullable=False,
            server_default=sa.text("NEWID()"),
        ),
        sa.Column(
            "user_id",
            sa.String(36),
            sa.ForeignKey("Users.user_id"),
            nullable=False,
        ),
        sa.Column(
            "operation_type",
            sa.String(50),
            nullable=False,
            comment="'video_submit' or 'copilot_query'",
        ),
        sa.Column(
            "resource_id",
            sa.String(255),
            nullable=True,
            comment="Optional reference to video_id, thread_id, etc.",
        ),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("SYSUTCDATETIME()"),
        ),
        sa.PrimaryKeyConstraint("usage_id"),
    )
    op.create_index(
        "ix_usage_user_op_created",
        "UsageRecords",
        ["user_id", "operation_type", "created_at"],
    )
    op.create_index("ix_usage_created", "UsageRecords", ["created_at"])

    # ExpediteRequests table
    op.create_table(
        "ExpediteRequests",
        sa.Column(
            "request_id",
            sa.String(36),
            nullable=False,
            server_default=sa.text("NEWID()"),
        ),
        sa.Column(
            "user_id",
            sa.String(36),
            sa.ForeignKey("Users.user_id"),
            nullable=False,
        ),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("video_count", sa.Integer(), nullable=False),
        sa.Column(
            "status",
            sa.String(50),
            nullable=False,
            server_default="pending",
            comment="'pending', 'approved', or 'denied'",
        ),
        sa.Column(
            "reviewed_by",
            sa.String(36),
            sa.ForeignKey("Users.user_id"),
            nullable=True,
        ),
        sa.Column("reviewed_at", sa.DateTime(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
            server_default=sa.text("SYSUTCDATETIME()"),
        ),
        sa.PrimaryKeyConstraint("request_id"),
    )
    op.create_index("ix_expedite_user", "ExpediteRequests", ["user_id"])
    op.create_index("ix_expedite_status", "ExpediteRequests", ["status"])
    op.create_index("ix_expedite_created", "ExpediteRequests", ["created_at"])

    # Add quota fields to Jobs table
    op.add_column(
        "Jobs",
        sa.Column(
            "quota_status",
            sa.String(50),
            nullable=False,
            server_default="released",
            comment="'quota_queued' or 'released'",
        ),
    )
    op.add_column(
        "Jobs",
        sa.Column(
            "user_id",
            sa.String(36),
            sa.ForeignKey("Users.user_id"),
            nullable=True,
            comment="User who submitted this job",
        ),
    )
    op.create_index("ix_jobs_quota_status", "Jobs", ["quota_status"])
    op.create_index("ix_jobs_user_id", "Jobs", ["user_id"])


def downgrade() -> None:
    """Remove quota-related tables and fields."""
    op.drop_index("ix_jobs_user_id", table_name="Jobs")
    op.drop_index("ix_jobs_quota_status", table_name="Jobs")
    op.drop_column("Jobs", "user_id")
    op.drop_column("Jobs", "quota_status")

    op.drop_index("ix_expedite_created", table_name="ExpediteRequests")
    op.drop_index("ix_expedite_status", table_name="ExpediteRequests")
    op.drop_index("ix_expedite_user", table_name="ExpediteRequests")
    op.drop_table("ExpediteRequests")

    op.drop_index("ix_usage_created", table_name="UsageRecords")
    op.drop_index("ix_usage_user_op_created", table_name="UsageRecords")
    op.drop_table("UsageRecords")

    op.drop_index("ix_users_email", table_name="Users")
    op.drop_index("ix_users_auth0_id", table_name="Users")
    op.drop_table("Users")
