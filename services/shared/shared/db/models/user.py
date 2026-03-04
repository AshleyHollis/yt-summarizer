"""User SQLAlchemy model for authentication and quota tracking."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import DateTime, Index, String, func
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, generate_uuid


class User(Base, TimestampMixin):
    """Registered user with quota tier assignment."""

    __tablename__ = "Users"

    user_id: Mapped[UUID] = mapped_column(
        primary_key=True,
        default=generate_uuid,
    )
    auth0_id: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        comment="Auth0 'sub' claim (e.g., 'auth0|abc123')",
    )
    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    quota_tier: Mapped[str] = mapped_column(
        String(50),
        default="free",
        nullable=False,
        comment="Quota tier: 'free' or 'admin'",
    )

    __table_args__ = (
        Index("ix_users_auth0_id", "auth0_id", unique=True),
        Index("ix_users_email", "email"),
    )
