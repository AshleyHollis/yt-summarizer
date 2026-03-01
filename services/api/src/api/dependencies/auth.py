"""Authentication dependency for protecting API routes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from fastapi import HTTPException, Request, status

try:
    from shared.config import get_settings
    from shared.logging.config import get_logger
except ImportError:
    import logging

    def get_settings():
        class MockSettings:
            class auth:
                session_cookie_name = "session"

        return MockSettings()

    def get_logger(name: str | None = None):
        return logging.getLogger(name)


from ..routes.auth import session_store

logger = get_logger(__name__)


@dataclass
class AuthenticatedUser:
    """Represents an authenticated user extracted from session."""

    sub: str  # Auth0 user ID (e.g., "auth0|abc123")
    email: str | None
    name: str | None
    picture: str | None
    raw: dict[str, Any]  # Full user_info dict from Auth0


async def require_auth(request: Request) -> AuthenticatedUser:
    """FastAPI dependency that requires a valid authenticated session.

    Usage:
        @router.post("/endpoint")
        async def my_endpoint(user: AuthenticatedUser = Depends(require_auth)):
            print(user.sub)  # Auth0 user ID

    Raises:
        HTTPException 401 if no valid session exists.
    """
    settings = get_settings()
    session_cookie_name = settings.auth.session_cookie_name

    session_id = request.cookies.get(session_cookie_name)
    if not session_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )

    session_data = await session_store.get_session(session_id)
    if not session_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session expired or invalid",
        )

    user_info = session_data.user_info
    return AuthenticatedUser(
        sub=user_info.get("sub", ""),
        email=user_info.get("email"),
        name=user_info.get("name"),
        picture=user_info.get("picture"),
        raw=user_info,
    )


async def optional_auth(request: Request) -> AuthenticatedUser | None:
    """FastAPI dependency that returns the authenticated user if present, or None.

    Useful for routes that work for both authenticated and anonymous users
    but may provide enhanced functionality for authenticated users.
    """
    try:
        return await require_auth(request)
    except HTTPException:
        return None
