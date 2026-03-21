"""Authentication dependency for protecting API routes."""

from __future__ import annotations

import os
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


def _check_api_key(request: Request) -> AuthenticatedUser | None:
    """Check for a valid X-API-Key header. Returns user if valid, None otherwise."""
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        return None

    expected_key = os.environ.get("API_KEY")
    if not expected_key:
        return None

    if api_key != expected_key:
        return None

    return AuthenticatedUser(
        sub="api-key",
        email="openclaw@internal",
        name="OpenClaw",
        picture=None,
        raw={"sub": "api-key", "email": "openclaw@internal", "name": "OpenClaw"},
    )


async def require_auth(request: Request) -> AuthenticatedUser:
    """FastAPI dependency that requires a valid authenticated session.

    Supports two authentication methods:
    1. X-API-Key header (for programmatic access, e.g. MCP servers)
    2. Session cookie (for browser-based Auth0 sessions)

    Usage:
        @router.post("/endpoint")
        async def my_endpoint(user: AuthenticatedUser = Depends(require_auth)):
            print(user.sub)  # Auth0 user ID

    Raises:
        HTTPException 401 if no valid session exists.
    """
    # Check API key first (fast path for programmatic access)
    api_key_user = _check_api_key(request)
    if api_key_user:
        return api_key_user

    # Fall back to session cookie auth
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
