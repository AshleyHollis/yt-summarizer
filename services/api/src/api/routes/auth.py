from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlencode, urlparse

import httpx
from fastapi import APIRouter, HTTPException, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel

from ..middleware.correlation import get_correlation_id

try:
    from shared.config import get_settings
    from shared.logging.config import get_logger
except ImportError:
    import logging

    def get_settings():
        class MockSettings:
            class api:
                cors_origins = ["http://localhost:3000"]
                cors_origin_regex = r"^https://.*\.azurestaticapps\.net$"

            class auth:
                domain = ""
                client_id = ""
                client_secret = ""
                audience = None
                session_secret = "dev-secret"
                session_ttl_seconds = 86400
                default_return_to = "http://localhost:3000"
                session_cookie_name = "session"

        return MockSettings()

    def get_logger(name: str | None = None):
        return logging.getLogger(name)


logger = get_logger(__name__)
router = APIRouter(prefix="/api/auth", tags=["Auth"])


@dataclass
class SessionData:
    user_info: dict[str, Any]
    access_token: str
    id_token: str | None
    expires_at: datetime


class UserInfo(BaseModel):
    sub: str
    email: str | None = None
    email_verified: bool | None = None
    name: str | None = None
    picture: str | None = None
    updated_at: str | None = None


class LogoutResponse(BaseModel):
    success: bool
    message: str


class SessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, SessionData] = {}
        self._lock = asyncio.Lock()

    async def create_session(self, data: SessionData) -> str:
        session_id = secrets.token_urlsafe(32)
        async with self._lock:
            self._sessions[session_id] = data
        return session_id

    async def get_session(self, session_id: str) -> SessionData | None:
        async with self._lock:
            data = self._sessions.get(session_id)
            if not data:
                return None
            if data.expires_at <= datetime.now(timezone.utc):
                self._sessions.pop(session_id, None)
                return None
            return data

    async def delete_session(self, session_id: str) -> None:
        async with self._lock:
            self._sessions.pop(session_id, None)


session_store = SessionStore()


def _b64encode(payload: bytes) -> str:
    return base64.urlsafe_b64encode(payload).decode().rstrip("=")


def _b64decode(payload: str) -> bytes:
    padding = "=" * (-len(payload) % 4)
    return base64.urlsafe_b64decode(payload + padding)


def _sign_value(value: str, secret: str) -> str:
    signature = hmac.new(secret.encode(), value.encode(), hashlib.sha256).digest()
    return _b64encode(signature)


def _build_state(return_to: str, secret: str, ttl_seconds: int = 600) -> str:
    payload = {
        "returnTo": return_to,
        "nonce": secrets.token_urlsafe(16),
        "exp": int((datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)).timestamp()),
    }
    raw = _b64encode(json.dumps(payload, separators=(",", ":")).encode())
    signature = _sign_value(raw, secret)
    return f"{raw}.{signature}"


def _parse_state(state: str, secret: str) -> dict[str, Any]:
    try:
        raw, signature = state.split(".", 1)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid state"
        ) from exc

    expected_signature = _sign_value(raw, secret)
    if not hmac.compare_digest(signature, expected_signature):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid state")

    payload = json.loads(_b64decode(raw))
    if payload.get("exp", 0) < int(datetime.now(timezone.utc).timestamp()):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="State expired")

    return payload


def _is_origin_allowed(origin: str, settings: Any) -> bool:
    if origin in settings.api.cors_origins:
        return True
    if settings.api.cors_origin_regex:
        return re.match(settings.api.cors_origin_regex, origin) is not None
    return False


def _sanitize_return_to(return_to: str, settings: Any) -> str:
    parsed = urlparse(return_to)
    if not parsed.scheme or not parsed.netloc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid returnTo")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    if not _is_origin_allowed(origin, settings):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Return URL not allowed"
        )
    return return_to


def _build_callback_url(request: Request) -> str:
    # Check for X-Forwarded-Proto header to handle reverse proxy HTTPS
    proto = request.headers.get("X-Forwarded-Proto", "http")
    host = request.headers.get("Host", str(request.base_url.netloc))
    # Use /auth/callback as the primary callback URL
    return f"{proto}://{host}/api/auth/callback"


def _ensure_auth_settings(settings: Any) -> Any:
    auth = settings.auth
    missing = [
        name
        for name in ("domain", "client_id", "client_secret", "session_secret")
        if not getattr(auth, name)
    ]
    if missing:
        logger.warning("Auth0 configuration missing", missing=missing)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Auth0 is not configured",
        )
    return auth


async def _exchange_code_for_tokens(
    auth: Any,
    code: str,
    redirect_uri: str,
    correlation_id: str,
) -> dict[str, Any]:
    payload = {
        "grant_type": "authorization_code",
        "client_id": auth.client_id,
        "client_secret": auth.client_secret,
        "code": code,
        "redirect_uri": redirect_uri,
    }
    if auth.audience:
        payload["audience"] = auth.audience

    token_url = f"https://{auth.domain}/oauth/token"
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.post(token_url, data=payload)

    if response.status_code != status.HTTP_200_OK:
        logger.warning(
            "Auth0 token exchange failed",
            status_code=response.status_code,
            response_text=response.text,
            correlation_id=correlation_id,
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token exchange failed",
        )

    return response.json()


async def _fetch_user_info(access_token: str, auth_domain: str) -> dict[str, Any]:
    userinfo_url = f"https://{auth_domain}/userinfo"
    async with httpx.AsyncClient(timeout=10.0) as client:
        response = await client.get(
            userinfo_url,
            headers={"Authorization": f"Bearer {access_token}"},
        )

    if response.status_code != status.HTTP_200_OK:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to fetch user info",
        )

    return response.json()


@router.get("/login", status_code=status.HTTP_302_FOUND)
async def login(request: Request, returnTo: str | None = None) -> RedirectResponse:
    settings = get_settings()
    auth = _ensure_auth_settings(settings)
    correlation_id = get_correlation_id(request)

    return_to = returnTo or auth.default_return_to
    return_to = _sanitize_return_to(return_to, settings)

    redirect_uri = _build_callback_url(request)
    state = _build_state(return_to, auth.session_secret)

    params = {
        "response_type": "code",
        "client_id": auth.client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid profile email",
        "state": state,
    }
    if auth.audience:
        params["audience"] = auth.audience

    authorize_url = f"https://{auth.domain}/authorize?{urlencode(params)}"
    logger.info(
        "Redirecting to Auth0 login",
        correlation_id=correlation_id,
        redirect_uri=redirect_uri,
    )
    return RedirectResponse(url=authorize_url, status_code=status.HTTP_302_FOUND)


@router.get("/callback", status_code=status.HTTP_302_FOUND)
@router.get("/callback/auth0", status_code=status.HTTP_302_FOUND)
async def auth0_callback(
    request: Request, code: str | None = None, state: str | None = None
) -> RedirectResponse:
    settings = get_settings()
    auth = _ensure_auth_settings(settings)
    correlation_id = get_correlation_id(request)

    if not code or not state:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing code or state")

    state_payload = _parse_state(state, auth.session_secret)
    return_to = _sanitize_return_to(state_payload["returnTo"], settings)

    redirect_uri = _build_callback_url(request)
    token_data = await _exchange_code_for_tokens(auth, code, redirect_uri, correlation_id)

    access_token = token_data.get("access_token")
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Token exchange failed",
        )

    user_info = await _fetch_user_info(access_token, auth.domain)
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=auth.session_ttl_seconds)

    session_data = SessionData(
        user_info=user_info,
        access_token=access_token,
        id_token=token_data.get("id_token"),
        expires_at=expires_at,
    )
    session_id = await session_store.create_session(session_data)

    response = RedirectResponse(url=return_to, status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        auth.session_cookie_name,
        session_id,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=auth.session_ttl_seconds,
        path="/",
    )
    logger.info("Auth0 callback completed", correlation_id=correlation_id, return_to=return_to)
    return response


@router.post("/logout", response_model=LogoutResponse)
async def logout(request: Request) -> JSONResponse:
    settings = get_settings()
    auth = _ensure_auth_settings(settings)

    session_id = request.cookies.get(auth.session_cookie_name)
    if not session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    session_data = await session_store.get_session(session_id)
    if not session_data:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    await session_store.delete_session(session_id)
    response = JSONResponse({"success": True, "message": "Logged out successfully"})
    response.set_cookie(
        auth.session_cookie_name,
        "",
        httponly=True,
        secure=True,
        samesite="none",
        max_age=0,
        path="/",
    )
    return response


@router.get("/me", response_model=UserInfo)
async def get_current_user(request: Request) -> UserInfo:
    settings = get_settings()
    auth = _ensure_auth_settings(settings)

    session_id = request.cookies.get(auth.session_cookie_name)
    if not session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    session_data = await session_store.get_session(session_id)
    if not session_data:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    return UserInfo(**session_data.user_info)


class SessionResponse(BaseModel):
    user: dict[str, Any] | None = None
    isAuthenticated: bool


@router.get("/session", response_model=SessionResponse)
async def get_session(request: Request) -> SessionResponse:
    """Get current session information.

    Returns user info if authenticated, or isAuthenticated=false if not.
    This endpoint does NOT return 401 - it always returns 200 with session status.
    """
    settings = get_settings()

    # Don't throw error if Auth0 not configured - just return not authenticated
    try:
        auth = _ensure_auth_settings(settings)
    except HTTPException:
        return SessionResponse(isAuthenticated=False)

    session_id = request.cookies.get(auth.session_cookie_name)
    if not session_id:
        return SessionResponse(isAuthenticated=False)

    session_data = await session_store.get_session(session_id)
    if not session_data:
        return SessionResponse(isAuthenticated=False)

    # Transform user_info to match frontend expectations
    user_info = session_data.user_info
    user = {
        "id": user_info.get("sub", ""),
        "email": user_info.get("email", ""),
        "name": user_info.get("name", ""),
        "picture": user_info.get("picture"),
    }

    return SessionResponse(user=user, isAuthenticated=True)
