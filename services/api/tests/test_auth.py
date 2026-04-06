"""Tests for auth endpoints."""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)


@pytest.mark.unit
def test_get_session_unauthenticated():
    """Test /auth/session returns isAuthenticated=false when not logged in."""
    response = client.get("/api/auth/session")

    assert response.status_code == 200
    data = response.json()
    assert data["isAuthenticated"] is False
    assert data["user"] is None


@pytest.mark.unit
def test_get_session_with_invalid_cookie():
    """Test /auth/session returns isAuthenticated=false with invalid session cookie."""
    response = client.get("/api/auth/session", cookies={"session": "invalid-session-id"})

    assert response.status_code == 200
    data = response.json()
    assert data["isAuthenticated"] is False
    assert data["user"] is None


@pytest.mark.unit
def test_login_redirects_to_auth0():
    """Test /auth/login redirects to Auth0 (or returns 500 if not configured)."""
    response = client.get("/api/auth/login", follow_redirects=False)

    # If Auth0 is not configured, it should return 500
    # If configured, it should redirect (302)
    assert response.status_code in [302, 500]

    if response.status_code == 302:
        # Should redirect to Auth0 domain
        location = response.headers.get("location", "")
        assert "authorize" in location or "auth0.com" in location


@pytest.mark.unit
def test_logout_without_session():
    """Test /auth/logout returns 401 when not authenticated."""
    response = client.post("/api/auth/logout")

    assert response.status_code == 401


@pytest.mark.unit
def test_get_me_without_session():
    """Test /auth/me returns 401 when not authenticated."""
    response = client.get("/api/auth/me")

    assert response.status_code == 401


@pytest.mark.unit
def test_callback_without_code():
    """Test /auth/callback returns 400 when code is missing."""
    response = client.get("/api/auth/callback", follow_redirects=False)

    assert response.status_code == 400


@pytest.mark.unit
def test_session_response_structure():
    """Test /auth/session returns correct JSON structure."""
    response = client.get("/api/auth/session")

    assert response.status_code == 200
    data = response.json()

    # Check required fields exist
    assert "isAuthenticated" in data
    assert "user" in data

    # Check types
    assert isinstance(data["isAuthenticated"], bool)
    assert data["user"] is None or isinstance(data["user"], dict)


# Integration tests would go here with mocked Auth0 responses
# These require setting up Auth0 configuration and mocking OAuth flow


@pytest.mark.unit
def test_get_session_includes_role_claim():
    """Test /auth/session forwards the Auth0 role custom claim to the frontend.

    The Auth0 Action adds 'https://yt-summarizer.com/role' to the ID token and
    userinfo payload. This claim must be forwarded in the session response so
    that AuthContext.hasRole() works correctly.
    """
    from api.routes.auth import _build_session_token

    SESSION_SECRET = "test-session-secret-at-least-32-chars"

    user_info = {
        "sub": "auth0|test-admin",
        "email": "admin@test.yt-summarizer.internal",
        "name": "Admin User",
        "picture": None,
        "https://yt-summarizer.com/role": "admin",
    }

    # Build a valid signed session token
    session_token = _build_session_token(user_info, SESSION_SECRET, ttl_seconds=3600)

    # Build a fake auth settings that passes _ensure_auth_settings validation
    class FakeAuth:
        domain = "test.auth0.com"
        client_id = "test-client-id"
        client_secret = "test-client-secret"
        session_secret = SESSION_SECRET
        session_cookie_name = "session"

    class FakeSettings:
        auth = FakeAuth()

    with (
        patch("api.routes.auth._ensure_auth_settings", return_value=FakeAuth()),
        patch("api.routes.auth.get_settings", return_value=FakeSettings()),
    ):
        response = client.get("/api/auth/session", cookies={"session": session_token})

    assert response.status_code == 200
    data = response.json()
    assert data["isAuthenticated"] is True
    assert data["user"] is not None
    assert data["user"]["https://yt-summarizer.com/role"] == "admin", (
        "Role claim must be forwarded from Auth0 userinfo to the session response "
        "so that AuthContext.hasRole('admin') returns true for admin users."
    )
