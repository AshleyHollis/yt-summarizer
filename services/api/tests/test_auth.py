"""Tests for auth endpoints."""

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
