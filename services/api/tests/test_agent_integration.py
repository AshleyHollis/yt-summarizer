"""Integration smoke test for agent API — verifies routes are registered and auth works."""

import os

import pytest
from fastapi.testclient import TestClient


def _route_paths(app) -> list[str]:
    """Collect paths from concrete routes and FastAPI included-router wrappers."""
    paths: list[str] = []
    for route in app.routes:
        if hasattr(route, "path"):
            paths.append(route.path)
        original_router = getattr(route, "original_router", None)
        if original_router:
            paths.extend(
                nested.path for nested in original_router.routes if hasattr(nested, "path")
            )
    return paths


@pytest.mark.unit  # run in CI without live DB
def test_agent_routes_registered():
    """All 7 agent routes are registered in the app."""
    os.environ["API_KEY"] = "test-key"
    from api.main import create_app

    app = create_app()
    paths = _route_paths(app)
    agent_paths = [p for p in paths if "/agent/" in p or p.startswith("/api/v1/agent")]
    assert len(agent_paths) >= 7, f"Expected 7+ agent routes, got {len(agent_paths)}: {agent_paths}"


@pytest.mark.unit
def test_agent_requires_auth():
    """Agent routes return 401 without API key."""
    os.environ["API_KEY"] = "test-key"
    from api.main import create_app

    app = create_app()
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.post("/api/v1/agent/search/semantic", json={"query": "test"})
    assert resp.status_code == 401


@pytest.mark.unit
def test_options_preflight_does_not_crash_with_agui_routes():
    """Browser preflight requests must not crash when AG-UI routes are registered."""
    os.environ["API_KEY"] = "test-key"
    from api.main import create_app

    app = create_app()
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.options(
        "/api/v1/library/videos",
        headers={
            "Origin": "https://preview.example.test",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization",
        },
    )

    assert resp.status_code != 500
