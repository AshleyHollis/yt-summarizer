"""Integration smoke test for agent API — verifies routes are registered and auth works."""

import os

import pytest
from fastapi.testclient import TestClient


@pytest.mark.unit  # run in CI without live DB
def test_agent_routes_registered():
    """All 7 agent routes are registered in the app."""
    os.environ["API_KEY"] = "test-key"
    from api.main import create_app

    app = create_app()
    paths = [r.path for r in app.routes]
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
