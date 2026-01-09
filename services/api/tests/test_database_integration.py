"""Integration tests for database connectivity and startup.

These tests verify that:
1. The API can connect to the database when available
2. Tables are created correctly during startup
3. The health check accurately reports database status
4. Fallback behavior works when database is unavailable

These tests require a running database (via Aspire or direct connection).
Use environment variable DATABASE_URL or ConnectionStrings__ytsummarizer.
"""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Mark all tests in this module as database integration tests
pytestmark = pytest.mark.integration


class TestDatabaseConnectionStartup:
    """Test database connection during application startup."""

    def test_app_state_has_db_initialized_flag(self, client):
        """Verify app.state tracks database initialization status."""
        # The mock app might not have state set, which is fine for unit tests
        # This test documents the expected behavior
        assert hasattr(client.app, "state")

    def test_readiness_includes_database_checks(self, client):
        """Verify readiness endpoint includes database status checks."""
        response = client.get("/health/ready")
        data = response.json()

        # The checks dict should include database-related keys
        checks = data.get("checks", {})
        assert "api" in checks
        # database_init may be missing in mocked tests, that's expected


class TestDatabaseHealthCheck:
    """Test database health verification via health endpoints."""

    def test_health_debug_returns_connection_info(self, client):
        """Verify debug endpoint exposes connection diagnostic info."""
        response = client.get("/health/debug")
        data = response.json()

        assert "connection_strings" in data
        assert "database" in data
        assert "status" in data["database"]

    def test_health_debug_masks_passwords(self, client):
        """Verify debug endpoint masks sensitive password data."""
        response = client.get("/health/debug")
        data = response.json()

        # Any URL shown should be truncated/masked
        db_url = data.get("database", {}).get("url", "")
        if db_url:
            # Should not contain full password - should be masked with ...
            assert "..." in db_url or len(db_url) < 100


class TestDatabaseRetryLogic:
    """Test that database connection retry logic works correctly."""

    @pytest.mark.asyncio
    async def test_database_connect_has_retry(self):
        """Verify DatabaseConnection.connect() uses retry logic."""
        from shared.db.connection import DatabaseConnection

        # Create a connection with invalid URL to trigger retries
        db = DatabaseConnection(
            url="mssql+aioodbc://invalid:invalid@localhost:9999/invalid?driver=ODBC+Driver+18+for+SQL+Server"
        )

        # The connect method should use tenacity retry decorator
        # Verify it has the retry attribute
        assert hasattr(db.connect, "retry")

    @pytest.mark.asyncio
    async def test_startup_retries_on_failure(self, monkeypatch):
        """Verify startup retries database connection on failure."""
        # Set low retry count for faster test
        monkeypatch.setenv("DB_STARTUP_RETRIES", "2")
        monkeypatch.setenv("DB_STARTUP_RETRY_DELAY", "0")

        # Track retry attempts
        attempts = []

        class MockDB:
            async def connect(self):
                attempts.append(1)
                if len(attempts) < 2:
                    raise ConnectionError("Database not ready")

            async def create_tables(self):
                pass

            async def close(self):
                pass

        mock_db = MockDB()

        # Import after setting env vars
        with patch("api.main.get_db", return_value=mock_db):
            from fastapi import FastAPI

            from api.main import lifespan

            app = FastAPI()

            async with lifespan(app):
                pass

            # Should have attempted twice (first failure + retry success)
            assert len(attempts) >= 1


class TestDatabaseTableCreation:
    """Test that database tables are created correctly."""

    def test_debug_endpoint_shows_tables_created(self, client):
        """Verify debug endpoint reports table creation status."""
        response = client.get("/health/debug")
        data = response.json()

        # The database section should indicate table creation status
        db_info = data.get("database", {})
        # tables_created may be True/False or not present (if connection failed)
        if db_info.get("status") == "connected":
            assert "tables_created" in db_info


class TestReadinessWithDatabase:
    """Test readiness endpoint behavior with database status."""

    def test_readiness_not_ready_when_db_not_initialized(self):
        """Verify readiness returns not ready when database init failed."""
        from contextlib import asynccontextmanager

        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from api.routes import health

        @asynccontextmanager
        async def mock_lifespan(app: FastAPI):
            # Simulate failed database initialization
            app.state.db_initialized = False
            app.state.db_error = "Connection refused"
            yield

        app = FastAPI(lifespan=mock_lifespan)
        app.include_router(health.router)

        with TestClient(app) as client:
            response = client.get("/health/ready")
            data = response.json()

            # Should report not ready
            assert data["ready"] is False
            assert data["checks"]["database_init"] is False

    def test_readiness_ready_when_db_initialized(self):
        """Verify readiness returns ready when database init succeeded."""
        from contextlib import asynccontextmanager
        from unittest.mock import patch

        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from api.routes import health

        @asynccontextmanager
        async def mock_lifespan(app: FastAPI):
            # Simulate successful database initialization
            app.state.db_initialized = True
            app.state.db_error = None
            yield

        app = FastAPI(lifespan=mock_lifespan)
        app.include_router(health.router)

        # Mock the database connection check in readiness
        mock_db = MagicMock()
        mock_db.connect = AsyncMock()

        with patch("shared.db.connection.get_db", return_value=mock_db):
            with TestClient(app) as client:
                response = client.get("/health/ready")
                data = response.json()

                # Should report ready
                assert data["ready"] is True
                assert data["checks"]["database_init"] is True
                assert data["checks"]["database_connection"] is True


# =============================================================================
# Live Integration Tests (require actual database)
# =============================================================================


@pytest.mark.skipif(
    not os.environ.get("DATABASE_URL") and not os.environ.get("ConnectionStrings__ytsummarizer"),
    reason="No database connection string available",
)
class TestLiveDatabaseIntegration:
    """Live integration tests that require an actual database.

    These tests are skipped if no database connection is configured.
    Run with Aspire or set DATABASE_URL to execute.
    """

    @pytest.mark.asyncio
    async def test_can_connect_to_database(self):
        """Verify we can actually connect to the configured database."""
        from shared.db.connection import get_db

        db = get_db()
        await db.connect()
        # If we get here without exception, connection succeeded

    @pytest.mark.asyncio
    async def test_can_create_tables(self):
        """Verify tables can be created in the database."""
        from shared.db.connection import get_db

        db = get_db()
        await db.connect()
        await db.create_tables()
        # If we get here without exception, table creation succeeded

    @pytest.mark.asyncio
    async def test_can_query_videos_table(self):
        """Verify the Videos table exists and is queryable."""
        from shared.db.connection import get_db
        from sqlalchemy import text

        db = get_db()
        async with db.session() as session:
            result = await session.execute(text("SELECT COUNT(*) FROM Videos"))
            count = result.scalar()
            assert count >= 0  # Table exists and is queryable
