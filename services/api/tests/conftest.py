"""Pytest configuration and fixtures for API tests."""

import asyncio
from collections.abc import AsyncGenerator, Generator
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient

from api.main import create_app


# ============================================================================
# Event Loop Configuration
# ============================================================================


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# ============================================================================
# Application Fixtures
# ============================================================================


@pytest.fixture
def mock_session():
    """Create a mock database session for testing.
    
    Sets up a mock that returns proper SQLAlchemy-like result objects
    for common query patterns.
    """
    session = AsyncMock()
    
    # Create a mock result that mimics SQLAlchemy Result
    mock_result = MagicMock()
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = []  # Return empty list by default
    mock_scalars.first.return_value = None  # Return None for single item queries
    mock_result.scalars.return_value = mock_scalars
    mock_result.scalar.return_value = 0  # For count queries
    mock_result.scalar_one_or_none.return_value = None
    mock_result.fetchone.return_value = None
    mock_result.fetchall.return_value = []
    
    session.execute = AsyncMock(return_value=mock_result)
    session.add = MagicMock()
    session.flush = AsyncMock()
    session.commit = AsyncMock()
    session.rollback = AsyncMock()
    session.close = AsyncMock()
    return session


@pytest.fixture
def app(mock_session):
    """Create a FastAPI test application with mocked dependencies.
    
    Creates a minimal FastAPI app without the full lifespan initialization
    to avoid database connection attempts during testing.
    """
    from contextlib import asynccontextmanager
    from fastapi import FastAPI
    from fastapi.middleware.cors import CORSMiddleware
    
    from api.middleware import CorrelationIdMiddleware
    from api.routes import batches, channels, copilot, health, jobs, library, videos
    from shared.db.connection import get_session
    
    @asynccontextmanager
    async def mock_lifespan(app: FastAPI):
        """Mock lifespan that skips database initialization."""
        # Set app state to indicate database is not initialized (mocked)
        app.state.db_initialized = False
        app.state.db_error = "Mocked - database not initialized in tests"
        yield
    
    # Create a minimal app for testing
    application = FastAPI(
        title="YT Summarizer API",
        description="AI-powered YouTube video summarization service",
        version="0.1.0",
        lifespan=mock_lifespan,
    )
    
    # Add middleware
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    application.add_middleware(CorrelationIdMiddleware)
    
    # Include routers 
    # health router has no prefix, others have their prefixes defined in the router
    application.include_router(health.router)
    application.include_router(videos.router)
    application.include_router(jobs.router)
    application.include_router(library.router)
    application.include_router(channels.router)
    application.include_router(batches.router)
    application.include_router(copilot.router)
    
    # Override the database session dependency
    async def mock_get_session():
        yield mock_session
    
    application.dependency_overrides[get_session] = mock_get_session
    return application


@pytest.fixture
def client(app) -> Generator[TestClient, None, None]:
    """Create a synchronous test client."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
async def async_client(app) -> AsyncGenerator[AsyncClient, None]:
    """Create an async test client."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as ac:
        yield ac


# ============================================================================
# Mock Database Fixtures
# ============================================================================


@pytest.fixture
def mock_db(mock_session):
    """Create a mock database connection manager."""
    db = MagicMock()
    db.session = MagicMock(return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_session), __aexit__=AsyncMock()))
    return db


# ============================================================================
# Mock Queue Fixtures
# ============================================================================


@pytest.fixture
def mock_queue_client():
    """Create a mock queue client."""
    client = MagicMock()
    client.send_message = MagicMock()
    client.receive_messages = MagicMock(return_value=[])
    client.delete_message = MagicMock()
    return client


# ============================================================================
# Mock Blob Fixtures
# ============================================================================


@pytest.fixture
def mock_blob_client():
    """Create a mock blob client."""
    client = MagicMock()
    client.upload_blob = MagicMock(return_value="https://storage.blob.core.windows.net/test/blob")
    client.download_blob = MagicMock(return_value=b"test content")
    client.delete_blob = MagicMock()
    return client


# ============================================================================
# Sample Data Fixtures
# ============================================================================


@pytest.fixture
def sample_video_id() -> str:
    """Generate a sample video ID."""
    return str(uuid4())


@pytest.fixture
def sample_youtube_video_id() -> str:
    """Sample YouTube video ID."""
    return "dQw4w9WgXcQ"


@pytest.fixture
def sample_youtube_url(sample_youtube_video_id) -> str:
    """Sample YouTube URL."""
    return f"https://www.youtube.com/watch?v={sample_youtube_video_id}"


@pytest.fixture
def sample_channel_data() -> dict[str, Any]:
    """Sample channel data."""
    return {
        "channel_id": str(uuid4()),
        "youtube_channel_id": "UCuAXFkgsw1L7xaCfnd5JJOw",
        "name": "Rick Astley",
        "description": "Official Rick Astley Channel",
        "thumbnail_url": "https://example.com/channel.jpg",
    }


@pytest.fixture
def sample_video_data(sample_video_id, sample_youtube_video_id, sample_channel_data) -> dict[str, Any]:
    """Sample video data."""
    return {
        "video_id": sample_video_id,
        "youtube_video_id": sample_youtube_video_id,
        "channel_id": sample_channel_data["channel_id"],
        "title": "Never Gonna Give You Up",
        "description": "The official video for Never Gonna Give You Up",
        "thumbnail_url": "https://i.ytimg.com/vi/dQw4w9WgXcQ/maxresdefault.jpg",
        "duration_seconds": 213,
        "published_at": "2009-10-25T06:57:33Z",
        "processing_status": "pending",
    }


@pytest.fixture
def sample_job_data(sample_video_id) -> dict[str, Any]:
    """Sample job data."""
    return {
        "job_id": str(uuid4()),
        "video_id": sample_video_id,
        "job_type": "transcribe",
        "stage": "queued",
        "status": "pending",
        "error_message": None,
        "retry_count": 0,
        "correlation_id": str(uuid4()),
    }


# ============================================================================
# Correlation ID Fixtures
# ============================================================================


@pytest.fixture
def correlation_id() -> str:
    """Generate a correlation ID for testing."""
    return str(uuid4())


@pytest.fixture
def headers(correlation_id) -> dict[str, str]:
    """Generate standard test headers."""
    return {
        "X-Correlation-ID": correlation_id,
        "Content-Type": "application/json",
    }


# ============================================================================
# Agent Framework Fixtures
# ============================================================================


@pytest.fixture
def azure_openai_env(monkeypatch):
    """Configure Azure OpenAI environment variables for agent tests.
    
    Use this fixture when testing agent creation or AG-UI endpoints
    that require LLM configuration.
    """
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://test.openai.azure.com")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "test-api-key-for-testing")
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
    return {
        "endpoint": "https://test.openai.azure.com",
        "api_key": "test-api-key-for-testing",
        "deployment": "gpt-4o",
    }


@pytest.fixture
def openai_env(monkeypatch):
    """Configure standard OpenAI environment variables for agent tests."""
    monkeypatch.delenv("AZURE_OPENAI_ENDPOINT", raising=False)
    monkeypatch.delenv("AZURE_OPENAI_API_KEY", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key-for-testing")
    monkeypatch.setenv("OPENAI_MODEL", "gpt-4o")
    return {
        "api_key": "sk-test-key-for-testing",
        "model": "gpt-4o",
    }


@pytest.fixture
def no_llm_env(monkeypatch):
    """Clear all LLM environment variables for testing fallback behavior."""
    monkeypatch.delenv("AZURE_OPENAI_ENDPOINT", raising=False)
    monkeypatch.delenv("AZURE_OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)


@pytest.fixture
def agui_app(azure_openai_env):
    """Create a FastAPI app with AG-UI endpoint configured.
    
    Use this fixture to test AG-UI endpoint behavior without
    starting the full application.
    """
    from fastapi import FastAPI
    from api.agents import setup_agui_endpoint
    
    app = FastAPI()
    setup_agui_endpoint(app)
    return app


@pytest.fixture
def agui_client(agui_app):
    """Create a test client for the AG-UI app."""
    return TestClient(agui_app)
