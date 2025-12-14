"""Pytest configuration and fixtures for worker tests."""

import asyncio
from collections.abc import Generator
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest


# =============================================================================
# Event Loop Configuration
# =============================================================================


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


# =============================================================================
# Mock Fixtures
# =============================================================================


@pytest.fixture
def mock_db_session():
    """Create a mock database session."""
    session = AsyncMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=None)
    session.add = MagicMock()
    session.commit = AsyncMock()
    session.refresh = AsyncMock()
    session.execute = AsyncMock()
    return session


@pytest.fixture
def mock_blob_client():
    """Create a mock blob storage client."""
    client = MagicMock()
    client.upload_blob = MagicMock()
    client.download_blob = MagicMock()
    
    # Mock download_blob to return content
    mock_download = MagicMock()
    mock_download.readall = MagicMock(return_value=b"Mock content")
    client.download_blob.return_value = mock_download
    
    return client


@pytest.fixture
def mock_queue_client():
    """Create a mock queue client."""
    client = MagicMock()
    client.send_message = MagicMock()
    client.receive_messages = MagicMock(return_value=[])
    client.delete_message = MagicMock()
    return client


@pytest.fixture
def mock_openai_client():
    """Create a mock OpenAI client."""
    client = MagicMock()
    
    # Mock chat completion
    mock_completion = MagicMock()
    mock_completion.choices = [MagicMock(message=MagicMock(content="Mock summary"))]
    client.chat.completions.create = MagicMock(return_value=mock_completion)
    
    # Mock embeddings
    mock_embedding = MagicMock()
    mock_embedding.data = [MagicMock(embedding=[0.1] * 1536)]
    client.embeddings.create = MagicMock(return_value=mock_embedding)
    
    return client
