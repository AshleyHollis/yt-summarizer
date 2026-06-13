"""Unit tests for MCP tools — verify each tool makes the right HTTP call."""

import json
import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Ensure server.py is importable from the package root
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from server import (  # noqa: E402
    ask,
    extract_knowledge,
    get_job_status,
    get_segments,
    get_video,
    ingest,
    ingest_batch,
    ingest_channel_sample,
    search_library,
    search_youtube,
)


def _make_mock_client(response_data: dict):
    """Build a mock httpx.AsyncClient context manager returning given data."""
    mock_resp = MagicMock()
    mock_resp.raise_for_status = MagicMock()
    mock_resp.json.return_value = response_data

    mock_client = AsyncMock()
    mock_client.post = AsyncMock(return_value=mock_resp)
    mock_client.get = AsyncMock(return_value=mock_resp)

    mock_cm = AsyncMock()
    mock_cm.__aenter__ = AsyncMock(return_value=mock_client)
    mock_cm.__aexit__ = AsyncMock(return_value=None)

    return mock_cm, mock_client


@pytest.mark.asyncio
async def test_search_library_calls_semantic_endpoint():
    """search_library POSTs to /api/v1/agent/search/semantic."""
    response_data = {"results": [], "total": 0, "estimated_tokens": 0}
    mock_cm, mock_client = _make_mock_client(response_data)

    with patch("server._client", return_value=mock_cm):
        result = await search_library(query="machine learning", limit=5)

    mock_client.post.assert_called_once()
    call_args = mock_client.post.call_args
    assert "/api/v1/agent/search/semantic" in call_args[0][0]
    body = call_args[1]["json"]
    assert body["query"] == "machine learning"
    assert body["limit"] == 5
    parsed = json.loads(result)
    assert parsed["total"] == 0


@pytest.mark.asyncio
async def test_search_youtube_calls_youtube_endpoint():
    """search_youtube GETs /api/v1/agent/youtube/search."""
    response_data = {"results": [{"youtube_video_id": "abc", "title": "Test"}], "total": 1}
    mock_cm, mock_client = _make_mock_client(response_data)

    with patch("server._client", return_value=mock_cm):
        result = await search_youtube(query="python", limit=3)

    mock_client.get.assert_called_once()
    call_args = mock_client.get.call_args
    assert "/api/v1/agent/youtube/search" in call_args[0][0]
    params = call_args[1]["params"]
    assert params["q"] == "python"
    assert params["limit"] == 3
    parsed = json.loads(result)
    assert parsed["total"] == 1


@pytest.mark.asyncio
async def test_get_video_calls_videos_endpoint():
    """get_video GETs /api/v1/agent/videos/{video_id}."""
    vid_id = "550e8400-e29b-41d4-a716-446655440000"
    response_data = {"video_id": vid_id, "title": "Test Video", "segments_index": []}
    mock_cm, mock_client = _make_mock_client(response_data)

    with patch("server._client", return_value=mock_cm):
        result = await get_video(video_id=vid_id)

    mock_client.get.assert_called_once()
    call_url = mock_client.get.call_args[0][0]
    assert vid_id in call_url
    assert "/api/v1/agent/videos/" in call_url
    parsed = json.loads(result)
    assert parsed["video_id"] == vid_id


@pytest.mark.asyncio
async def test_get_segments_calls_segments_endpoint():
    """get_segments GETs /api/v1/agent/videos/{id}/segments."""
    vid_id = "550e8400-e29b-41d4-a716-446655440001"
    response_data = {"video_id": vid_id, "segments": [], "total": 0, "estimated_tokens": 0}
    mock_cm, mock_client = _make_mock_client(response_data)

    with patch("server._client", return_value=mock_cm):
        result = await get_segments(video_id=vid_id, start_sec=10.0, end_sec=30.0)

    mock_client.get.assert_called_once()
    call_url = mock_client.get.call_args[0][0]
    assert "/segments" in call_url
    params = mock_client.get.call_args[1].get("params", {})
    assert params.get("start_sec") == 10.0
    assert params.get("end_sec") == 30.0
    parsed = json.loads(result)
    assert parsed["total"] == 0


@pytest.mark.asyncio
async def test_ask_calls_ask_endpoint():
    """ask POSTs to /api/v1/agent/ask."""
    response_data = {"answer": "42", "citations": [], "estimated_tokens": 10}
    mock_cm, mock_client = _make_mock_client(response_data)

    with patch("server._client", return_value=mock_cm):
        result = await ask(query="What is life?", max_evidence_segments=3)

    mock_client.post.assert_called_once()
    call_url = mock_client.post.call_args[0][0]
    assert "/api/v1/agent/ask" in call_url
    body = mock_client.post.call_args[1]["json"]
    assert body["query"] == "What is life?"
    assert body["max_evidence_segments"] == 3
    parsed = json.loads(result)
    assert parsed["answer"] == "42"


@pytest.mark.asyncio
async def test_ingest_calls_videos_endpoint():
    """ingest POSTs to /api/v1/agent/videos."""
    job_id = "550e8400-e29b-41d4-a716-446655440002"
    response_data = {
        "job_id": job_id,
        "video_id": "550e8400-e29b-41d4-a716-446655440003",
        "status": "pending",
    }
    mock_cm, mock_client = _make_mock_client(response_data)
    yt_url = "https://www.youtube.com/watch?v=dQw4w9WgXcQ"

    with patch("server._client", return_value=mock_cm):
        result = await ingest(url=yt_url)

    mock_client.post.assert_called_once()
    call_url = mock_client.post.call_args[0][0]
    assert "/api/v1/agent/videos" in call_url
    body = mock_client.post.call_args[1]["json"]
    assert body["url"] == yt_url
    assert body["processing_mode"] == "transcript_only"
    parsed = json.loads(result)
    assert parsed["job_id"] == job_id


@pytest.mark.asyncio
async def test_ingest_accepts_full_analysis_override():
    """ingest can explicitly request full analysis."""
    response_data = {
        "job_id": "550e8400-e29b-41d4-a716-446655440012",
        "video_id": "550e8400-e29b-41d4-a716-446655440013",
        "status": "pending",
    }
    mock_cm, mock_client = _make_mock_client(response_data)

    with patch("server._client", return_value=mock_cm):
        await ingest(
            url="https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            processing_mode="full_analysis",
        )

    body = mock_client.post.call_args[1]["json"]
    assert body["processing_mode"] == "full_analysis"


@pytest.mark.asyncio
async def test_ingest_batch_calls_batches_endpoint():
    """ingest_batch POSTs selected URLs to /api/v1/agent/batches."""
    response_data = {"id": "batch-1", "total_count": 2}
    mock_cm, mock_client = _make_mock_client(response_data)

    with patch("server._client", return_value=mock_cm):
        result = await ingest_batch(
            urls=["https://www.youtube.com/watch?v=dQw4w9WgXcQ"],
            video_ids=["abc123"],
            name="Discord links",
        )

    call_url = mock_client.post.call_args[0][0]
    assert "/api/v1/agent/batches" in call_url
    body = mock_client.post.call_args[1]["json"]
    assert body["urls"] == ["https://www.youtube.com/watch?v=dQw4w9WgXcQ"]
    assert body["video_ids"] == ["abc123"]
    assert body["name"] == "Discord links"
    assert body["processing_mode"] == "transcript_only"
    assert json.loads(result)["total_count"] == 2


@pytest.mark.asyncio
async def test_ingest_channel_sample_calls_batches_endpoint():
    """ingest_channel_sample sends a limited channel request."""
    response_data = {"id": "batch-2", "total_count": 10}
    mock_cm, mock_client = _make_mock_client(response_data)

    with patch("server._client", return_value=mock_cm):
        await ingest_channel_sample("https://www.youtube.com/@MarkWildman", channel_limit=10)

    call_url = mock_client.post.call_args[0][0]
    assert "/api/v1/agent/batches" in call_url
    body = mock_client.post.call_args[1]["json"]
    assert body["channel_url"] == "https://www.youtube.com/@MarkWildman"
    assert body["channel_limit"] == 10
    assert body["processing_mode"] == "transcript_only"


@pytest.mark.asyncio
async def test_extract_knowledge_calls_knowledge_endpoint():
    """extract_knowledge returns Obsidian-ready note payloads."""
    response_data = {
        "title": "Clubbell Shoulder Mobility",
        "para_path": "Resources/Training/YouTube/Clubbell Shoulder Mobility.md",
        "markdown": "# Clubbell Shoulder Mobility",
        "tags": ["youtube"],
        "sources": [],
        "estimated_tokens": 12,
    }
    mock_cm, mock_client = _make_mock_client(response_data)

    with patch("server._client", return_value=mock_cm):
        result = await extract_knowledge(
            ["550e8400-e29b-41d4-a716-446655440014"],
            topic="shoulder mobility",
            para_destination="Resources/Training/YouTube",
        )

    call_url = mock_client.post.call_args[0][0]
    assert "/api/v1/agent/knowledge/extract" in call_url
    body = mock_client.post.call_args[1]["json"]
    assert body["video_ids"] == ["550e8400-e29b-41d4-a716-446655440014"]
    assert body["topic"] == "shoulder mobility"
    assert body["para_destination"] == "Resources/Training/YouTube"
    assert json.loads(result)["markdown"].startswith("# Clubbell")


@pytest.mark.asyncio
async def test_get_job_status_calls_jobs_endpoint():
    """get_job_status GETs /api/v1/agent/jobs/{job_id}."""
    job_id = "550e8400-e29b-41d4-a716-446655440004"
    response_data = {
        "job_id": job_id,
        "status": "running",
        "progress_pct": 50,
        "stages": [],
        "created_at": "2024-01-01T00:00:00",
        "updated_at": "2024-01-01T00:01:00",
    }
    mock_cm, mock_client = _make_mock_client(response_data)

    with patch("server._client", return_value=mock_cm):
        result = await get_job_status(job_id=job_id)

    mock_client.get.assert_called_once()
    call_url = mock_client.get.call_args[0][0]
    assert job_id in call_url
    assert "/api/v1/agent/jobs/" in call_url
    parsed = json.loads(result)
    assert parsed["job_id"] == job_id
    assert parsed["status"] == "running"
