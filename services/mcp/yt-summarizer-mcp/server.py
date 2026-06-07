"""MCP server for yt-summarizer agent API.

Provides tools for AI agents (OpenClaw, Claude Code, Copilot, Squad) to:
- Search the transcript library
- Search YouTube for new content
- Get video metadata and segment index
- Fetch transcript text by timestamp range
- Ask questions via server-side RAG
- Ingest new YouTube URLs
- Poll ingestion job status
"""

import json
import os

import httpx
from mcp.server.fastmcp import FastMCP

API_URL = os.environ.get("YT_SUMMARIZER_API_URL", "https://api.yt-summarizer.apps.ashleyhollis.com")
API_KEY = os.environ.get("YT_SUMMARIZER_API_KEY", "")

mcp = FastMCP("yt-summarizer")


def _headers() -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if API_KEY:
        headers["X-API-Key"] = API_KEY
    return headers


def _client(timeout: float = 30.0) -> httpx.AsyncClient:
    return httpx.AsyncClient(base_url=API_URL, headers=_headers(), timeout=timeout)


@mcp.tool()
async def search_library(query: str, limit: int = 10) -> str:
    """Search the ingested transcript library using semantic/vector similarity.

    Use this to find relevant content from already-processed videos.
    Returns matching transcript segments with timestamps and source URLs.

    Args:
        query: Natural language search query.
        limit: Max results to return (1-50, default 10).
    """
    async with _client() as client:
        resp = await client.post(
            "/api/v1/agent/search/semantic",
            json={"query": query, "limit": min(max(limit, 1), 50)},
        )
        resp.raise_for_status()
        return json.dumps(resp.json(), indent=2)


@mcp.tool()
async def search_youtube(query: str, limit: int = 10) -> str:
    """Search YouTube for videos matching a query.

    Returns a list of candidates (title, channel, URL) — does NOT auto-ingest.
    To add a result to the library, call ingest() with the video URL.

    Args:
        query: YouTube search query.
        limit: Max results to return (1-50, default 10).
    """
    async with _client() as client:
        resp = await client.get(
            "/api/v1/agent/youtube/search",
            params={"q": query, "limit": min(max(limit, 1), 50)},
        )
        resp.raise_for_status()
        return json.dumps(resp.json(), indent=2)


@mcp.tool()
async def get_video(video_id: str) -> str:
    """Get video metadata, AI summary, and segment index.

    Returns metadata + a lightweight segment index (timestamps + AI labels) but
    NOT the full transcript text. Use get_segments() for specific text ranges,
    or ask() for RAG queries.

    Args:
        video_id: UUID of the video.
    """
    async with _client() as client:
        resp = await client.get(f"/api/v1/agent/videos/{video_id}")
        resp.raise_for_status()
        return json.dumps(resp.json(), indent=2)


@mcp.tool()
async def get_segments(
    video_id: str,
    start_sec: float | None = None,
    end_sec: float | None = None,
) -> str:
    """Fetch transcript text for a timestamp range within a video.

    Returns the actual text for segments overlapping the given range.
    Omit start_sec/end_sec to get all segments (expensive for long videos).

    Args:
        video_id: UUID of the video.
        start_sec: Start time in seconds (inclusive).
        end_sec: End time in seconds (exclusive).
    """
    params: dict = {}
    if start_sec is not None:
        params["start_sec"] = start_sec
    if end_sec is not None:
        params["end_sec"] = end_sec

    async with _client() as client:
        resp = await client.get(
            f"/api/v1/agent/videos/{video_id}/segments",
            params=params if params else None,
        )
        resp.raise_for_status()
        return json.dumps(resp.json(), indent=2)


@mcp.tool()
async def ask(query: str, max_evidence_segments: int = 5) -> str:
    """Ask a natural language question across the transcript library (RAG).

    The server performs retrieval and generates a cited answer. Use this for
    most Q&A use cases — it avoids loading large transcripts into your context.

    Args:
        query: Question to answer from the transcript library.
        max_evidence_segments: Max citation segments in response (1-20, default 5).
    """
    async with _client(timeout=60.0) as client:
        resp = await client.post(
            "/api/v1/agent/ask",
            json={"query": query, "max_evidence_segments": max_evidence_segments},
        )
        resp.raise_for_status()
        return json.dumps(resp.json(), indent=2)


@mcp.tool()
async def ingest(url: str) -> str:
    """Ingest a YouTube video URL for processing.

    Submits the video for async transcription, summarisation, and embedding.
    Returns a job_id — use get_job_status() to poll for completion.

    Args:
        url: YouTube video URL (e.g. https://www.youtube.com/watch?v=...)
    """
    async with _client() as client:
        resp = await client.post("/api/v1/agent/videos", json={"url": url})
        resp.raise_for_status()
        return json.dumps(resp.json(), indent=2)


@mcp.tool()
async def get_job_status(job_id: str) -> str:
    """Get the processing status of an ingestion job.

    Poll this after calling ingest() until status is 'completed' or 'failed'.

    Args:
        job_id: UUID returned by ingest().
    """
    async with _client() as client:
        resp = await client.get(f"/api/v1/agent/jobs/{job_id}")
        resp.raise_for_status()
        return json.dumps(resp.json(), indent=2)


if __name__ == "__main__":
    mcp.run()
