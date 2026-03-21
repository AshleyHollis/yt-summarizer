"""MCP server for yt-summarizer API.

Provides tools to submit YouTube videos, check processing progress,
and retrieve transcripts and summaries.
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


def _client() -> httpx.AsyncClient:
    return httpx.AsyncClient(base_url=API_URL, headers=_headers(), timeout=30.0)


@mcp.tool()
async def submit_video(url: str) -> str:
    """Submit a YouTube video URL for transcription and summarization.

    Args:
        url: YouTube video URL (e.g. https://www.youtube.com/watch?v=...)

    Returns:
        JSON with video_id and processing status.
    """
    async with _client() as client:
        resp = await client.post("/api/v1/videos", json={"url": url})
        resp.raise_for_status()
        return json.dumps(resp.json(), indent=2)


@mcp.tool()
async def get_video(video_id: str) -> str:
    """Get video metadata by ID.

    Args:
        video_id: UUID of the video.

    Returns:
        JSON with video details (title, channel, status, etc).
    """
    async with _client() as client:
        resp = await client.get(f"/api/v1/videos/{video_id}")
        resp.raise_for_status()
        return json.dumps(resp.json(), indent=2)


@mcp.tool()
async def get_video_progress(video_id: str) -> str:
    """Get processing progress for a video.

    Args:
        video_id: UUID of the video.

    Returns:
        JSON with overall progress percentage and per-stage status.
    """
    async with _client() as client:
        resp = await client.get(f"/api/v1/jobs/video/{video_id}/progress")
        resp.raise_for_status()
        return json.dumps(resp.json(), indent=2)


@mcp.tool()
async def get_transcript(video_id: str) -> str:
    """Get the transcript text for a processed video.

    Args:
        video_id: UUID of the video.

    Returns:
        Plain text transcript.
    """
    async with _client() as client:
        resp = await client.get(f"/api/v1/videos/{video_id}/transcript")
        resp.raise_for_status()
        return resp.text


@mcp.tool()
async def get_summary(video_id: str) -> str:
    """Get the markdown summary for a processed video.

    Args:
        video_id: UUID of the video.

    Returns:
        Markdown summary text.
    """
    async with _client() as client:
        resp = await client.get(f"/api/v1/videos/{video_id}/summary")
        resp.raise_for_status()
        return resp.text


@mcp.tool()
async def search_library(query: str, limit: int = 10) -> str:
    """Search the video library by title or description.

    Args:
        query: Search text.
        limit: Max results to return (1-50, default 10).

    Returns:
        JSON with matching videos.
    """
    async with _client() as client:
        resp = await client.get(
            "/api/v1/library/videos",
            params={"search": query, "page_size": min(max(limit, 1), 50)},
        )
        resp.raise_for_status()
        return json.dumps(resp.json(), indent=2)


@mcp.tool()
async def get_library_stats() -> str:
    """Get overall library statistics (video count, channel count, etc).

    Returns:
        JSON with library stats.
    """
    async with _client() as client:
        resp = await client.get("/api/v1/library/stats")
        resp.raise_for_status()
        return json.dumps(resp.json(), indent=2)


if __name__ == "__main__":
    mcp.run()
