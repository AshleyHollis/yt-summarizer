"""Metadata helpers for self-contained video blob folders."""

import json
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from azure.core.exceptions import ResourceNotFoundError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from shared.db.models import Artifact, Video

from .client import (
    LIBRARY_CONTAINER,
    BlobClient,
    compute_content_hash,
    get_blob_client,
    get_metadata_blob_path,
    get_segments_blob_path,
    get_summary_blob_path,
    get_transcript_blob_path,
    sanitize_channel_name,
)

METADATA_SCHEMA_VERSION = 1
ARTIFACT_CONTENT_TYPES = {
    "metadata": "application/json; charset=utf-8",
    "segments": "application/json; charset=utf-8",
    "summary": "text/markdown; charset=utf-8",
    "transcript": "text/plain; charset=utf-8",
}


def _dt(value: Any) -> str | None:
    return value.isoformat() if value else None


def artifact_path(channel_name: str, youtube_video_id: str, artifact_type: str) -> str:
    """Return the canonical library path for a known artifact type."""
    if artifact_type == "transcript":
        return get_transcript_blob_path(channel_name, youtube_video_id)
    if artifact_type == "segments":
        return get_segments_blob_path(channel_name, youtube_video_id)
    if artifact_type == "summary":
        return get_summary_blob_path(channel_name, youtube_video_id)
    if artifact_type == "metadata":
        return get_metadata_blob_path(channel_name, youtube_video_id)
    raise ValueError(f"Unsupported artifact type: {artifact_type}")


def build_video_metadata(
    video: Video,
    artifacts: list[Artifact] | None = None,
    *,
    extra_artifacts: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build the metadata.json payload for a video folder."""
    channel = video.channel
    channel_name = channel.name if channel else "unknown-channel"
    youtube_video_id = video.youtube_video_id
    artifact_entries: dict[str, dict[str, Any]] = {}

    for artifact in artifacts or []:
        artifact_type = artifact.artifact_type
        artifact_entries[artifact_type] = {
            "path": artifact_path(channel_name, youtube_video_id, artifact_type),
            "blob_uri": artifact.blob_uri,
            "content_length": artifact.content_length,
            "content_hash": artifact.content_hash,
            "content_type": ARTIFACT_CONTENT_TYPES.get(artifact_type),
            "updated_at": _dt(artifact.created_at),
        }

    for artifact_type, data in (extra_artifacts or {}).items():
        artifact_entries[artifact_type] = {
            "path": artifact_path(channel_name, youtube_video_id, artifact_type),
            "content_type": ARTIFACT_CONTENT_TYPES.get(artifact_type),
            **data,
        }

    return {
        "schema_version": METADATA_SCHEMA_VERSION,
        "video_id": str(video.video_id),
        "youtube_video_id": youtube_video_id,
        "youtube_url": f"https://www.youtube.com/watch?v={youtube_video_id}",
        "title": video.title,
        "description": video.description,
        "duration": video.duration,
        "publish_date": _dt(video.publish_date),
        "thumbnail_url": video.thumbnail_url,
        "processing_status": video.processing_status,
        "processing_mode": getattr(video, "processing_mode", None),
        "channel": {
            "channel_id": str(channel.channel_id) if channel else None,
            "youtube_channel_id": channel.youtube_channel_id if channel else None,
            "name": channel.name if channel else None,
            "slug": sanitize_channel_name(channel_name),
            "description": channel.description if channel else None,
            "thumbnail_url": channel.thumbnail_url if channel else None,
        },
        "artifacts": artifact_entries,
        "updated_at": datetime.now(UTC).isoformat(),
    }


async def write_video_metadata(
    session: AsyncSession,
    video_id: str,
    *,
    blob_client: BlobClient | None = None,
    extra_artifacts: dict[str, dict[str, Any]] | None = None,
) -> str | None:
    """Write metadata.json for a video using current SQL metadata and artifacts."""
    video_uuid = UUID(video_id) if isinstance(video_id, str) else video_id
    result = await session.execute(
        select(Video).options(selectinload(Video.channel)).where(Video.video_id == video_uuid)
    )
    video = result.scalar_one_or_none()
    if not video:
        return None

    artifacts_result = await session.execute(
        select(Artifact).where(Artifact.video_id == video_uuid)
    )
    artifacts = list(artifacts_result.scalars().all())
    channel_name = video.channel.name if video.channel else "unknown-channel"
    blob_name = get_metadata_blob_path(channel_name, video.youtube_video_id)
    client = blob_client or get_blob_client()

    payload = build_video_metadata(video, artifacts, extra_artifacts=extra_artifacts)
    try:
        existing = json.loads(client.download_blob(LIBRARY_CONTAINER, blob_name).decode("utf-8"))
        existing_artifacts = existing.get("artifacts") or {}
        payload["artifacts"] = {
            **existing_artifacts,
            **payload["artifacts"],
        }
    except (ResourceNotFoundError, json.JSONDecodeError, UnicodeDecodeError):
        pass

    content = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8")
    return client.upload_blob(
        LIBRARY_CONTAINER,
        blob_name,
        content,
        content_type=ARTIFACT_CONTENT_TYPES["metadata"],
    )


def metadata_artifact_ref(content: bytes, blob_uri: str) -> dict[str, Any]:
    """Build artifact details for metadata.json when content was just written."""
    return {
        "blob_uri": blob_uri,
        "content_length": len(content),
        "content_hash": compute_content_hash(content),
        "updated_at": datetime.now(UTC).isoformat(),
    }
