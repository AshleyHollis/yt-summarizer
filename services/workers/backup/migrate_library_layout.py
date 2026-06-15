"""Migrate legacy blob artifacts into the canonical library container."""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

from azure.core.exceptions import ResourceNotFoundError
from shared.blob import (
    ARTIFACT_CONTENT_TYPES,
    LIBRARY_CONTAINER,
    SUMMARIES_CONTAINER,
    TRANSCRIPTS_CONTAINER,
    BlobClient,
    compute_content_hash,
    get_blob_client,
    get_segments_blob_path,
    get_summary_blob_path,
    get_transcript_blob_path,
    sanitize_channel_name,
    write_video_metadata,
)
from shared.db.connection import get_db
from shared.db.models import Artifact, Channel, Video
from shared.logging.config import get_logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

logger = get_logger(__name__)


@dataclass
class ArtifactMigrationResult:
    """Result for a single artifact copy attempt."""

    artifact_type: str
    source_container: str
    destination_container: str
    blob_path: str
    status: str
    bytes_copied: int = 0
    source_hash: str | None = None
    destination_hash: str | None = None
    source_blob_uri: str | None = None
    destination_blob_uri: str | None = None
    error: str | None = None


@dataclass
class VideoMigrationResult:
    """Result for one migrated video folder."""

    video_id: str
    youtube_video_id: str
    channel_slug: str
    status: str
    artifacts: list[ArtifactMigrationResult] = field(default_factory=list)
    verified_legacy_blobs: list[tuple[str, str]] = field(default_factory=list)
    metadata_written: bool = False
    deleted_legacy_blobs: int = 0
    error: str | None = None


@dataclass
class MigrationReport:
    """Aggregate migration report."""

    dry_run: bool
    delete_verified: bool
    channels: list[str]
    videos_seen: int = 0
    videos_migrated: int = 0
    artifacts_copied: int = 0
    artifacts_skipped: int = 0
    artifacts_missing: int = 0
    artifacts_failed: int = 0
    legacy_blobs_deleted: int = 0
    videos: list[VideoMigrationResult] = field(default_factory=list)


LEGACY_ARTIFACTS: dict[str, tuple[str, Any]] = {
    "transcript": (TRANSCRIPTS_CONTAINER, get_transcript_blob_path),
    "segments": (TRANSCRIPTS_CONTAINER, get_segments_blob_path),
    "summary": (SUMMARIES_CONTAINER, get_summary_blob_path),
}


class LibraryLayoutMigrator:
    """Copy legacy artifacts into per-video library folders."""

    def __init__(
        self,
        *,
        dry_run: bool,
        delete_verified: bool,
        channels: list[str],
        blob_client: BlobClient | None = None,
    ) -> None:
        self.dry_run = dry_run
        self.delete_verified = delete_verified
        self.channels = [sanitize_channel_name(channel) for channel in channels]
        self.blob_client = blob_client or get_blob_client()

    async def run(self) -> MigrationReport:
        """Run the migration and return an in-memory report."""
        report = MigrationReport(
            dry_run=self.dry_run,
            delete_verified=self.delete_verified,
            channels=self.channels,
        )
        db = get_db()
        async with db.session() as session:
            videos = await self._load_videos(session)

        report.videos_seen = len(videos)
        for video in videos:
            async with db.session() as session:
                result = await self._migrate_video(session, video)
            self._delete_verified_legacy_blobs(result)
            self._apply_video_result(report, result)
            logger.info(
                "Library layout migration video processed",
                channel_slug=result.channel_slug,
                youtube_video_id=result.youtube_video_id,
                status=result.status,
            )
        return report

    async def _load_videos(self, session: AsyncSession) -> list[Video]:
        stmt = (
            select(Video)
            .options(selectinload(Video.channel))
            .join(Channel)
            .order_by(Channel.name.asc(), Video.publish_date.asc())
        )
        if self.channels:
            stmt = stmt.where(Channel.name.is_not(None))
        result = await session.execute(stmt)
        videos = list(result.scalars().all())
        if not self.channels:
            return videos
        return [
            video
            for video in videos
            if video.channel
            and (
                sanitize_channel_name(video.channel.name) in self.channels
                or video.channel.youtube_channel_id.lower() in self.channels
            )
        ]

    async def _migrate_video(
        self,
        session: AsyncSession,
        detached_video: Video,
    ) -> VideoMigrationResult:
        video_result = await session.execute(
            select(Video)
            .options(selectinload(Video.channel))
            .where(Video.video_id == detached_video.video_id)
        )
        video = video_result.scalar_one()
        channel_name = video.channel.name if video.channel else "unknown-channel"
        channel_slug = sanitize_channel_name(channel_name)
        result = VideoMigrationResult(
            video_id=str(video.video_id),
            youtube_video_id=video.youtube_video_id,
            channel_slug=channel_slug,
            status="pending",
        )

        artifact_rows = await self._load_artifacts(session, video)

        try:
            for artifact_type, (source_container, path_helper) in LEGACY_ARTIFACTS.items():
                blob_path = path_helper(channel_name, video.youtube_video_id)
                artifact_result = self._copy_and_verify_artifact(
                    artifact_type,
                    source_container,
                    blob_path,
                )
                result.artifacts.append(artifact_result)
                if artifact_result.status == "copied":
                    result.verified_legacy_blobs.append((source_container, blob_path))
                    self._update_artifact_row(artifact_rows, artifact_type, artifact_result)

            if not self.dry_run:
                await session.flush()
                metadata_uri = await write_video_metadata(
                    session,
                    str(video.video_id),
                    blob_client=self.blob_client,
                    extra_artifacts=self._metadata_artifacts(result),
                )
                result.metadata_written = bool(metadata_uri)

            result.status = "succeeded" if self._video_verified(result) else "partial"
            return result
        except Exception as exc:
            result.status = "failed"
            result.error = str(exc)
            logger.exception(
                "Library layout migration failed for video",
                video_id=str(video.video_id),
                youtube_video_id=video.youtube_video_id,
            )
            raise

    async def _load_artifacts(
        self,
        session: AsyncSession,
        video: Video,
    ) -> dict[str, Artifact]:
        rows = await session.execute(select(Artifact).where(Artifact.video_id == video.video_id))
        return {artifact.artifact_type: artifact for artifact in rows.scalars().all()}

    def _copy_and_verify_artifact(
        self,
        artifact_type: str,
        source_container: str,
        blob_path: str,
    ) -> ArtifactMigrationResult:
        result = ArtifactMigrationResult(
            artifact_type=artifact_type,
            source_container=source_container,
            destination_container=LIBRARY_CONTAINER,
            blob_path=blob_path,
            status="pending",
        )
        try:
            source_content = self.blob_client.download_blob(source_container, blob_path)
        except ResourceNotFoundError:
            result.status = "missing"
            return result

        source_hash = compute_content_hash(source_content)
        result.source_hash = source_hash
        result.bytes_copied = len(source_content)
        result.source_blob_uri = self.blob_client.get_blob_url(source_container, blob_path)

        if self.dry_run:
            result.status = "would_copy"
            return result

        result.destination_blob_uri = self.blob_client.upload_blob(
            LIBRARY_CONTAINER,
            blob_path,
            source_content,
            content_type=ARTIFACT_CONTENT_TYPES[artifact_type],
            overwrite=True,
        )
        destination_content = self.blob_client.download_blob(LIBRARY_CONTAINER, blob_path)
        destination_hash = compute_content_hash(destination_content)
        result.destination_hash = destination_hash
        if destination_hash != source_hash:
            result.status = "failed"
            result.error = "Destination hash does not match source hash"
            return result

        result.status = "copied"
        return result

    def _update_artifact_row(
        self,
        artifact_rows: dict[str, Artifact],
        artifact_type: str,
        artifact_result: ArtifactMigrationResult,
    ) -> None:
        artifact = artifact_rows.get(artifact_type)
        if not artifact or not artifact_result.destination_blob_uri:
            return
        artifact.blob_uri = artifact_result.destination_blob_uri
        artifact.content_hash = artifact_result.destination_hash
        artifact.content_length = artifact_result.bytes_copied

    @staticmethod
    def _metadata_artifacts(result: VideoMigrationResult) -> dict[str, dict[str, Any]]:
        artifacts: dict[str, dict[str, Any]] = {}
        for artifact in result.artifacts:
            if artifact.status != "copied" or not artifact.destination_blob_uri:
                continue
            artifacts[artifact.artifact_type] = {
                "blob_uri": artifact.destination_blob_uri,
                "content_length": artifact.bytes_copied,
                "content_hash": artifact.destination_hash,
                "updated_at": datetime.now(UTC).isoformat(),
            }
        return artifacts

    def _delete_verified_legacy_blobs(self, result: VideoMigrationResult) -> None:
        """Delete old blobs only after the video transaction has committed."""
        if self.dry_run or not self.delete_verified or result.status != "succeeded":
            return

        for container, blob_path in result.verified_legacy_blobs:
            self.blob_client.delete_blob(container, blob_path)
            result.deleted_legacy_blobs += 1

    @staticmethod
    def _video_verified(result: VideoMigrationResult) -> bool:
        return all(
            artifact.status in {"copied", "missing", "would_copy"} for artifact in result.artifacts
        )

    @staticmethod
    def _apply_video_result(report: MigrationReport, result: VideoMigrationResult) -> None:
        report.videos.append(result)
        if result.status == "succeeded":
            report.videos_migrated += 1
        report.legacy_blobs_deleted += result.deleted_legacy_blobs
        for artifact in result.artifacts:
            if artifact.status == "copied":
                report.artifacts_copied += 1
            elif artifact.status == "would_copy":
                report.artifacts_skipped += 1
            elif artifact.status == "missing":
                report.artifacts_missing += 1
            elif artifact.status == "failed":
                report.artifacts_failed += 1


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description="Migrate video blobs into the library container")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="Report actions without copying")
    mode.add_argument("--execute", action="store_true", help="Copy and update verified artifacts")
    parser.add_argument(
        "--delete-verified",
        action="store_true",
        help="Delete legacy blobs after each video verifies successfully",
    )
    parser.add_argument(
        "--channel",
        action="append",
        default=[],
        help="Limit migration to a channel name, slug, or YouTube channel ID",
    )
    return parser.parse_args()


async def async_main() -> None:
    """Run from the command line."""
    args = parse_args()
    dry_run = not args.execute
    migrator = LibraryLayoutMigrator(
        dry_run=dry_run,
        delete_verified=bool(args.execute and args.delete_verified),
        channels=args.channel,
    )
    report = await migrator.run()
    logger.info("Library layout migration completed", report=asdict(report))
    print(asdict(report))


def main() -> None:
    """Entrypoint."""
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
