"""Nightly incremental channel backup runner."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from azure.core.exceptions import ResourceNotFoundError
from azure.storage.blob import ContentSettings
from shared.blob.client import (
    SUMMARIES_CONTAINER,
    TRANSCRIPTS_CONTAINER,
    BlobClient,
    compute_content_hash,
    get_segments_blob_path,
    get_summary_blob_path,
    get_transcript_blob_path,
    sanitize_channel_name,
)
from shared.db.connection import get_db
from shared.db.models import Artifact, Channel, Job, Video
from shared.logging.config import get_logger
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

BACKUP_JOB_TYPE = "backup_nightly"
RESTORE_JOB_TYPE = "restore_channel"
DEFAULT_BACKUP_CONTAINER = "backups"

logger = get_logger(__name__)


@dataclass
class BackupConfig:
    """Configuration for a nightly backup run."""

    channels: list[str]
    include_summaries: bool = True
    include_relationships: bool = True
    include_facets: bool = True
    include_embeddings: bool = False
    max_changed_transcript_ratio: float = 0.10
    max_missing_transcript_ratio: float = 0.01
    backup_container: str = DEFAULT_BACKUP_CONTAINER

    @classmethod
    def from_env(cls) -> BackupConfig:
        """Load backup configuration from environment variables."""
        raw_json = os.environ.get("BACKUP_CONFIG_JSON")
        if raw_json:
            data = json.loads(raw_json)
            return cls(
                channels=[
                    sanitize_channel_name(str(channel))
                    for channel in data.get("channels", [])
                    if str(channel).strip()
                ],
                include_summaries=bool(data.get("includeSummaries", True)),
                include_relationships=bool(data.get("includeRelationships", True)),
                include_facets=bool(data.get("includeFacets", True)),
                include_embeddings=bool(data.get("includeEmbeddings", False)),
                max_changed_transcript_ratio=float(data.get("maxChangedTranscriptRatio", 0.10)),
                max_missing_transcript_ratio=float(data.get("maxMissingTranscriptRatio", 0.01)),
                backup_container=str(
                    data.get("backupContainer")
                    or os.environ.get("BACKUP_CONTAINER_NAME")
                    or DEFAULT_BACKUP_CONTAINER
                ),
            )

        raw_channels = os.environ.get("BACKUP_CHANNELS", "")
        channels = [
            sanitize_channel_name(channel.strip())
            for channel in raw_channels.split(",")
            if channel.strip()
        ]
        return cls(
            channels=channels,
            backup_container=os.environ.get("BACKUP_CONTAINER_NAME", DEFAULT_BACKUP_CONTAINER),
        )


@dataclass
class ChannelProgress:
    """Compact per-channel progress stored in the backup system job."""

    slug: str
    name: str
    status: str = "pending"
    phase: str = "queued"
    total_videos: int = 0
    processed_videos: int = 0
    copied_blobs: int = 0
    skipped_blobs: int = 0
    missing_blobs: int = 0
    bytes_copied: int = 0
    warnings: list[str] = field(default_factory=list)


@dataclass
class RunProgress:
    """Compact run progress stored in Jobs.metadata_json."""

    kind: str
    run_id: str
    current_channel: str | None
    total_channels: int
    completed_channels: int = 0
    copied_blobs: int = 0
    skipped_blobs: int = 0
    missing_blobs: int = 0
    bytes_copied: int = 0
    warnings: list[str] = field(default_factory=list)
    channels: list[dict[str, Any]] = field(default_factory=list)
    report_blob_path: str | None = None


class NightlyBackupRunner:
    """Run an incremental channel backup and publish progress to the Jobs table."""

    def __init__(
        self,
        config: BackupConfig,
        live_blob_client: BlobClient | None = None,
        backup_blob_client: BlobClient | None = None,
    ) -> None:
        self.config = config
        self.live_blob_client = live_blob_client or self._create_live_blob_client()
        self.backup_blob_client = backup_blob_client or self._create_backup_blob_client()
        self.run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + f"-{uuid4().hex[:8]}"
        self.snapshot_date = datetime.now(UTC).strftime("%Y-%m-%d")

    @staticmethod
    def _create_live_blob_client() -> BlobClient:
        account_url = os.environ.get("AZURE_STORAGE_ACCOUNT_URL") or os.environ.get(
            "LIVE_STORAGE_ACCOUNT_URL"
        )
        use_managed_identity = (
            os.environ.get("AZURE_STORAGE_USE_MANAGED_IDENTITY", "false").lower() == "true"
            or os.environ.get("LIVE_STORAGE_USE_MANAGED_IDENTITY", "false").lower() == "true"
        )

        if use_managed_identity:
            return BlobClient(use_managed_identity=True, account_url=account_url)
        return BlobClient()

    @staticmethod
    def _create_backup_blob_client() -> BlobClient:
        conn_str = os.environ.get("AZURE_BACKUP_STORAGE_CONNECTION_STRING") or os.environ.get(
            "BACKUP_STORAGE_CONNECTION_STRING"
        )
        account_url = os.environ.get("AZURE_BACKUP_STORAGE_ACCOUNT_URL") or os.environ.get(
            "BACKUP_STORAGE_ACCOUNT_URL"
        )
        use_managed_identity = (
            os.environ.get("BACKUP_STORAGE_USE_MANAGED_IDENTITY", "false").lower() == "true"
        )

        if use_managed_identity:
            return BlobClient(use_managed_identity=True, account_url=account_url)
        if not conn_str:
            raise ValueError(
                "Backup storage connection not found. Set AZURE_BACKUP_STORAGE_CONNECTION_STRING "
                "or BACKUP_STORAGE_USE_MANAGED_IDENTITY=true with BACKUP_STORAGE_ACCOUNT_URL."
            )
        return BlobClient(connection_string=conn_str)

    async def run(self) -> str:
        """Run the backup and return the system job ID."""
        if not self.config.channels:
            raise ValueError("No backup channels configured")

        db = get_db()
        async with db.session() as session:
            job = await self._create_job(session)
            try:
                await self._run_with_job(session, job)
            except Exception as exc:
                await self._mark_failed(session, job, exc)
                raise
            return str(job.job_id)

    async def _create_job(self, session: AsyncSession) -> Job:
        progress = RunProgress(
            kind=BACKUP_JOB_TYPE,
            run_id=self.run_id,
            current_channel=None,
            total_channels=len(self.config.channels),
        )
        job = Job(
            video_id=None,
            batch_id=None,
            job_type=BACKUP_JOB_TYPE,
            stage="running",
            status="running",
            progress=0,
            error_message=None,
            retry_count=0,
            max_retries=0,
            correlation_id=self.run_id,
            started_at=datetime.utcnow(),
            processing_mode="full_analysis",
            metadata_json=json.dumps(asdict(progress)),
        )
        session.add(job)
        await session.flush()
        await session.commit()
        logger.info("Backup job created", job_id=str(job.job_id), run_id=self.run_id)
        return job

    async def _run_with_job(self, session: AsyncSession, job: Job) -> None:
        channels = await self._load_configured_channels(session)
        channel_progress = [
            ChannelProgress(slug=sanitize_channel_name(channel.name), name=channel.name)
            for channel in channels
        ]
        progress = RunProgress(
            kind=BACKUP_JOB_TYPE,
            run_id=self.run_id,
            current_channel=None,
            total_channels=len(channels),
            channels=[asdict(item) for item in channel_progress],
        )

        if missing := sorted(set(self.config.channels) - {item.slug for item in channel_progress}):
            progress.warnings.append(f"Configured channels not found: {', '.join(missing)}")

        await self._update_job(session, job, progress)

        manifests: dict[str, dict[str, Any]] = {}
        for index, channel in enumerate(channels):
            channel_slug = sanitize_channel_name(channel.name)
            progress.current_channel = channel_slug
            channel_progress[index].status = "running"
            channel_progress[index].phase = "loading"
            progress.channels = [asdict(item) for item in channel_progress]
            await self._update_job(session, job, progress)

            manifest, index_data = await self._backup_channel(
                session,
                channel,
                channel_progress[index],
                progress,
                job,
            )
            manifests[channel_slug] = manifest

            await self._write_json(
                f"indexes/{channel_slug}.json",
                index_data,
            )
            await self._write_json(
                f"snapshots/{channel_slug}/{self.snapshot_date}/manifest.json",
                manifest,
            )

            if channel_progress[index].warnings:
                progress.warnings.extend(
                    f"{channel_slug}: {warning}" for warning in channel_progress[index].warnings
                )

            channel_progress[index].status = (
                "suspect" if channel_progress[index].warnings else "succeeded"
            )
            channel_progress[index].phase = "completed"
            progress.completed_channels += 1
            progress.channels = [asdict(item) for item in channel_progress]
            await self._update_job(session, job, progress)

        report = {
            "run_id": self.run_id,
            "snapshot_date": self.snapshot_date,
            "status": "suspect" if progress.warnings else "succeeded",
            "config": {
                "channels": self.config.channels,
                "include_summaries": self.config.include_summaries,
                "include_relationships": self.config.include_relationships,
                "include_facets": self.config.include_facets,
                "include_embeddings": self.config.include_embeddings,
            },
            "progress": asdict(progress),
            "manifests": {
                slug: f"snapshots/{slug}/{self.snapshot_date}/manifest.json" for slug in manifests
            },
            "created_at": datetime.now(UTC).isoformat(),
        }
        report_path = f"reports/{self.snapshot_date}/{self.run_id}.json"
        await self._write_json(report_path, report)
        progress.report_blob_path = report_path

        if not progress.warnings:
            for channel_slug in manifests:
                await self._write_json(
                    f"latest-good/{channel_slug}.json",
                    {
                        "channel_slug": channel_slug,
                        "snapshot_date": self.snapshot_date,
                        "manifest_blob_path": f"snapshots/{channel_slug}/{self.snapshot_date}/manifest.json",
                        "report_blob_path": report_path,
                        "run_id": self.run_id,
                        "updated_at": datetime.now(UTC).isoformat(),
                    },
                )

        job.status = "suspect" if progress.warnings else "succeeded"
        job.stage = "completed"
        job.progress = 100
        job.completed_at = datetime.utcnow()
        job.metadata_json = json.dumps(asdict(progress))
        await session.commit()

    async def _load_configured_channels(self, session: AsyncSession) -> list[Channel]:
        result = await session.execute(select(Channel).order_by(Channel.name.asc()))
        channels = result.scalars().all()
        requested = set(self.config.channels)
        return [
            channel
            for channel in channels
            if sanitize_channel_name(channel.name) in requested
            or channel.name.lower() in requested
            or channel.youtube_channel_id.lower() in requested
        ]

    async def _backup_channel(
        self,
        session: AsyncSession,
        channel: Channel,
        channel_progress: ChannelProgress,
        progress: RunProgress,
        job: Job,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        channel_slug = sanitize_channel_name(channel.name)
        index_data = await self._read_json(f"indexes/{channel_slug}.json") or {
            "channel_slug": channel_slug,
            "artifacts": {},
        }
        index_artifacts: dict[str, Any] = index_data.setdefault("artifacts", {})

        result = await session.execute(
            select(Video)
            .where(Video.channel_id == channel.channel_id)
            .order_by(Video.publish_date.asc())
        )
        videos = result.scalars().all()
        channel_progress.total_videos = len(videos)

        video_ids = [video.video_id for video in videos]
        artifact_map: dict[str, dict[str, Artifact]] = {}
        if video_ids:
            artifacts_result = await session.execute(
                select(Artifact).where(Artifact.video_id.in_(video_ids))
            )
            for artifact in artifacts_result.scalars().all():
                artifact_map.setdefault(str(artifact.video_id), {})[artifact.artifact_type] = (
                    artifact
                )

        manifest_videos: list[dict[str, Any]] = []
        changed_transcripts = 0
        missing_transcripts = 0

        for video in videos:
            channel_progress.phase = "copying"
            video_artifacts = artifact_map.get(str(video.video_id), {})
            transcript_artifact = video_artifacts.get("transcript")
            summary_artifact = video_artifacts.get("summary")

            video_entry: dict[str, Any] = {
                "video_id": str(video.video_id),
                "youtube_video_id": video.youtube_video_id,
                "title": video.title,
                "description": video.description,
                "duration": video.duration,
                "publish_date": video.publish_date.isoformat() if video.publish_date else None,
                "thumbnail_url": video.thumbnail_url,
                "processing_status": video.processing_status,
                "artifacts": {},
            }

            if transcript_artifact:
                transcript_ref, copied = await self._ensure_backed_up(
                    index_artifacts,
                    live_container=TRANSCRIPTS_CONTAINER,
                    live_path=get_transcript_blob_path(channel.name, video.youtube_video_id),
                    backup_path=f"mirror/transcripts/{channel_slug}/{video.youtube_video_id}/transcript.txt",
                    artifact=transcript_artifact,
                    artifact_type="transcript",
                    content_type="text/plain; charset=utf-8",
                )
                self._record_copy_result(channel_progress, progress, transcript_ref, copied)
                if copied:
                    changed_transcripts += 1
                video_entry["artifacts"]["transcript"] = transcript_ref

                segments_ref, copied = await self._ensure_segments_backed_up(
                    index_artifacts,
                    channel.name,
                    video.youtube_video_id,
                    channel_slug,
                    force_copy=False,
                )
                if segments_ref:
                    self._record_copy_result(channel_progress, progress, segments_ref, copied)
                    video_entry["artifacts"]["segments"] = segments_ref
            else:
                missing_transcripts += 1

            if self.config.include_summaries and summary_artifact:
                summary_ref, copied = await self._ensure_backed_up(
                    index_artifacts,
                    live_container=SUMMARIES_CONTAINER,
                    live_path=get_summary_blob_path(channel.name, video.youtube_video_id),
                    backup_path=f"mirror/summaries/{channel_slug}/{video.youtube_video_id}/summary.md",
                    artifact=summary_artifact,
                    artifact_type="summary",
                    content_type="text/markdown; charset=utf-8",
                )
                self._record_copy_result(channel_progress, progress, summary_ref, copied)
                video_entry["artifacts"]["summary"] = summary_ref

            manifest_videos.append(video_entry)
            channel_progress.processed_videos += 1
            if channel_progress.processed_videos % 25 == 0:
                progress.channels = self._replace_channel(progress.channels, channel_progress)
                await self._update_job(session, job, progress)

        self._apply_suspect_checks(
            channel_progress,
            total_videos=len(videos),
            changed_transcripts=changed_transcripts,
            missing_transcripts=missing_transcripts,
        )

        index_data["updated_at"] = datetime.now(UTC).isoformat()
        manifest = {
            "run_id": self.run_id,
            "snapshot_date": self.snapshot_date,
            "channel": {
                "channel_id": str(channel.channel_id),
                "youtube_channel_id": channel.youtube_channel_id,
                "name": channel.name,
                "slug": channel_slug,
                "description": channel.description,
                "thumbnail_url": channel.thumbnail_url,
                "video_count": channel.video_count,
                "last_synced_at": channel.last_synced_at.isoformat()
                if channel.last_synced_at
                else None,
            },
            "videos": manifest_videos,
            "counts": {
                "videos": len(videos),
                "copied_blobs": channel_progress.copied_blobs,
                "skipped_blobs": channel_progress.skipped_blobs,
                "missing_blobs": channel_progress.missing_blobs,
                "bytes_copied": channel_progress.bytes_copied,
            },
            "warnings": channel_progress.warnings,
        }
        return manifest, index_data

    async def _ensure_backed_up(
        self,
        index_artifacts: dict[str, Any],
        *,
        live_container: str,
        live_path: str,
        backup_path: str,
        artifact: Artifact,
        artifact_type: str,
        content_type: str,
    ) -> tuple[dict[str, Any], bool]:
        index_key = f"{live_container}/{live_path}"
        existing = index_artifacts.get(index_key)
        fingerprint = {
            "content_hash": artifact.content_hash,
            "content_length": artifact.content_length,
            "blob_uri": artifact.blob_uri,
        }

        if existing and all(existing.get(key) == value for key, value in fingerprint.items()):
            return existing, False

        ref = await self._copy_live_blob(
            live_container=live_container,
            live_path=live_path,
            backup_path=backup_path,
            artifact_type=artifact_type,
            content_type=content_type,
            source_content_hash=artifact.content_hash,
            source_content_length=artifact.content_length,
            source_blob_uri=artifact.blob_uri,
        )
        index_artifacts[index_key] = ref
        return ref, True

    async def _ensure_segments_backed_up(
        self,
        index_artifacts: dict[str, Any],
        channel_name: str,
        youtube_video_id: str,
        channel_slug: str,
        *,
        force_copy: bool,
    ) -> tuple[dict[str, Any] | None, bool]:
        live_path = get_segments_blob_path(channel_name, youtube_video_id)
        index_key = f"{TRANSCRIPTS_CONTAINER}/{live_path}"
        existing = index_artifacts.get(index_key)
        if existing and not force_copy:
            return existing, False

        try:
            ref = await self._copy_live_blob(
                live_container=TRANSCRIPTS_CONTAINER,
                live_path=live_path,
                backup_path=f"mirror/transcripts/{channel_slug}/{youtube_video_id}/segments.json",
                artifact_type="segments",
                content_type="application/json",
                source_content_hash=None,
                source_content_length=None,
                source_blob_uri=self.live_blob_client.get_blob_url(
                    TRANSCRIPTS_CONTAINER, live_path
                ),
            )
        except ResourceNotFoundError:
            return None, False

        index_artifacts[index_key] = ref
        return ref, True

    async def _copy_live_blob(
        self,
        *,
        live_container: str,
        live_path: str,
        backup_path: str,
        artifact_type: str,
        content_type: str,
        source_content_hash: str | None,
        source_content_length: int | None,
        source_blob_uri: str | None,
    ) -> dict[str, Any]:
        content = self.live_blob_client.download_blob(live_container, live_path)
        content_hash = compute_content_hash(content)
        content_length = len(content)
        if source_content_hash and content_hash != source_content_hash:
            logger.warning(
                "Live blob hash differs from artifact metadata",
                live_container=live_container,
                live_path=live_path,
                artifact_type=artifact_type,
            )

        self.backup_blob_client.ensure_container(self.config.backup_container)
        blob_client = self.backup_blob_client.client.get_blob_client(
            self.config.backup_container,
            backup_path,
        )
        blob_client.upload_blob(
            content,
            overwrite=True,
            content_settings=ContentSettings(content_type=content_type),
        )
        props = blob_client.get_blob_properties()
        return {
            "artifact_type": artifact_type,
            "live_container": live_container,
            "live_path": live_path,
            "backup_container": self.config.backup_container,
            "backup_path": backup_path,
            "backup_version_id": getattr(props, "version_id", None),
            "content_hash": source_content_hash or content_hash,
            "actual_content_hash": content_hash,
            "content_length": source_content_length or content_length,
            "actual_content_length": content_length,
            "blob_uri": source_blob_uri,
            "backed_up_at": datetime.now(UTC).isoformat(),
        }

    async def _read_json(self, path: str) -> dict[str, Any] | None:
        try:
            content = self.backup_blob_client.download_blob(self.config.backup_container, path)
        except ResourceNotFoundError:
            return None
        return json.loads(content.decode("utf-8"))

    async def _write_json(self, path: str, payload: dict[str, Any]) -> None:
        self.backup_blob_client.upload_blob(
            self.config.backup_container,
            path,
            json.dumps(payload, indent=2, sort_keys=True).encode("utf-8"),
            content_type="application/json",
            overwrite=True,
        )

    async def _update_job(self, session: AsyncSession, job: Job, progress: RunProgress) -> None:
        progress.channels = [
            channel if isinstance(channel, dict) else asdict(channel)
            for channel in progress.channels
        ]
        job.metadata_json = json.dumps(asdict(progress))
        if progress.total_channels:
            job.progress = min(
                99,
                int((progress.completed_channels / progress.total_channels) * 100),
            )
        await session.commit()

    async def _mark_failed(self, session: AsyncSession, job: Job, exc: Exception) -> None:
        metadata = self._load_job_metadata(job)
        metadata.setdefault("warnings", []).append(str(exc))
        job.status = "failed"
        job.stage = "failed"
        job.error_message = str(exc)[:4000]
        job.completed_at = datetime.utcnow()
        job.metadata_json = json.dumps(metadata)
        await session.commit()
        logger.exception("Backup job failed", job_id=str(job.job_id), run_id=self.run_id)

    @staticmethod
    def _load_job_metadata(job: Job) -> dict[str, Any]:
        if not job.metadata_json:
            return {}
        try:
            return json.loads(job.metadata_json)
        except json.JSONDecodeError:
            return {}

    @staticmethod
    def _record_copy_result(
        channel_progress: ChannelProgress,
        progress: RunProgress,
        ref: dict[str, Any],
        copied: bool,
    ) -> None:
        if copied:
            channel_progress.copied_blobs += 1
            progress.copied_blobs += 1
            bytes_copied = int(ref.get("actual_content_length") or ref.get("content_length") or 0)
            channel_progress.bytes_copied += bytes_copied
            progress.bytes_copied += bytes_copied
        else:
            channel_progress.skipped_blobs += 1
            progress.skipped_blobs += 1

    @staticmethod
    def _replace_channel(
        channels: list[dict[str, Any]],
        channel_progress: ChannelProgress,
    ) -> list[dict[str, Any]]:
        replacement = asdict(channel_progress)
        return [
            replacement if channel.get("slug") == channel_progress.slug else channel
            for channel in channels
        ]

    def _apply_suspect_checks(
        self,
        channel_progress: ChannelProgress,
        *,
        total_videos: int,
        changed_transcripts: int,
        missing_transcripts: int,
    ) -> None:
        if total_videos == 0:
            channel_progress.warnings.append("Channel has no videos to back up")
            return

        changed_ratio = changed_transcripts / total_videos
        missing_ratio = missing_transcripts / total_videos
        if changed_ratio > self.config.max_changed_transcript_ratio:
            channel_progress.warnings.append(
                f"Changed transcript ratio {changed_ratio:.1%} exceeds "
                f"{self.config.max_changed_transcript_ratio:.1%}"
            )
        if missing_ratio > self.config.max_missing_transcript_ratio:
            channel_progress.warnings.append(
                f"Missing transcript ratio {missing_ratio:.1%} exceeds "
                f"{self.config.max_missing_transcript_ratio:.1%}"
            )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run nightly channel backups")
    parser.add_argument("--config-json", help="Inline JSON config override")
    return parser.parse_args()


async def async_main() -> None:
    args = parse_args()
    if args.config_json:
        os.environ["BACKUP_CONFIG_JSON"] = args.config_json
    config = BackupConfig.from_env()
    runner = NightlyBackupRunner(config)
    job_id = await runner.run()
    logger.info("Nightly backup completed", job_id=job_id)


def main() -> None:
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
