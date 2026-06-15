"""Tests for the one-shot library blob layout migration."""

from azure.core.exceptions import ResourceNotFoundError
from shared.blob import LIBRARY_CONTAINER, TRANSCRIPTS_CONTAINER, compute_content_hash

from backup.migrate_library_layout import LibraryLayoutMigrator, VideoMigrationResult


class _MemoryBlobClient:
    def __init__(self, blobs: dict[tuple[str, str], bytes] | None = None):
        self.blobs = blobs or {}
        self.deleted: list[tuple[str, str]] = []

    def download_blob(self, container_name: str, blob_name: str) -> bytes:
        key = (container_name, blob_name)
        if key not in self.blobs:
            raise ResourceNotFoundError("missing")
        return self.blobs[key]

    def upload_blob(
        self,
        container_name: str,
        blob_name: str,
        content: bytes,
        content_type: str,
        overwrite: bool = True,
    ) -> str:
        self.blobs[(container_name, blob_name)] = content
        return self.get_blob_url(container_name, blob_name)

    def get_blob_url(self, container_name: str, blob_name: str) -> str:
        return f"https://storage.test/{container_name}/{blob_name}"

    def delete_blob(self, container_name: str, blob_name: str) -> None:
        self.deleted.append((container_name, blob_name))
        self.blobs.pop((container_name, blob_name), None)


def test_copy_and_verify_dry_run_does_not_write_destination():
    blob_path = "mark-wildman/video/transcript.txt"
    blob_client = _MemoryBlobClient({(TRANSCRIPTS_CONTAINER, blob_path): b"hello"})
    migrator = LibraryLayoutMigrator(
        dry_run=True,
        delete_verified=False,
        channels=[],
        blob_client=blob_client,
    )

    result = migrator._copy_and_verify_artifact("transcript", TRANSCRIPTS_CONTAINER, blob_path)

    assert result.status == "would_copy"
    assert (LIBRARY_CONTAINER, blob_path) not in blob_client.blobs
    assert result.source_hash == compute_content_hash(b"hello")


def test_copy_and_verify_execute_writes_library_blob():
    blob_path = "mark-wildman/video/transcript.txt"
    blob_client = _MemoryBlobClient({(TRANSCRIPTS_CONTAINER, blob_path): b"hello"})
    migrator = LibraryLayoutMigrator(
        dry_run=False,
        delete_verified=True,
        channels=[],
        blob_client=blob_client,
    )

    result = migrator._copy_and_verify_artifact("transcript", TRANSCRIPTS_CONTAINER, blob_path)

    assert result.status == "copied"
    assert blob_client.blobs[(LIBRARY_CONTAINER, blob_path)] == b"hello"
    assert result.source_hash == result.destination_hash


def test_copy_and_verify_missing_source_is_not_failure():
    blob_client = _MemoryBlobClient()
    migrator = LibraryLayoutMigrator(
        dry_run=False,
        delete_verified=True,
        channels=[],
        blob_client=blob_client,
    )

    result = migrator._copy_and_verify_artifact(
        "transcript",
        TRANSCRIPTS_CONTAINER,
        "mark-wildman/video/transcript.txt",
    )

    assert result.status == "missing"


def test_delete_verified_legacy_blobs_only_after_success():
    blob_path = "mark-wildman/video/transcript.txt"
    blob_client = _MemoryBlobClient({(TRANSCRIPTS_CONTAINER, blob_path): b"hello"})
    migrator = LibraryLayoutMigrator(
        dry_run=False,
        delete_verified=True,
        channels=[],
        blob_client=blob_client,
    )
    result = VideoMigrationResult(
        video_id="video-id",
        youtube_video_id="youtube-id",
        channel_slug="mark-wildman",
        status="partial",
        verified_legacy_blobs=[(TRANSCRIPTS_CONTAINER, blob_path)],
    )

    migrator._delete_verified_legacy_blobs(result)

    assert blob_client.deleted == []
    assert (TRANSCRIPTS_CONTAINER, blob_path) in blob_client.blobs

    result.status = "succeeded"
    migrator._delete_verified_legacy_blobs(result)

    assert blob_client.deleted == [(TRANSCRIPTS_CONTAINER, blob_path)]
    assert (TRANSCRIPTS_CONTAINER, blob_path) not in blob_client.blobs
