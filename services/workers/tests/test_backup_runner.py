"""Tests for the nightly backup runner."""

from types import SimpleNamespace

import pytest

from backup.nightly import BackupConfig, ChannelProgress, NightlyBackupRunner, RunProgress


class _FakeBlobProperties:
    version_id = "version-1"


class _FakeDestinationBlob:
    def __init__(self):
        self.uploads = []

    def upload_blob(self, content, overwrite, content_settings):
        self.uploads.append(
            {
                "content": content,
                "overwrite": overwrite,
                "content_type": content_settings.content_type,
            }
        )

    def get_blob_properties(self):
        return _FakeBlobProperties()


class _FakeBlobService:
    def __init__(self, destination_blob):
        self.destination_blob = destination_blob

    def get_blob_client(self, container, blob):
        return self.destination_blob


class _FakeBlobClient:
    def __init__(self, content: bytes):
        self.content = content
        self.destination_blob = _FakeDestinationBlob()
        self.client = _FakeBlobService(self.destination_blob)
        self.download_count = 0

    def ensure_container(self, container_name):
        return None

    def download_blob(self, container_name, blob_name):
        self.download_count += 1
        return self.content

    def get_blob_url(self, container_name, blob_name):
        return f"https://example.test/{container_name}/{blob_name}"


@pytest.mark.asyncio
async def test_ensure_backed_up_skips_unchanged_artifact():
    live = _FakeBlobClient(b"transcript")
    backup = _FakeBlobClient(b"")
    runner = NightlyBackupRunner(
        BackupConfig(channels=["mark-wildman"]),
        live_blob_client=live,
        backup_blob_client=backup,
    )
    existing_ref = {
        "content_hash": "hash-1",
        "content_length": 10,
        "blob_uri": "https://live/transcript.txt",
    }
    index = {"transcripts/mark-wildman/video/transcript.txt": existing_ref}

    ref, copied = await runner._ensure_backed_up(
        index,
        live_container="transcripts",
        live_path="mark-wildman/video/transcript.txt",
        backup_path="mirror/transcripts/mark-wildman/video/transcript.txt",
        artifact=SimpleNamespace(
            content_hash="hash-1",
            content_length=10,
            blob_uri="https://live/transcript.txt",
        ),
        artifact_type="transcript",
        content_type="text/plain",
    )

    assert copied is False
    assert ref == existing_ref
    assert live.download_count == 0


@pytest.mark.asyncio
async def test_ensure_backed_up_copies_changed_artifact():
    live = _FakeBlobClient(b"new transcript")
    backup = _FakeBlobClient(b"")
    runner = NightlyBackupRunner(
        BackupConfig(channels=["mark-wildman"]),
        live_blob_client=live,
        backup_blob_client=backup,
    )
    index = {
        "transcripts/mark-wildman/video/transcript.txt": {
            "content_hash": "old-hash",
            "content_length": 10,
            "blob_uri": "https://live/transcript.txt",
        }
    }

    ref, copied = await runner._ensure_backed_up(
        index,
        live_container="transcripts",
        live_path="mark-wildman/video/transcript.txt",
        backup_path="mirror/transcripts/mark-wildman/video/transcript.txt",
        artifact=SimpleNamespace(
            content_hash="new-hash",
            content_length=14,
            blob_uri="https://live/transcript.txt",
        ),
        artifact_type="transcript",
        content_type="text/plain",
    )

    assert copied is True
    assert live.download_count == 1
    assert ref["backup_version_id"] == "version-1"
    assert index["transcripts/mark-wildman/video/transcript.txt"]["content_hash"] == "new-hash"


def test_record_copy_result_updates_progress():
    channel = ChannelProgress(slug="mark-wildman", name="Mark Wildman")
    progress = RunProgress(
        kind="backup_nightly", run_id="run", current_channel=None, total_channels=1
    )

    NightlyBackupRunner._record_copy_result(
        channel,
        progress,
        {"actual_content_length": 1024},
        copied=True,
    )

    assert channel.copied_blobs == 1
    assert progress.copied_blobs == 1
    assert progress.bytes_copied == 1024
