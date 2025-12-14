"""Transcribe worker for extracting YouTube video transcripts."""

from dataclasses import dataclass
from typing import Any

from shared.blob.client import TRANSCRIPTS_CONTAINER, compute_content_hash, get_blob_client
from shared.config import get_settings
from shared.db.connection import get_db
from shared.db.job_service import mark_job_completed, mark_job_failed, mark_job_running
from shared.db.models import Artifact, Job, Video
from shared.logging.config import get_logger
from shared.queue.client import SUMMARIZE_QUEUE, TRANSCRIBE_QUEUE, get_queue_client
from shared.worker.base_worker import BaseWorker, WorkerResult, run_worker

logger = get_logger(__name__)


@dataclass
class TranscribeMessage:
    """Message payload for transcribe jobs."""

    job_id: str
    video_id: str
    youtube_video_id: str
    correlation_id: str
    retry_count: int = 0


class TranscribeWorker(BaseWorker[TranscribeMessage]):
    """Worker for extracting YouTube video transcripts."""

    @property
    def queue_name(self) -> str:
        """Return the queue name."""
        return TRANSCRIBE_QUEUE

    def parse_message(self, raw_message: dict[str, Any]) -> TranscribeMessage:
        """Parse raw message to TranscribeMessage."""
        return TranscribeMessage(
            job_id=raw_message["job_id"],
            video_id=raw_message["video_id"],
            youtube_video_id=raw_message["youtube_video_id"],
            correlation_id=raw_message.get("correlation_id", "unknown"),
            retry_count=raw_message.get("retry_count", 0),
        )

    async def process_message(
        self,
        message: TranscribeMessage,
        correlation_id: str,
    ) -> WorkerResult:
        """Process a transcribe job.

        1. Update job status to running
        2. Fetch transcript from YouTube (captions or yt-dlp)
        3. Store transcript in blob storage
        4. Create artifact record
        5. Update job status to completed
        6. Queue next job (summarize)
        """
        logger.info(
            "Processing transcribe job",
            job_id=message.job_id,
            video_id=message.video_id,
            youtube_video_id=message.youtube_video_id,
        )

        try:
            # Mark job as running
            await mark_job_running(message.job_id, "transcribing")

            # Get transcript
            transcript = await self._fetch_transcript(message.youtube_video_id)

            if not transcript:
                await mark_job_failed(message.job_id, "Could not fetch transcript from YouTube")
                return WorkerResult.failed(
                    Exception("No transcript available"),
                    "Could not fetch transcript from YouTube",
                )

            # Store transcript in blob storage
            blob_uri = await self._store_transcript(
                message.video_id,
                message.youtube_video_id,
                transcript,
            )

            # Create artifact record
            await self._create_artifact(
                message.video_id,
                blob_uri,
                transcript,
            )

            # Mark job as completed
            await mark_job_completed(message.job_id)

            # Queue next job (summarize)
            await self._queue_next_job(message, correlation_id)

            logger.info(
                "Transcribe job completed",
                job_id=message.job_id,
                transcript_length=len(transcript),
            )

            return WorkerResult.success(
                message="Transcript extracted successfully",
                data={"transcript_length": len(transcript), "blob_uri": blob_uri},
            )

        except Exception as e:
            logger.exception("Transcribe job failed", job_id=message.job_id)
            await mark_job_failed(message.job_id, str(e))
            return WorkerResult.failed(e)

    async def _fetch_transcript(self, youtube_video_id: str) -> str | None:
        """Fetch transcript from YouTube.

        Tries YouTube captions API first, falls back to yt-dlp.
        """
        # Try youtube-transcript-api first
        try:
            from youtube_transcript_api import YouTubeTranscriptApi

            # New API: create instance and call fetch()
            ytt_api = YouTubeTranscriptApi()
            transcript_data = ytt_api.fetch(youtube_video_id, languages=["en"])
            # Combine transcript segments - transcript_data is a FetchedTranscript
            transcript = " ".join(entry.text for entry in transcript_data)
            logger.info("Fetched transcript via youtube-transcript-api")
            return transcript
        except Exception as e:
            logger.warning(
                "youtube-transcript-api failed, trying yt-dlp",
                error=str(e),
            )

        # Fallback to yt-dlp
        try:
            import yt_dlp

            ydl_opts = {
                "skip_download": True,
                "writesubtitles": True,
                "writeautomaticsub": True,
                "subtitleslangs": ["en"],
                "quiet": True,
            }

            with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                info = ydl.extract_info(
                    f"https://www.youtube.com/watch?v={youtube_video_id}",
                    download=False,
                )

                # Check for subtitles
                subtitles = info.get("subtitles", {})
                auto_captions = info.get("automatic_captions", {})

                # Prefer manual subtitles over auto-generated
                subs = subtitles.get("en") or auto_captions.get("en")
                if subs:
                    # Get the first available format
                    sub_url = subs[0].get("url")
                    if sub_url:
                        import aiohttp

                        async with aiohttp.ClientSession() as session:
                            async with session.get(sub_url) as resp:
                                subtitle_content = await resp.text()
                                # Parse VTT/SRT format
                                transcript = self._parse_subtitles(subtitle_content)
                                logger.info("Fetched transcript via yt-dlp")
                                return transcript

        except Exception as e:
            logger.warning("yt-dlp failed", error=str(e))

        return None

    def _parse_subtitles(self, content: str) -> str:
        """Parse VTT/SRT subtitle content to plain text."""
        import re

        # Remove VTT header
        content = re.sub(r"WEBVTT.*?\n\n", "", content, flags=re.DOTALL)
        # Remove timestamps
        content = re.sub(r"\d{2}:\d{2}:\d{2}[.,]\d{3} --> \d{2}:\d{2}:\d{2}[.,]\d{3}", "", content)
        # Remove speaker tags
        content = re.sub(r"<[^>]+>", "", content)
        # Remove line numbers
        content = re.sub(r"^\d+$", "", content, flags=re.MULTILINE)
        # Clean up whitespace
        content = re.sub(r"\n+", " ", content)
        content = re.sub(r"\s+", " ", content)

        return content.strip()

    async def _store_transcript(
        self,
        video_id: str,
        youtube_video_id: str,
        transcript: str,
    ) -> str:
        """Store transcript in blob storage."""
        blob_client = get_blob_client()
        blob_name = f"{video_id}/{youtube_video_id}_transcript.txt"

        uri = blob_client.upload_blob(
            TRANSCRIPTS_CONTAINER,
            blob_name,
            transcript.encode("utf-8"),
            content_type="text/plain",
        )

        return uri

    async def _create_artifact(
        self,
        video_id: str,
        blob_uri: str,
        transcript: str,
    ) -> None:
        """Create artifact record in database."""
        from uuid import UUID

        db = get_db()
        async with db.session() as session:
            from sqlalchemy import select

            # Check if artifact already exists
            result = await session.execute(
                select(Artifact).where(
                    Artifact.video_id == UUID(video_id),
                    Artifact.artifact_type == "transcript",
                )
            )
            existing = result.scalar_one_or_none()

            if existing:
                # Update existing artifact
                existing.blob_uri = blob_uri
                existing.content_length = len(transcript)
                existing.content_hash = compute_content_hash(transcript.encode("utf-8"))
            else:
                # Create new artifact
                artifact = Artifact(
                    video_id=UUID(video_id),
                    artifact_type="transcript",
                    blob_uri=blob_uri,
                    content_length=len(transcript),
                    content_hash=compute_content_hash(transcript.encode("utf-8")),
                )
                session.add(artifact)

    async def _queue_next_job(
        self,
        message: TranscribeMessage,
        correlation_id: str,
    ) -> None:
        """Queue the next job (summarize)."""
        from uuid import UUID

        db = get_db()
        async with db.session() as session:
            # Create summarize job
            job = Job(
                video_id=UUID(message.video_id),
                job_type="summarize",
                stage="queued",
                status="pending",
                correlation_id=correlation_id,
            )
            session.add(job)
            await session.flush()

            # Queue the job
            queue_client = get_queue_client()
            queue_client.send_message(
                SUMMARIZE_QUEUE,
                {
                    "job_id": str(job.job_id),
                    "video_id": message.video_id,
                    "youtube_video_id": message.youtube_video_id,
                    "correlation_id": correlation_id,
                },
            )

            logger.info("Queued summarize job", job_id=str(job.job_id))


def main():
    """Run the transcribe worker."""
    worker = TranscribeWorker()
    run_worker(worker)


if __name__ == "__main__":
    main()
