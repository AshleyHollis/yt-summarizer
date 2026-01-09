"""Transcribe worker for extracting YouTube video transcripts."""

import random
import time
from dataclasses import dataclass
from typing import Any

from shared.blob.client import (
    TRANSCRIPTS_CONTAINER,
    compute_content_hash,
    get_blob_client,
    get_segments_blob_path,
    get_transcript_blob_path,
)
from shared.db.connection import get_db
from shared.db.job_service import mark_job_completed, mark_job_failed, mark_job_rate_limited, mark_job_running
from shared.db.models import Artifact, Job
from shared.logging.config import get_logger
from shared.queue.client import SUMMARIZE_QUEUE, TRANSCRIBE_QUEUE, get_queue_client
from shared.telemetry.config import inject_trace_context
from shared.worker.base_worker import BaseWorker, WorkerResult, run_worker

logger = get_logger(__name__)

# Track request timing for rate limit debugging
_last_youtube_request_time: float | None = None
_youtube_request_count: int = 0

# Maximum length for content to be considered an error page when combined with other signals
MAX_ERROR_PAGE_LENGTH = 1000


class RateLimitError(Exception):
    """Raised when YouTube rate limits or IP blocks our requests."""
    pass


@dataclass
class TranscribeMessage:
    """Message payload for transcribe jobs."""

    job_id: str
    video_id: str
    youtube_video_id: str
    correlation_id: str
    channel_name: str = "unknown-channel"
    batch_id: str | None = None
    retry_count: int = 0


class TranscribeWorker(BaseWorker[TranscribeMessage]):
    """Worker for extracting YouTube video transcripts.
    
    Configured with rate limiting to avoid YouTube API rate limits:
    - 5 second minimum delay between requests
    - Up to 5 seconds additional random jitter
    - This results in ~6-12 requests per minute max
    """
    
    def __init__(self):
        """Initialize with YouTube-friendly rate limiting."""
        super().__init__(
            min_request_delay=5.0,      # 5 seconds minimum between requests
            request_delay_jitter=5.0,   # 0-5 seconds random additional delay
        )

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
            channel_name=raw_message.get("channel_name", "unknown-channel"),
            batch_id=raw_message.get("batch_id"),
            retry_count=raw_message.get("retry_count", 0),
        )

    async def process_message(
        self,
        message: TranscribeMessage,
        correlation_id: str,
    ) -> WorkerResult:
        """Process a transcribe job.

        1. Check if transcript already exists in blob storage (skip download if so)
        2. Update job status to running
        3. Fetch transcript from YouTube (captions or yt-dlp)
        4. Store transcript in blob storage
        5. Create artifact record
        6. Update job status to completed
        7. Queue next job (summarize)
        """
        global _last_youtube_request_time, _youtube_request_count
        
        logger.info(
            "Processing transcribe job",
            job_id=message.job_id,
            video_id=message.video_id,
            youtube_video_id=message.youtube_video_id,
            channel_name=message.channel_name,
        )

        try:
            # Mark job as running
            await mark_job_running(message.job_id, "transcribing")

            # Check if transcript already exists in blob storage
            existing_transcript = await self._check_existing_transcript(
                message.channel_name,
                message.youtube_video_id,
            )
            
            if existing_transcript:
                transcript, timestamped_segments = existing_transcript
                logger.info(
                    "Using existing transcript from blob storage",
                    job_id=message.job_id,
                    youtube_video_id=message.youtube_video_id,
                    transcript_length=len(transcript),
                )
            else:
                # Get transcript WITH timestamps in a single API call
                # This is the ONLY YouTube API call we make per video
                transcript, timestamped_segments = await self._fetch_transcript_with_timestamps_and_text(
                    message.youtube_video_id
                )

                if not transcript:
                    error_msg = (
                        "No transcript available for this video. "
                        "This video does not have captions or auto-generated subtitles on YouTube."
                    )
                    await mark_job_failed(message.job_id, error_msg)
                    return WorkerResult.failed(
                        Exception("No transcript available"),
                        error_msg,
                    )
        except RateLimitError as e:
            # Rate limited by YouTube - retry indefinitely with 5 minute delays
            retry_delay = 300  # 5 minutes
            logger.warning(
                "YouTube rate limit detected, will retry in 5 minutes",
                job_id=message.job_id,
                error=str(e),
            )
            # Update job AND video status to show rate limiting in UI
            await mark_job_rate_limited(message.job_id, message.video_id, retry_delay)
            return WorkerResult.rate_limited(
                message="YouTube is rate limiting requests. Will retry automatically in 5 minutes.",
                retry_delay=retry_delay,
            )

        try:

            # Store transcript in blob storage (using channel-based path)
            blob_uri = await self._store_transcript(
                message.channel_name,
                message.youtube_video_id,
                transcript,
            )

            # Store timestamped segments (already fetched above, no extra API call)
            if timestamped_segments:
                await self._store_timestamped_segments(
                    message.channel_name,
                    message.youtube_video_id,
                    timestamped_segments,
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

    def _is_valid_transcript_content(self, content: str) -> bool:
        """Validate that content is a valid transcript, not an HTML error page.
        
        Uses multiple signals to avoid false positives - a legitimate transcript
        might mention "captcha" or "automated queries" in context, so we look
        for combinations of indicators that suggest an error page.
        
        Returns False only if content appears to be an error page based on
        multiple signals (HTML structure + error keywords + short length).
        """
        if not content or len(content.strip()) < 10:
            return False
        
        content_lower = content.lower()
        content_stripped = content.strip()
        
        # Strong HTML indicators - these almost never appear in transcripts
        # Check if it STARTS with HTML (not just contains it)
        is_html_document = (
            content_stripped.startswith('<!doctype') or
            content_stripped.startswith('<html') or
            content_stripped.startswith('<!DOCTYPE')
        )
        
        # Count HTML tag pairs - error pages have many, transcripts have none
        html_tag_count = sum(1 for marker in ['<html', '<head>', '<body>', '</html>', '</body>'] 
                            if marker in content_lower)
        
        # Rate limit indicators - only concerning if combined with HTML structure
        rate_limit_phrases = [
            'automated queries',
            'to protect our users',
            'unusual traffic from your',
            'please complete the captcha',
        ]
        has_rate_limit_phrase = any(phrase in content_lower for phrase in rate_limit_phrases)
        
        # Google-specific error page pattern (very specific, unlikely in normal content)
        is_google_error = (
            'googlessorry' in content_lower.replace(' ', '').replace('.', '') or
            ('google' in content_lower and 'sorry' in content_lower and html_tag_count >= 2)
        )
        
        # Decision logic: require multiple signals for rejection
        # This prevents false positives from legitimate transcripts mentioning these terms
        if is_html_document and html_tag_count >= 3:
            logger.warning("Detected HTML document structure")
            return False
        
        if is_google_error:
            logger.warning("Detected Google error page pattern")
            return False
        
        # Only reject on rate limit phrases if ALSO short and has HTML markers
        if has_rate_limit_phrase and html_tag_count >= 2 and len(content) < MAX_ERROR_PAGE_LENGTH:
            logger.warning("Detected short HTML response with rate limit message")
            return False
        
        return True

    async def _check_existing_transcript(
        self,
        channel_name: str,
        youtube_video_id: str,
    ) -> tuple[str, list[dict]] | None:
        """Check if transcript already exists in blob storage.
        
        This allows skipping the YouTube API call if we already have the transcript,
        which is useful for:
        - Reprocessing videos (e.g., to regenerate summaries)
        - Handling retries after partial failures
        - Avoiding rate limits
        
        Args:
            channel_name: The YouTube channel name.
            youtube_video_id: The YouTube video ID.
        
        Returns:
            Tuple of (transcript_text, segments) if found, None otherwise.
        """
        import json
        
        blob_client = get_blob_client()
        
        # Check for transcript using the YouTube video ID path
        transcript_path = get_transcript_blob_path(channel_name, youtube_video_id)
        segments_path = get_segments_blob_path(channel_name, youtube_video_id)
        
        try:
            if not blob_client.blob_exists(TRANSCRIPTS_CONTAINER, transcript_path):
                return None
            
            # Download existing transcript
            transcript_bytes = blob_client.download_blob(TRANSCRIPTS_CONTAINER, transcript_path)
            transcript = transcript_bytes.decode("utf-8")
            
            # Try to get segments too
            segments = []
            if blob_client.blob_exists(TRANSCRIPTS_CONTAINER, segments_path):
                segments_bytes = blob_client.download_blob(TRANSCRIPTS_CONTAINER, segments_path)
                segments = json.loads(segments_bytes.decode("utf-8"))
            
            logger.info(
                "Found existing transcript in blob storage",
                youtube_video_id=youtube_video_id,
                channel_name=channel_name,
                transcript_length=len(transcript),
                segment_count=len(segments),
            )
            
            return transcript, segments
            
        except Exception as e:
            logger.warning(
                "Error checking for existing transcript",
                youtube_video_id=youtube_video_id,
                error=str(e),
            )
            return None

    def _log_youtube_request(self, video_id: str, method: str) -> None:
        """Log a YouTube API request with timing info for rate limit debugging."""
        global _last_youtube_request_time, _youtube_request_count
        
        now = time.time()
        _youtube_request_count += 1
        
        if _last_youtube_request_time is not None:
            elapsed = now - _last_youtube_request_time
            logger.info(
                "YouTube API request",
                method=method,
                video_id=video_id,
                request_number=_youtube_request_count,
                seconds_since_last_request=round(elapsed, 2),
            )
        else:
            logger.info(
                "YouTube API request (first)",
                method=method,
                video_id=video_id,
                request_number=_youtube_request_count,
            )
        
        _last_youtube_request_time = now

    async def _fetch_transcript_with_timestamps_and_text(
        self, youtube_video_id: str
    ) -> tuple[str | None, list[dict] | None]:
        """Fetch transcript and timestamps using yt-dlp exclusively.
        
        We use yt-dlp to download subtitles directly because:
        1. The sleep_interval_subtitles option works (waits 70s before subtitle download)
        2. Better rate-limit handling (cookie support, client spoofing)
        3. Frequently updated when YouTube changes their blocking
        4. Single library = simpler codebase, fewer dependencies
        
        Returns:
            Tuple of (transcript_text, timestamped_segments) or (None, None) if unavailable.
        """
        import asyncio
        import tempfile
        import os
        import glob
        import yt_dlp
        
        self._log_youtube_request(youtube_video_id, "yt-dlp-download-subtitles")
        
        # Use a temp directory for subtitle download
        with tempfile.TemporaryDirectory() as tmpdir:
            output_template = os.path.join(tmpdir, "%(id)s")
            
            # 60 seconds minimum + 0-10 seconds jitter (confirmed fix from GitHub issue #13831)
            subtitle_sleep = 60 + random.randint(0, 10)
            
            ydl_opts = {
                "skip_download": True,  # Don't download video/audio
                "writesubtitles": True,
                "writeautomaticsub": True,
                "subtitleslangs": ["en"],
                "subtitlesformat": "json3",  # Prefer json3 for timestamps
                "outtmpl": output_template,
                "quiet": True,
                # Rate limit avoidance - wait before subtitle download
                "sleep_interval_subtitles": subtitle_sleep,
                "sleep_interval_requests": 1.0,  # Wait between API requests
                # Use alternative YouTube clients that may be less rate-limited
                "extractor_args": {
                    "youtube": {
                        "player_client": ["android_sdkless", "web_safari"],
                    }
                },
                "http_headers": {
                    "Accept-Language": "en-US,en;q=0.9",
                },
            }
            
            logger.info(
                "Starting subtitle download with rate limit delay",
                video_id=youtube_video_id,
                sleep_seconds=subtitle_sleep,
            )

            try:
                # Run yt-dlp in a thread pool to not block async loop
                def download_subs():
                    with yt_dlp.YoutubeDL(ydl_opts) as ydl:
                        return ydl.extract_info(
                            f"https://www.youtube.com/watch?v={youtube_video_id}",
                            download=True,  # Actually download subtitles
                        )
                
                loop = asyncio.get_event_loop()
                info = await loop.run_in_executor(None, download_subs)
                
                # Find the downloaded subtitle file
                sub_files = glob.glob(os.path.join(tmpdir, f"{youtube_video_id}*.json3"))
                if not sub_files:
                    # Try other formats
                    sub_files = glob.glob(os.path.join(tmpdir, f"{youtube_video_id}*.vtt"))
                if not sub_files:
                    sub_files = glob.glob(os.path.join(tmpdir, f"{youtube_video_id}*"))
                
                if not sub_files:
                    # Check if subtitles are available at all
                    subtitles = info.get("subtitles", {})
                    auto_captions = info.get("automatic_captions", {})
                    if not subtitles.get("en") and not auto_captions.get("en"):
                        logger.warning(
                            "No English subtitles available",
                            video_id=youtube_video_id,
                            available_subs=list(subtitles.keys()),
                            available_auto=list(auto_captions.keys()),
                        )
                    else:
                        logger.warning(
                            "Subtitles available but not downloaded",
                            video_id=youtube_video_id,
                            files_in_tmpdir=os.listdir(tmpdir),
                        )
                    return None, None
                
                sub_file = sub_files[0]
                sub_ext = os.path.splitext(sub_file)[1].lstrip(".")
                
                with open(sub_file, "r", encoding="utf-8") as f:
                    subtitle_content = f.read()
                
                # Validate the content before accepting it
                if not self._is_valid_transcript_content(subtitle_content):
                    logger.warning(
                        "Invalid subtitle content detected (possible rate limit page)",
                        video_id=youtube_video_id,
                        content_preview=subtitle_content[:200],
                    )
                    raise RateLimitError(
                        "YouTube returned invalid content (likely rate limit). "
                        "This may take hours to resolve."
                    )
                
                # Parse based on format
                if sub_ext == "json3":
                    transcript, segments = self._parse_json3_subtitles(subtitle_content)
                else:
                    # VTT or other text formats
                    transcript, segments = self._parse_vtt_subtitles(subtitle_content)
                
                if not self._is_valid_transcript_content(transcript):
                    logger.warning("Parsed transcript is invalid", video_id=youtube_video_id)
                    return None, None
                
                logger.info(
                    "Fetched transcript via yt-dlp",
                    video_id=youtube_video_id,
                    format=sub_ext,
                    segment_count=len(segments) if segments else 0,
                    transcript_length=len(transcript),
                )
                return transcript, segments

            except RateLimitError:
                raise  # Re-raise rate limit errors
            except yt_dlp.utils.DownloadError as e:
                error_str = str(e)
                if any(phrase in error_str.lower() for phrase in ["429", "too many", "rate", "block"]):
                    raise RateLimitError(
                        "YouTube is blocking requests from this IP. "
                        "This may take hours to resolve."
                    )
                logger.warning("yt-dlp download error", error=error_str, video_id=youtube_video_id)
                return None, None
            except Exception as e:
                error_str = str(e)
                if any(phrase in error_str.lower() for phrase in ["429", "too many", "rate", "block", "ip"]):
                    raise RateLimitError(
                        "YouTube is blocking requests from this IP. "
                        "This may take hours to resolve."
                    )
                logger.warning("Failed to fetch transcript", error=error_str, video_id=youtube_video_id)
                return None, None

    def _parse_json3_subtitles(self, content: str) -> tuple[str, list[dict]]:
        """Parse YouTube's json3 subtitle format with timestamps.
        
        json3 format contains events with timing and text segments.
        """
        import json
        
        try:
            data = json.loads(content)
            events = data.get("events", [])
            
            segments = []
            text_parts = []
            
            for event in events:
                # Skip events without text segments
                segs = event.get("segs", [])
                if not segs:
                    continue
                
                start_ms = event.get("tStartMs", 0)
                duration_ms = event.get("dDurationMs", 0)
                
                # Combine text from all segments in this event
                text = "".join(seg.get("utf8", "") for seg in segs).strip()
                if not text or text == "\n":
                    continue
                
                segments.append({
                    "start": start_ms / 1000.0,  # Convert to seconds
                    "duration": duration_ms / 1000.0,
                    "text": text,
                })
                text_parts.append(text)
            
            transcript = " ".join(text_parts)
            return transcript, segments
            
        except json.JSONDecodeError as e:
            logger.warning("Failed to parse json3 subtitles", error=str(e))
            # Fall back to treating it as plain text
            return content, []

    def _parse_vtt_subtitles(self, content: str) -> tuple[str, list[dict]]:
        """Parse VTT/SRT subtitle content with timestamps.
        
        Returns both plain text transcript and timestamped segments.
        """
        import re
        
        segments = []
        text_parts = []
        
        # Match VTT timestamp lines: 00:00:00.000 --> 00:00:05.000
        # Followed by text until next timestamp or end
        pattern = r"(\d{2}:\d{2}:\d{2}[.,]\d{3})\s*-->\s*(\d{2}:\d{2}:\d{2}[.,]\d{3})\s*\n(.*?)(?=\n\d{2}:\d{2}:\d{2}|\n\n|\Z)"
        
        matches = re.findall(pattern, content, re.DOTALL)
        
        for start_time, end_time, text in matches:
            # Parse start time to seconds
            start_seconds = self._parse_timestamp(start_time)
            end_seconds = self._parse_timestamp(end_time)
            duration = end_seconds - start_seconds
            
            # Clean up text
            text = re.sub(r"<[^>]+>", "", text)  # Remove HTML tags
            text = text.strip()
            
            if text:
                segments.append({
                    "start": start_seconds,
                    "duration": duration,
                    "text": text,
                })
                text_parts.append(text)
        
        transcript = " ".join(text_parts)
        
        # If regex didn't find anything, fall back to simple parsing
        if not transcript:
            transcript = self._parse_subtitles(content)
        
        return transcript, segments

    def _parse_timestamp(self, timestamp: str) -> float:
        """Parse VTT/SRT timestamp to seconds."""
        # Handle both comma and period as decimal separator
        timestamp = timestamp.replace(",", ".")
        parts = timestamp.split(":")
        
        if len(parts) == 3:
            hours, minutes, seconds = parts
            return float(hours) * 3600 + float(minutes) * 60 + float(seconds)
        elif len(parts) == 2:
            minutes, seconds = parts
            return float(minutes) * 60 + float(seconds)
        else:
            return float(timestamp)

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
        channel_name: str,
        youtube_video_id: str,
        transcript: str,
    ) -> str:
        """Store transcript in blob storage.
        
        Uses channel-based paths for easy organization:
        {channel_name}/{youtube_video_id}/transcript.txt
        """
        blob_client = get_blob_client()
        blob_name = get_transcript_blob_path(channel_name, youtube_video_id)

        uri = blob_client.upload_blob(
            TRANSCRIPTS_CONTAINER,
            blob_name,
            transcript.encode("utf-8"),
            content_type="text/plain",
        )
        
        logger.info(
            "Stored transcript",
            youtube_video_id=youtube_video_id,
            channel_name=channel_name,
            blob_path=blob_name,
        )

        return uri

    async def _store_timestamped_segments(
        self,
        channel_name: str,
        youtube_video_id: str,
        segments: list[dict],
    ) -> str:
        """Store timestamped transcript segments as JSON for semantic search.
        
        Groups small segments into ~30 second chunks for better semantic coherence
        while preserving timestamp information.
        
        Uses channel-based paths for easy organization:
        {channel_name}/{youtube_video_id}/segments.json
        """
        import json
        
        # Sanity check for very long transcripts that could cause memory issues
        if len(segments) > 10000:
            logger.warning(
                "Very large number of segments detected",
                segment_count=len(segments),
                youtube_video_id=youtube_video_id,
            )
        
        # Group small segments into larger chunks (~30 seconds each)
        # This improves semantic search quality while preserving timestamps
        chunked_segments = []
        current_chunk = {
            "start": 0.0,
            "end": 0.0,
            "text": "",
        }
        chunk_duration = 30.0  # Target ~30 seconds per chunk
        
        for seg in segments:
            seg_start = seg["start"]
            seg_end = seg_start + seg.get("duration", 0)
            seg_text = seg["text"].strip()
            
            if not seg_text:
                continue
                
            # Start a new chunk if this segment would exceed the target duration
            if current_chunk["text"] and (seg_start - current_chunk["start"]) > chunk_duration:
                chunked_segments.append(current_chunk)
                current_chunk = {
                    "start": seg_start,
                    "end": seg_end,
                    "text": seg_text,
                }
            else:
                # Add to current chunk
                if not current_chunk["text"]:
                    current_chunk["start"] = seg_start
                current_chunk["end"] = seg_end
                current_chunk["text"] += (" " if current_chunk["text"] else "") + seg_text
        
        # Don't forget the last chunk
        if current_chunk["text"]:
            chunked_segments.append(current_chunk)
        
        blob_client = get_blob_client()
        blob_name = get_segments_blob_path(channel_name, youtube_video_id)
        
        uri = blob_client.upload_blob(
            TRANSCRIPTS_CONTAINER,
            blob_name,
            json.dumps(chunked_segments).encode("utf-8"),
            content_type="application/json",
        )
        
        logger.info(
            "Stored timestamped segments",
            youtube_video_id=youtube_video_id,
            channel_name=channel_name,
            blob_path=blob_name,
            segment_count=len(chunked_segments),
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
                batch_id=UUID(message.batch_id) if message.batch_id else None,
                job_type="summarize",
                stage="queued",
                status="pending",
                correlation_id=correlation_id,
            )
            session.add(job)
            await session.flush()

            # Queue the job
            queue_client = get_queue_client()
            queue_message = inject_trace_context({
                "job_id": str(job.job_id),
                "video_id": message.video_id,
                "youtube_video_id": message.youtube_video_id,
                "channel_name": message.channel_name,
                "correlation_id": correlation_id,
            })
            if message.batch_id:
                queue_message["batch_id"] = message.batch_id
            
            queue_client.send_message(SUMMARIZE_QUEUE, queue_message)

            logger.info("Queued summarize job", job_id=str(job.job_id))


def main():
    """Run the transcribe worker."""
    worker = TranscribeWorker()
    run_worker(worker)


if __name__ == "__main__":
    main()
