"""Embed worker for generating vector embeddings from video content."""

import os
from dataclasses import dataclass
from typing import Any

# Fix SSL certificate verification on Windows by using certifi's CA bundle
try:
    import certifi

    os.environ.setdefault("SSL_CERT_FILE", certifi.where())
except ImportError:
    pass  # certifi not installed, use system defaults

import sqlalchemy as sa

from shared.blob.client import (
    SUMMARIES_CONTAINER,
    TRANSCRIPTS_CONTAINER,
    get_blob_client,
    get_segments_blob_path,
    get_summary_blob_path,
    get_transcript_blob_path,
)
from shared.config import get_settings
from shared.db.connection import get_db
from shared.db.job_service import mark_job_completed, mark_job_failed, mark_job_running
from shared.db.models import Job, Segment
from shared.logging.config import get_logger
from shared.queue.client import EMBED_QUEUE, RELATIONSHIPS_QUEUE, get_queue_client
from shared.telemetry.config import inject_trace_context
from shared.worker.base_worker import BaseWorker, WorkerResult, run_worker

logger = get_logger(__name__)

# Default chunk settings
DEFAULT_CHUNK_SIZE = 1000
DEFAULT_CHUNK_OVERLAP = 200


@dataclass
class EmbedMessage:
    """Message payload for embed jobs."""

    job_id: str
    video_id: str
    youtube_video_id: str
    channel_name: str
    correlation_id: str
    batch_id: str | None = None
    retry_count: int = 0


class EmbedWorker(BaseWorker[EmbedMessage]):
    """Worker for generating vector embeddings from video content."""

    @property
    def queue_name(self) -> str:
        """Return the queue name."""
        return EMBED_QUEUE

    def get_additional_connectivity_checks(self) -> dict[str, Any]:
        """Add OpenAI connectivity check since this worker requires it for embeddings."""
        return {"openai": self._check_openai_connectivity}

    def parse_message(self, raw_message: dict[str, Any]) -> EmbedMessage:
        """Parse raw message to EmbedMessage."""
        return EmbedMessage(
            job_id=raw_message["job_id"],
            video_id=raw_message["video_id"],
            youtube_video_id=raw_message["youtube_video_id"],
            channel_name=raw_message.get("channel_name", "unknown-channel"),
            correlation_id=raw_message.get("correlation_id", "unknown"),
            batch_id=raw_message.get("batch_id"),
            retry_count=raw_message.get("retry_count", 0),
        )

    async def process_message(
        self,
        message: EmbedMessage,
        correlation_id: str,
    ) -> WorkerResult:
        """Process an embed job.

        1. Fetch timestamped segments from blob storage (preferred)
        2. Fall back to transcript/summary if segments not available
        3. Generate embeddings for each chunk
        4. Store embeddings in database with timestamps
        5. Queue next job (relationships)
        """
        logger.info(
            "Processing embed job",
            job_id=message.job_id,
            video_id=message.video_id,
        )

        try:
            # Mark job as running
            await mark_job_running(message.job_id, "embedding")

            # Try to fetch timestamped segments first (preferred for semantic search)
            # Use channel-based blob path
            segments_blob_path = get_segments_blob_path(
                message.channel_name, message.youtube_video_id
            )
            segments_json = await self._fetch_content(
                TRANSCRIPTS_CONTAINER,
                segments_blob_path,
            )

            timestamped_segments = None
            if segments_json:
                import json

                try:
                    timestamped_segments = json.loads(segments_json)
                    logger.info(
                        "Using timestamped segments for embeddings",
                        segment_count=len(timestamped_segments),
                    )
                except json.JSONDecodeError:
                    logger.warning("Failed to parse segments JSON, falling back to transcript")

            chunk_timestamps: list[tuple[float, float]] | None = None

            if timestamped_segments:
                # Use timestamped segments - extract text for embedding
                chunks = [seg["text"] for seg in timestamped_segments]
                chunk_timestamps = [(seg["start"], seg["end"]) for seg in timestamped_segments]
            else:
                # Fallback: Fetch transcript and summary (using channel-based blob paths)
                transcript_blob_path = get_transcript_blob_path(
                    message.channel_name, message.youtube_video_id
                )
                summary_blob_path = get_summary_blob_path(
                    message.channel_name, message.youtube_video_id
                )

                transcript = await self._fetch_content(
                    TRANSCRIPTS_CONTAINER,
                    transcript_blob_path,
                )
                summary = await self._fetch_content(
                    SUMMARIES_CONTAINER,
                    summary_blob_path,
                )

                if not transcript and not summary:
                    await mark_job_failed(message.job_id, "Could not find transcript or summary")
                    return WorkerResult.failed(
                        Exception("No content found"),
                        "Could not find transcript or summary",
                    )

                # Combine content for embedding (fallback path - no timestamps)
                content = f"# Summary\n{summary or ''}\n\n# Transcript\n{transcript or ''}"
                chunks = self._chunk_content(content)

            # Generate embeddings
            embeddings, error = await self._generate_embeddings(chunks)

            if not embeddings:
                error_msg = error or "OpenAI API failed to generate embeddings"
                # Truncate error message for database (max 4000 chars for SQL Server nvarchar)
                if len(error_msg) > 4000:
                    error_msg = error_msg[:3997] + "..."
                await mark_job_failed(message.job_id, error_msg)
                return WorkerResult.failed(
                    Exception("Embedding generation failed"),
                    error_msg,
                )

            # Store embeddings with timestamps if available
            await self._store_embeddings(
                message.video_id,
                message.youtube_video_id,
                chunks,
                embeddings,
                chunk_timestamps,
            )

            # Mark job as completed
            await mark_job_completed(message.job_id)

            # Queue next job (relationships)
            await self._queue_next_job(message, correlation_id)

            logger.info(
                "Embed job completed",
                job_id=message.job_id,
                chunk_count=len(chunks),
            )

            return WorkerResult.success(
                message="Embeddings generated successfully",
                data={"chunk_count": len(chunks)},
            )

        except Exception as e:
            logger.exception("Embed job failed", job_id=message.job_id)
            await mark_job_failed(message.job_id, str(e))
            return WorkerResult.failed(e)

    async def _fetch_content(self, container: str, blob_name: str) -> str | None:
        """Fetch content from blob storage."""
        try:
            blob_client = get_blob_client()
            content = blob_client.download_blob(container, blob_name)
            return content.decode("utf-8")
        except Exception as e:
            logger.warning("Failed to fetch content", blob_name=blob_name, error=str(e))
            return None

    def _chunk_content(self, content: str) -> list[str]:
        """Chunk content into smaller pieces for embedding.

        Uses a sliding window approach with overlap.
        """
        settings = get_settings()
        chunk_size = getattr(
            getattr(settings, "embeddings", None), "chunk_size", DEFAULT_CHUNK_SIZE
        )
        chunk_overlap = getattr(
            getattr(settings, "embeddings", None), "chunk_overlap", DEFAULT_CHUNK_OVERLAP
        )

        chunks = []
        start = 0
        text_length = len(content)

        while start < text_length:
            end = start + chunk_size

            # If this is not the last chunk, try to break at a sentence boundary
            if end < text_length:
                # Look for sentence boundaries
                for boundary in [". ", ".\n", "! ", "!\n", "? ", "?\n", "\n\n"]:
                    last_boundary = content.rfind(boundary, start, end)
                    if last_boundary > start + chunk_size // 2:
                        end = last_boundary + len(boundary)
                        break

            chunk = content[start:end].strip()
            if chunk:
                chunks.append(chunk)

            # Move to next chunk with overlap
            start = end - chunk_overlap

        logger.info(
            "Content chunked",
            total_length=text_length,
            chunk_count=len(chunks),
        )

        return chunks

    async def _generate_embeddings(
        self, chunks: list[str]
    ) -> tuple[list[list[float]] | None, str | None]:
        """Generate embeddings using OpenAI API.

        Returns:
            Tuple of (embeddings, error_message). If successful, embeddings is set and error is None.
            If failed, embeddings is None and error_message contains the failure reason.
        """
        import random

        settings = get_settings()

        # Log configuration for debugging
        logger.info(
            "DEBUG: _generate_embeddings config check",
            is_azure_configured=settings.openai.is_azure_configured,
            is_azure_ai_foundry=settings.openai.is_azure_ai_foundry,
            azure_openai_base_url=settings.openai.azure_openai_base_url,
            azure_embedding_deployment=settings.openai.azure_embedding_deployment,
        )

        # Check if any OpenAI configuration is available (Azure or standard)
        has_valid_config = settings.openai.is_azure_configured or (
            settings.openai.api_key and settings.openai.api_key != "not-configured"
        )

        # For Azure AI Foundry, also check if embedding deployment is configured
        embedding_deployment = settings.openai.azure_embedding_deployment
        if settings.openai.is_azure_ai_foundry and (
            not embedding_deployment or embedding_deployment == "not-configured"
        ):
            logger.warning(
                "Azure AI Foundry embedding deployment not configured - generating mock embeddings"
            )
            has_valid_config = False

        if not has_valid_config:
            logger.warning("OpenAI API key not configured - generating mock embeddings for testing")
            # Provide mock embeddings (1536 dimensions like text-embedding-3-small)
            mock_embeddings = []
            for _ in chunks:
                # Generate a random normalized vector
                embedding = [random.gauss(0, 1) for _ in range(1536)]
                # Normalize to unit length
                magnitude = sum(x**2 for x in embedding) ** 0.5
                embedding = [x / magnitude for x in embedding]
                mock_embeddings.append(embedding)
            return (mock_embeddings, None)

        try:
            # Use Azure OpenAI if configured, otherwise use standard OpenAI
            if settings.openai.is_azure_configured:
                base_url = settings.openai.azure_openai_base_url
                embedding_model = (
                    settings.openai.azure_embedding_deployment or "text-embedding-3-small"
                )

                # Azure AI Foundry uses OpenAI-compatible API with /models endpoint
                if settings.openai.is_azure_ai_foundry:
                    from openai import AsyncOpenAI

                    client = AsyncOpenAI(
                        api_key=settings.openai.effective_api_key,
                        base_url=base_url,
                        default_headers={"api-key": settings.openai.effective_api_key},
                    )
                    logger.info(
                        "Using Azure AI Foundry for embeddings",
                        original_endpoint=settings.openai.azure_endpoint,
                        base_url=base_url,
                        model=embedding_model,
                    )
                else:
                    # Standard Azure OpenAI
                    from openai import AsyncAzureOpenAI

                    client = AsyncAzureOpenAI(
                        api_key=settings.openai.effective_api_key,
                        azure_endpoint=base_url,
                        api_version=settings.openai.azure_api_version,
                    )
                    logger.info(
                        "Using Azure OpenAI for embeddings",
                        original_endpoint=settings.openai.azure_endpoint,
                        base_url=base_url,
                        deployment=embedding_model,
                    )
            else:
                from openai import AsyncOpenAI

                client = AsyncOpenAI(api_key=settings.openai.api_key)
                embedding_model = settings.openai.embedding_model

            embeddings = []

            # Process in batches of 100 (OpenAI limit)
            batch_size = 100
            for i in range(0, len(chunks), batch_size):
                batch = chunks[i : i + batch_size]

                response = await client.embeddings.create(
                    model=embedding_model,
                    input=batch,
                )

                for item in response.data:
                    embeddings.append(item.embedding)

                logger.debug(
                    "Batch embeddings generated",
                    batch_start=i,
                    batch_size=len(batch),
                )

            return (embeddings, None)

        except Exception as e:
            import traceback

            error_details = f"{type(e).__name__}: {str(e)}"
            full_traceback = traceback.format_exc()
            logger.error(
                "OpenAI embeddings API call failed",
                error=str(e),
                error_type=type(e).__name__,
                traceback=full_traceback,
            )
            return (None, f"{error_details}\n\nTraceback:\n{full_traceback}")

    async def _store_embeddings(
        self,
        video_id: str,
        youtube_video_id: str,
        chunks: list[str],
        embeddings: list[list[float]],
        timestamps: list[tuple[float, float]] | None = None,
    ) -> None:
        """Store embeddings in database as Segments.

        Args:
            video_id: Internal UUID for the video
            youtube_video_id: YouTube video ID for logging
            chunks: List of text chunks to store
            embeddings: List of embedding vectors
            timestamps: Optional list of (start_time, end_time) tuples for each chunk
        """
        import hashlib
        from uuid import UUID

        db = get_db()
        async with db.session() as session:
            from sqlalchemy import delete

            # Ensure Embedding column exists (handle case where migration didn't run the ALTER)
            try:
                await session.execute(
                    sa.text("""
                        IF NOT EXISTS (
                            SELECT 1 FROM INFORMATION_SCHEMA.COLUMNS
                            WHERE TABLE_NAME = 'Segments' AND COLUMN_NAME = 'Embedding'
                        )
                        BEGIN
                            ALTER TABLE Segments ADD Embedding VECTOR(1536) NULL
                        END
                    """)
                )
                await session.commit()
            except Exception as e:
                logger.warning("Could not check/add Embedding column", error=str(e))
                # Continue anyway - the column might exist

            # Delete existing segments for this video
            await session.execute(delete(Segment).where(Segment.video_id == UUID(video_id)))

            # Create new segments
            has_timestamps = timestamps and len(timestamps) == len(chunks)
            for i, (chunk, embedding) in enumerate(zip(chunks, embeddings)):
                # Convert embedding to JSON array format for VECTOR type
                embedding_json = "[" + ",".join(str(x) for x in embedding) + "]"

                # Calculate content hash
                content_hash = hashlib.sha256(chunk.encode()).hexdigest()

                # Use real timestamps if available, otherwise default to 0.0
                start_time = timestamps[i][0] if has_timestamps else 0.0
                end_time = timestamps[i][1] if has_timestamps else 0.0

                segment = Segment(
                    video_id=UUID(video_id),
                    sequence_number=i,
                    start_time=start_time,
                    end_time=end_time,
                    text=chunk[:4000],  # Limit text size for database
                    content_hash=content_hash,
                    model_name="text-embedding-3-small",
                )
                session.add(segment)
                await session.flush()

                # Store embedding as VECTOR - use literal SQL to avoid type conversion issues
                # SQL Server 2025 VECTOR accepts JSON array format directly
                await session.execute(
                    sa.text(
                        f"UPDATE Segments SET Embedding = CAST('{embedding_json}' AS VECTOR(1536)) WHERE segment_id = :segment_id"
                    ),
                    {"segment_id": segment.segment_id},
                )

            logger.info(
                "Embeddings stored",
                video_id=video_id,
                youtube_video_id=youtube_video_id,
                chunk_count=len(chunks),
                has_timestamps=has_timestamps,
            )

    async def _queue_next_job(
        self,
        message: EmbedMessage,
        correlation_id: str,
    ) -> None:
        """Queue the next job (relationships)."""
        from uuid import UUID

        db = get_db()
        async with db.session() as session:
            # Create relationships job
            job = Job(
                video_id=UUID(message.video_id),
                batch_id=UUID(message.batch_id) if message.batch_id else None,
                job_type="build_relationships",
                stage="queued",
                status="pending",
                correlation_id=correlation_id,
            )
            session.add(job)
            await session.flush()

            # Queue the job
            queue_client = get_queue_client()
            queue_message = inject_trace_context(
                {
                    "job_id": str(job.job_id),
                    "video_id": message.video_id,
                    "youtube_video_id": message.youtube_video_id,
                    "channel_name": message.channel_name,
                    "correlation_id": correlation_id,
                }
            )
            if message.batch_id:
                queue_message["batch_id"] = message.batch_id

            queue_client.send_message(RELATIONSHIPS_QUEUE, queue_message)

            logger.info("Queued relationships job", job_id=str(job.job_id))


def main():
    """Run the embed worker."""
    worker = EmbedWorker()
    run_worker(worker)


if __name__ == "__main__":
    main()
