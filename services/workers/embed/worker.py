"""Embed worker for generating vector embeddings from video content."""

from dataclasses import dataclass
from typing import Any

import sqlalchemy as sa

from shared.blob.client import (
    SUMMARIES_CONTAINER,
    TRANSCRIPTS_CONTAINER,
    get_blob_client,
)
from shared.config import get_settings
from shared.db.connection import get_db
from shared.db.job_service import mark_job_completed, mark_job_failed, mark_job_running
from shared.db.models import Job, Video, Segment
from shared.logging.config import get_logger
from shared.queue.client import EMBED_QUEUE, RELATIONSHIPS_QUEUE, get_queue_client
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
    correlation_id: str
    batch_id: str | None = None
    retry_count: int = 0


class EmbedWorker(BaseWorker[EmbedMessage]):
    """Worker for generating vector embeddings from video content."""

    @property
    def queue_name(self) -> str:
        """Return the queue name."""
        return EMBED_QUEUE

    def parse_message(self, raw_message: dict[str, Any]) -> EmbedMessage:
        """Parse raw message to EmbedMessage."""
        return EmbedMessage(
            job_id=raw_message["job_id"],
            video_id=raw_message["video_id"],
            youtube_video_id=raw_message["youtube_video_id"],
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

        1. Fetch transcript and summary from blob storage
        2. Chunk the content
        3. Generate embeddings for each chunk
        4. Store embeddings in database
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

            # Fetch content
            transcript = await self._fetch_content(
                TRANSCRIPTS_CONTAINER,
                f"{message.video_id}/{message.youtube_video_id}_transcript.txt",
            )
            summary = await self._fetch_content(
                SUMMARIES_CONTAINER,
                f"{message.video_id}/{message.youtube_video_id}_summary.md",
            )

            if not transcript and not summary:
                await mark_job_failed(message.job_id, "Could not find transcript or summary")
                return WorkerResult.failed(
                    Exception("No content found"),
                    "Could not find transcript or summary",
                )

            # Combine content for embedding
            content = f"# Summary\n{summary or ''}\n\n# Transcript\n{transcript or ''}"

            # Chunk the content
            chunks = self._chunk_content(content)

            # Generate embeddings
            embeddings = await self._generate_embeddings(chunks)

            if not embeddings:
                await mark_job_failed(message.job_id, "OpenAI API failed to generate embeddings")
                return WorkerResult.failed(
                    Exception("Embedding generation failed"),
                    "OpenAI API failed to generate embeddings",
                )

            # Store embeddings
            await self._store_embeddings(message.video_id, chunks, embeddings)

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

    async def _generate_embeddings(self, chunks: list[str]) -> list[list[float]] | None:
        """Generate embeddings using OpenAI API."""
        try:
            from openai import AsyncOpenAI
            import random

            settings = get_settings()
            
            # Check if API key is configured (also check for placeholder value)
            if not settings.openai.api_key or settings.openai.api_key == "not-configured":
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
                return mock_embeddings
                
            client = AsyncOpenAI(api_key=settings.openai.api_key)

            embeddings = []

            # Process in batches of 100 (OpenAI limit)
            batch_size = 100
            for i in range(0, len(chunks), batch_size):
                batch = chunks[i : i + batch_size]

                response = await client.embeddings.create(
                    model="text-embedding-3-small",
                    input=batch,
                )

                for item in response.data:
                    embeddings.append(item.embedding)

                logger.debug(
                    "Batch embeddings generated",
                    batch_start=i,
                    batch_size=len(batch),
                )

            return embeddings

        except Exception as e:
            logger.error("OpenAI embeddings API call failed", error=str(e))
            return None

    async def _store_embeddings(
        self,
        video_id: str,
        chunks: list[str],
        embeddings: list[list[float]],
    ) -> None:
        """Store embeddings in database as Segments."""
        import hashlib
        import struct
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
                            ALTER TABLE Segments ADD Embedding VARBINARY(MAX) NULL
                        END
                    """)
                )
                await session.commit()
            except Exception as e:
                logger.warning("Could not check/add Embedding column", error=str(e))
                # Continue anyway - the column might exist

            # Delete existing segments for this video
            await session.execute(
                delete(Segment).where(Segment.video_id == UUID(video_id))
            )

            # Create new segments
            for i, (chunk, embedding) in enumerate(zip(chunks, embeddings)):
                # Convert embedding to binary (VARBINARY) format
                embedding_bytes = struct.pack(f'{len(embedding)}f', *embedding)
                
                # Calculate content hash
                content_hash = hashlib.sha256(chunk.encode()).hexdigest()
                
                segment = Segment(
                    video_id=UUID(video_id),
                    sequence_number=i,
                    start_time=0.0,  # Not applicable for summary chunks
                    end_time=0.0,
                    text=chunk[:4000],  # Limit text size for database
                    content_hash=content_hash,
                    model_name="text-embedding-3-small",
                )
                session.add(segment)
                await session.flush()
                
                # Store embedding as binary using raw SQL
                await session.execute(
                    sa.text("UPDATE Segments SET Embedding = :embedding WHERE segment_id = :segment_id"),
                    {"embedding": embedding_bytes, "segment_id": segment.segment_id}
                )

            logger.info(
                "Embeddings stored",
                video_id=video_id,
                chunk_count=len(chunks),
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
            queue_message = {
                "job_id": str(job.job_id),
                "video_id": message.video_id,
                "youtube_video_id": message.youtube_video_id,
                "correlation_id": correlation_id,
            }
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
