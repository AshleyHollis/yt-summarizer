"""Relationships worker for discovering related videos based on embeddings."""

import struct
from dataclasses import dataclass
from typing import Any

import numpy as np
import sqlalchemy as sa

from shared.config import get_settings
from shared.db.connection import get_db
from shared.db.job_service import mark_job_completed, mark_job_failed, mark_job_running
from shared.db.models import Job, Relationship, Segment, Video
from shared.logging.config import get_logger
from shared.queue.client import RELATIONSHIPS_QUEUE, get_queue_client
from shared.worker.base_worker import BaseWorker, WorkerResult, run_worker

logger = get_logger(__name__)

# Default settings
DEFAULT_SIMILARITY_THRESHOLD = 0.7
DEFAULT_MAX_RELATED = 10


@dataclass
class RelationshipsMessage:
    """Message payload for relationships jobs."""

    job_id: str
    video_id: str
    youtube_video_id: str
    channel_name: str
    correlation_id: str
    batch_id: str | None = None
    retry_count: int = 0


class RelationshipsWorker(BaseWorker[RelationshipsMessage]):
    """Worker for discovering related videos based on embeddings."""

    @property
    def queue_name(self) -> str:
        """Return the queue name."""
        return RELATIONSHIPS_QUEUE

    def parse_message(self, raw_message: dict[str, Any]) -> RelationshipsMessage:
        """Parse raw message to RelationshipsMessage."""
        return RelationshipsMessage(
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
        message: RelationshipsMessage,
        correlation_id: str,
    ) -> WorkerResult:
        """Process a relationships job.

        1. Get embeddings for the current video
        2. Compare with all other videos' embeddings
        3. Find similar videos above threshold
        4. Store related video records
        5. Update video processing status to completed
        """
        logger.info(
            "Processing relationships job",
            job_id=message.job_id,
            video_id=message.video_id,
        )

        try:
            # Mark job as running
            await mark_job_running(message.job_id, "relationships")

            # Get current video's embeddings
            current_embeddings = await self._get_video_embeddings(message.video_id)

            if not current_embeddings:
                logger.warning(
                    "No embeddings found for video",
                    video_id=message.video_id,
                )
                # Still mark as successful - video might not have enough content
                await self._update_video_status(message.video_id, "completed")
                await mark_job_completed(message.job_id)
                return WorkerResult.success(
                    message="No embeddings to compare",
                    data={"related_count": 0},
                )

            # Calculate average embedding for the video
            current_avg_embedding = self._average_embeddings(current_embeddings)

            # Find related videos
            related_videos = await self._find_related_videos(
                message.video_id,
                current_avg_embedding,
            )

            # Store relationships
            await self._store_relationships(message.video_id, related_videos)

            # Update video processing status
            await self._update_video_status(message.video_id, "completed")

            # Mark job as completed
            await mark_job_completed(message.job_id)

            logger.info(
                "Relationships job completed",
                job_id=message.job_id,
                related_count=len(related_videos),
            )

            return WorkerResult.success(
                message="Related videos discovered successfully",
                data={"related_count": len(related_videos)},
            )

        except Exception as e:
            logger.exception("Relationships job failed", job_id=message.job_id)
            await mark_job_failed(message.job_id, str(e))
            return WorkerResult.failed(e)

    async def _get_video_embeddings(self, video_id: str) -> list[list[float]]:
        """Get all embeddings for a video."""
        import json
        from uuid import UUID

        db = get_db()
        async with db.session() as session:
            # Get embeddings from Segments using raw SQL
            # Use CAST to convert VECTOR to VARCHAR for reliable retrieval
            result = await session.execute(
                sa.text("""
                    SELECT CAST(Embedding AS VARCHAR(MAX)) FROM Segments 
                    WHERE video_id = :video_id 
                    AND Embedding IS NOT NULL
                    ORDER BY sequence_number
                """),
                {"video_id": str(video_id)}
            )

            embeddings = []
            for row in result.fetchall():
                if row[0]:  # If embedding exists
                    embedding_str = row[0]
                    # VECTOR type returns as JSON array string like "[0.123, -0.456, ...]"
                    if isinstance(embedding_str, str):
                        # Parse JSON array string
                        embedding = json.loads(embedding_str)
                        embeddings.append(embedding)
                    elif isinstance(embedding_str, bytes):
                        # Fallback for binary format (legacy)
                        num_floats = len(embedding_str) // 4
                        embedding = list(struct.unpack(f'{num_floats}f', embedding_str))
                        embeddings.append(embedding)
            
            return embeddings

    def _average_embeddings(self, embeddings: list[list[float]]) -> list[float]:
        """Calculate the average of multiple embeddings."""
        if not embeddings:
            return []

        arr = np.array(embeddings)
        avg = np.mean(arr, axis=0)

        # Normalize the average embedding
        norm = np.linalg.norm(avg)
        if norm > 0:
            avg = avg / norm

        return avg.tolist()

    async def _find_related_videos(
        self,
        current_video_id: str,
        current_embedding: list[float],
    ) -> list[tuple[str, float]]:
        """Find related videos based on embedding similarity.

        Returns list of (video_id, similarity_score) tuples.
        """
        import json
        from uuid import UUID

        settings = get_settings()
        similarity_threshold = getattr(
            getattr(settings, "relationships", None),
            "similarity_threshold",
            DEFAULT_SIMILARITY_THRESHOLD,
        )
        max_related = getattr(
            getattr(settings, "relationships", None),
            "max_related",
            DEFAULT_MAX_RELATED,
        )

        db = get_db()
        async with db.session() as session:
            # Get all other videos with their embeddings
            # Use CAST to convert VECTOR to VARCHAR for reliable retrieval
            result = await session.execute(
                sa.text("""
                    SELECT video_id, CAST(Embedding AS VARCHAR(MAX)) FROM Segments 
                    WHERE video_id != :current_video_id 
                    AND Embedding IS NOT NULL
                """),
                {"current_video_id": str(current_video_id)}
            )

            # Group embeddings by video
            video_embeddings: dict[str, list[list[float]]] = {}
            for row in result.fetchall():
                vid = str(row[0])
                if row[1]:  # If embedding exists
                    embedding_str = row[1]
                    # VECTOR type returns as JSON array string like "[0.123, -0.456, ...]"
                    if isinstance(embedding_str, str):
                        embedding = json.loads(embedding_str)
                    elif isinstance(embedding_str, bytes):
                        # Fallback for binary format (legacy)
                        num_floats = len(embedding_str) // 4
                        embedding = list(struct.unpack(f'{num_floats}f', embedding_str))
                    else:
                        continue
                    if vid not in video_embeddings:
                        video_embeddings[vid] = []
                    video_embeddings[vid].append(embedding)

            # Calculate similarity for each video
            similarities = []
            current_arr = np.array(current_embedding)

            for vid, embeddings in video_embeddings.items():
                avg_embedding = self._average_embeddings(embeddings)
                if not avg_embedding:
                    continue

                # Cosine similarity (embeddings are normalized)
                other_arr = np.array(avg_embedding)
                similarity = float(np.dot(current_arr, other_arr))

                if similarity >= similarity_threshold:
                    similarities.append((vid, similarity))

            # Sort by similarity (descending) and limit
            similarities.sort(key=lambda x: x[1], reverse=True)
            return similarities[:max_related]

    async def _store_relationships(
        self,
        video_id: str,
        related_videos: list[tuple[str, float]],
    ) -> None:
        """Store related video records in database using Relationship model."""
        from uuid import UUID

        if not related_videos:
            return

        db = get_db()
        async with db.session() as session:
            from sqlalchemy import delete

            # Delete existing relationships for this video (as source)
            await session.execute(
                delete(Relationship).where(
                    Relationship.source_video_id == UUID(video_id)
                )
            )

            # Create new relationships
            for related_vid, score in related_videos:
                relationship = Relationship(
                    source_video_id=UUID(video_id),
                    target_video_id=UUID(related_vid),
                    relationship_type="same_topic",  # Valid enum: series, progression, same_topic, references, related
                    confidence=score,
                    rationale=f"Videos share similar content based on embedding similarity (score: {score:.3f})",
                    evidence_type="embedding",
                    model_name="text-embedding-3-small",
                )
                session.add(relationship)

            logger.info(
                "Relationships stored",
                video_id=video_id,
                related_count=len(related_videos),
            )

    async def _update_video_status(
        self,
        video_id: str,
        status: str,
    ) -> None:
        """Update video processing status."""
        from uuid import UUID

        db = get_db()
        async with db.session() as session:
            from sqlalchemy import select

            result = await session.execute(
                select(Video).where(Video.video_id == UUID(video_id))
            )
            video = result.scalar_one_or_none()

            if video:
                video.processing_status = status
                logger.info(
                    "Video status updated",
                    video_id=video_id,
                    status=status,
                )


def main():
    """Run the relationships worker."""
    worker = RelationshipsWorker()
    run_worker(worker)


if __name__ == "__main__":
    main()
