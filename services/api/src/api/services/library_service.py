"""Library service for browsing and filtering videos."""

from datetime import datetime
from uuid import UUID

from sqlalchemy import Select, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

# Import shared modules
try:
    from shared.blob.client import SUMMARIES_CONTAINER, BlobClient
    from shared.db.models import (
        Artifact,
        Channel,
        Facet,
        Relationship,
        Segment,
        Video,
        VideoFacet,
    )
    from shared.logging.config import get_logger
except ImportError as e:
    import logging

    logging.warning(f"Failed to import shared modules: {e}")
    # Fallback for development
    from typing import Any

    Artifact = Any
    Channel = Any
    Facet = Any
    Relationship = Any
    Segment = Any
    Video = Any
    VideoFacet = Any
    BlobClient = None
    SUMMARIES_CONTAINER = "summaries"

    def get_logger(name):
        import logging

        return logging.getLogger(name)


from ..models.channel import ChannelCard, ChannelDetailResponse, ChannelListResponse
from ..models.facet import FacetCount, FacetListResponse
from ..models.library import (
    ArtifactInfo,
    ChannelSummaryLibrary,
    FacetTag,
    LibraryStatsResponse,
    SegmentListResponse,
    SortField,
    SortOrder,
    VideoCard,
    VideoDetailResponse,
    VideoFilterParams,
    VideoListResponse,
)
from ..models.library import (
    Segment as SegmentModel,
)

logger = get_logger(__name__)


class LibraryService:
    """Service for library browsing operations."""

    def __init__(self, session: AsyncSession):
        """Initialize the library service.

        Args:
            session: Database session.
        """
        self.session = session

    def _build_video_query(self, filters: VideoFilterParams) -> Select:
        """Build the base query for videos with filters.

        Args:
            filters: Video filter parameters.

        Returns:
            SQLAlchemy select query.
        """
        query = select(Video).options(selectinload(Video.channel))

        # Apply filters
        if filters.channel_id:
            query = query.where(Video.channel_id == filters.channel_id)

        if filters.from_date:
            query = query.where(
                Video.publish_date >= datetime.combine(filters.from_date, datetime.min.time())
            )

        if filters.to_date:
            query = query.where(
                Video.publish_date <= datetime.combine(filters.to_date, datetime.max.time())
            )

        if filters.status:
            query = query.where(Video.processing_status == filters.status.value)

        if filters.search:
            search_pattern = f"%{filters.search}%"
            # Search in title, description, AND transcript segments
            # Use a subquery to find videos with matching segment text
            segment_match_subquery = (
                select(Segment.video_id).where(Segment.text.ilike(search_pattern)).distinct()
            )
            query = query.where(
                or_(
                    Video.title.ilike(search_pattern),
                    Video.description.ilike(search_pattern),
                    Video.video_id.in_(segment_match_subquery),
                )
            )

        # Facet filtering - videos must have all specified facets
        if filters.facets:
            for facet_id in filters.facets:
                subquery = select(VideoFacet.video_id).where(VideoFacet.facet_id == facet_id)
                query = query.where(Video.video_id.in_(subquery))

        # Apply sorting
        sort_column = {
            SortField.PUBLISH_DATE: Video.publish_date,
            SortField.TITLE: Video.title,
            SortField.CREATED_AT: Video.created_at,
        }.get(filters.sort_by, Video.publish_date)

        if filters.sort_order == SortOrder.DESC:
            query = query.order_by(sort_column.desc())
        else:
            query = query.order_by(sort_column.asc())

        return query

    async def list_videos(self, filters: VideoFilterParams) -> VideoListResponse:
        """List videos with filtering and pagination.

        Args:
            filters: Video filter parameters.

        Returns:
            Paginated list of video cards.
        """
        # Build base query
        query = self._build_video_query(filters)

        # Get total count
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await self.session.execute(count_query)
        total_count = total_result.scalar() or 0

        # Apply pagination
        offset = (filters.page - 1) * filters.page_size
        query = query.offset(offset).limit(filters.page_size)

        # Execute query
        result = await self.session.execute(query)
        videos = result.scalars().all()

        # Get segment counts for all videos
        video_ids = [v.video_id for v in videos]
        segment_counts = await self._get_segment_counts(video_ids)

        # Get facets for all videos
        video_facets = await self._get_video_facets(video_ids)

        # Build video cards
        video_cards = []
        for video in videos:
            video_cards.append(
                VideoCard(
                    video_id=video.video_id,
                    youtube_video_id=video.youtube_video_id,
                    title=video.title,
                    channel_id=video.channel_id,
                    channel_name=video.channel.name,
                    channel_thumbnail_url=video.channel.thumbnail_url,
                    duration=video.duration,
                    publish_date=video.publish_date,
                    thumbnail_url=video.thumbnail_url,
                    processing_status=video.processing_status,
                    segment_count=segment_counts.get(video.video_id, 0),
                    facets=video_facets.get(video.video_id, []),
                )
            )

        return VideoListResponse(
            videos=video_cards,
            page=filters.page,
            page_size=filters.page_size,
            total_count=total_count,
        )

    async def get_video_detail(self, video_id: UUID) -> VideoDetailResponse | None:
        """Get full video details.

        Args:
            video_id: Video ID.

        Returns:
            Video detail response or None if not found.
        """
        query = (
            select(Video)
            .options(
                selectinload(Video.channel),
                selectinload(Video.artifacts),
            )
            .where(Video.video_id == video_id)
        )
        result = await self.session.execute(query)
        video = result.scalar_one_or_none()

        if not video:
            return None

        # Get segment count
        segment_count_result = await self.session.execute(
            select(func.count()).where(Segment.video_id == video_id)
        )
        segment_count = segment_count_result.scalar() or 0

        # Get relationship count
        relationship_count_result = await self.session.execute(
            select(func.count()).where(
                or_(
                    Relationship.source_video_id == video_id,
                    Relationship.target_video_id == video_id,
                )
            )
        )
        relationship_count = relationship_count_result.scalar() or 0

        # Get facets
        video_facets = await self._get_video_facets([video_id])
        facets = video_facets.get(video_id, [])

        # Get artifacts
        summary_artifact = None
        transcript_artifact = None
        summary_text = None
        summary_blob_name = None

        for artifact in video.artifacts:
            artifact_info = ArtifactInfo(
                artifact_id=artifact.artifact_id,
                type=artifact.artifact_type,
                content_length=artifact.content_length,
                model_name=artifact.model_name,
                created_at=artifact.created_at,
            )
            if artifact.artifact_type == "summary":
                summary_artifact = artifact_info
                # Extract blob name from blob_uri for fetching content
                # blob_uri format: http://host/account/container/{video_id}/{youtube_video_id}_summary.md
                # We need to extract: {video_id}/{youtube_video_id}_summary.md (everything after container name)
                if artifact.blob_uri:
                    parts = artifact.blob_uri.split(f"/{SUMMARIES_CONTAINER}/")
                    summary_blob_name = (
                        parts[1] if len(parts) > 1 else artifact.blob_uri.split("/")[-1]
                    )
                else:
                    summary_blob_name = None
            elif artifact.artifact_type == "transcript":
                transcript_artifact = artifact_info

        # Fetch summary content from blob storage if available
        if summary_blob_name and BlobClient is not None:
            try:
                blob_client = BlobClient()
                summary_bytes = blob_client.download_blob(SUMMARIES_CONTAINER, summary_blob_name)
                summary_text = summary_bytes.decode("utf-8")
            except Exception as e:
                logger.warning(f"Failed to fetch summary from blob: {e}")
                summary_text = None

        return VideoDetailResponse(
            video_id=video.video_id,
            youtube_video_id=video.youtube_video_id,
            title=video.title,
            description=video.description,
            channel=ChannelSummaryLibrary(
                channel_id=video.channel.channel_id,
                youtube_channel_id=video.channel.youtube_channel_id,
                name=video.channel.name,
                thumbnail_url=video.channel.thumbnail_url,
            ),
            duration=video.duration,
            publish_date=video.publish_date,
            thumbnail_url=video.thumbnail_url,
            youtube_url=f"https://www.youtube.com/watch?v={video.youtube_video_id}",
            processing_status=video.processing_status,
            summary=summary_text,
            summary_artifact=summary_artifact,
            transcript_artifact=transcript_artifact,
            segment_count=segment_count,
            relationship_count=relationship_count,
            facets=facets,
            created_at=video.created_at,
            updated_at=video.updated_at,
        )

    async def list_segments(
        self,
        video_id: UUID,
        page: int = 1,
        page_size: int = 50,
    ) -> SegmentListResponse | None:
        """List segments for a video with pagination.

        Args:
            video_id: Video ID.
            page: Page number.
            page_size: Items per page.

        Returns:
            Paginated list of segments or None if video not found.
        """
        # Verify video exists
        video_result = await self.session.execute(
            select(Video.video_id, Video.youtube_video_id).where(Video.video_id == video_id)
        )
        video = video_result.one_or_none()
        if not video:
            return None

        # Get total count
        count_result = await self.session.execute(
            select(func.count()).where(Segment.video_id == video_id)
        )
        total_count = count_result.scalar() or 0

        # Get segments
        offset = (page - 1) * page_size
        segments_result = await self.session.execute(
            select(Segment)
            .where(Segment.video_id == video_id)
            .order_by(Segment.sequence_number)
            .offset(offset)
            .limit(page_size)
        )
        segments = segments_result.scalars().all()

        youtube_video_id = video.youtube_video_id

        return SegmentListResponse(
            video_id=video_id,
            segments=[
                SegmentModel(
                    segment_id=s.segment_id,
                    sequence_number=s.sequence_number,
                    start_time=s.start_time,
                    end_time=s.end_time,
                    text=s.text,
                    youtube_url=f"https://www.youtube.com/watch?v={youtube_video_id}&t={int(s.start_time)}",
                )
                for s in segments
            ],
            page=page,
            page_size=page_size,
            total_count=total_count,
        )

    async def list_channels(
        self,
        page: int = 1,
        page_size: int = 20,
        search: str | None = None,
    ) -> ChannelListResponse:
        """List channels with pagination.

        Args:
            page: Page number.
            page_size: Items per page.
            search: Optional search filter.

        Returns:
            Paginated list of channel cards.
        """
        query = select(Channel)

        if search:
            query = query.where(Channel.name.ilike(f"%{search}%"))

        # Get total count
        count_query = select(func.count()).select_from(query.subquery())
        total_result = await self.session.execute(count_query)
        total_count = total_result.scalar() or 0

        # Apply pagination and ordering
        offset = (page - 1) * page_size
        query = query.order_by(Channel.name).offset(offset).limit(page_size)

        result = await self.session.execute(query)
        channels = result.scalars().all()

        # Get video counts for each channel
        channel_ids = [c.channel_id for c in channels]
        video_counts = await self._get_channel_video_counts(channel_ids)

        return ChannelListResponse(
            channels=[
                ChannelCard(
                    channel_id=c.channel_id,
                    youtube_channel_id=c.youtube_channel_id,
                    name=c.name,
                    thumbnail_url=c.thumbnail_url,
                    video_count=video_counts.get(c.channel_id, 0),
                    last_synced_at=c.last_synced_at,
                )
                for c in channels
            ],
            page=page,
            page_size=page_size,
            total_count=total_count,
        )

    async def get_channel_detail(self, channel_id: UUID) -> ChannelDetailResponse | None:
        """Get full channel details.

        Args:
            channel_id: Channel ID.

        Returns:
            Channel detail response or None if not found.
        """
        result = await self.session.execute(select(Channel).where(Channel.channel_id == channel_id))
        channel = result.scalar_one_or_none()

        if not channel:
            return None

        # Get video counts
        video_count_result = await self.session.execute(
            select(func.count()).where(Video.channel_id == channel_id)
        )
        video_count = video_count_result.scalar() or 0

        completed_count_result = await self.session.execute(
            select(func.count()).where(
                Video.channel_id == channel_id,
                Video.processing_status == "completed",
            )
        )
        completed_count = completed_count_result.scalar() or 0

        # Get top facets for this channel
        top_facets = await self._get_channel_top_facets(channel_id)

        return ChannelDetailResponse(
            channel_id=channel.channel_id,
            youtube_channel_id=channel.youtube_channel_id,
            name=channel.name,
            description=channel.description,
            thumbnail_url=channel.thumbnail_url,
            youtube_url=f"https://www.youtube.com/channel/{channel.youtube_channel_id}",
            video_count=video_count,
            completed_video_count=completed_count,
            last_synced_at=channel.last_synced_at,
            top_facets=top_facets,
            created_at=channel.created_at,
            updated_at=channel.updated_at,
        )

    async def list_facets(
        self,
        facet_type: str | None = None,
        min_count: int = 1,
    ) -> FacetListResponse:
        """List facets with video counts.

        Args:
            facet_type: Optional filter by facet type.
            min_count: Minimum video count to include.

        Returns:
            List of facets with counts.
        """
        query = (
            select(
                Facet.facet_id,
                Facet.name,
                Facet.facet_type,
                func.count(VideoFacet.video_id).label("video_count"),
            )
            .outerjoin(VideoFacet, Facet.facet_id == VideoFacet.facet_id)
            .group_by(Facet.facet_id, Facet.name, Facet.facet_type)
            .having(func.count(VideoFacet.video_id) >= min_count)
            .order_by(func.count(VideoFacet.video_id).desc())
        )

        if facet_type:
            query = query.where(Facet.facet_type == facet_type)

        result = await self.session.execute(query)
        rows = result.all()

        return FacetListResponse(
            facets=[
                FacetCount(
                    facet_id=row.facet_id,
                    name=row.name,
                    type=row.facet_type,
                    video_count=row.video_count,
                )
                for row in rows
            ]
        )

    async def get_library_stats(self) -> LibraryStatsResponse:
        """Get overall library statistics.

        Returns:
            Library statistics.
        """
        # Total channels
        channel_count = await self.session.execute(select(func.count()).select_from(Channel))
        total_channels = channel_count.scalar() or 0

        # Total videos
        video_count = await self.session.execute(select(func.count()).select_from(Video))
        total_videos = video_count.scalar() or 0

        # Completed videos
        completed_count = await self.session.execute(
            select(func.count()).where(Video.processing_status == "completed")
        )
        completed_videos = completed_count.scalar() or 0

        # Total segments
        segment_count = await self.session.execute(select(func.count()).select_from(Segment))
        total_segments = segment_count.scalar() or 0

        # Total relationships
        rel_count = await self.session.execute(select(func.count()).select_from(Relationship))
        total_relationships = rel_count.scalar() or 0

        # Total facets
        facet_count = await self.session.execute(select(func.count()).select_from(Facet))
        total_facets = facet_count.scalar() or 0

        # Last updated
        last_updated_result = await self.session.execute(select(func.max(Video.updated_at)))
        last_updated_at = last_updated_result.scalar()

        return LibraryStatsResponse(
            total_channels=total_channels,
            total_videos=total_videos,
            completed_videos=completed_videos,
            total_segments=total_segments,
            total_relationships=total_relationships,
            total_facets=total_facets,
            last_updated_at=last_updated_at,
        )

    async def _get_segment_counts(self, video_ids: list[UUID]) -> dict[UUID, int]:
        """Get segment counts for multiple videos.

        Args:
            video_ids: List of video IDs.

        Returns:
            Dictionary mapping video ID to segment count.
        """
        if not video_ids:
            return {}

        result = await self.session.execute(
            select(Segment.video_id, func.count().label("count"))
            .where(Segment.video_id.in_(video_ids))
            .group_by(Segment.video_id)
        )

        return {row.video_id: row.count for row in result.all()}

    async def _get_video_facets(self, video_ids: list[UUID]) -> dict[UUID, list[FacetTag]]:
        """Get facets for multiple videos.

        Args:
            video_ids: List of video IDs.

        Returns:
            Dictionary mapping video ID to list of facet tags.
        """
        if not video_ids:
            return {}

        result = await self.session.execute(
            select(VideoFacet.video_id, Facet)
            .join(Facet, VideoFacet.facet_id == Facet.facet_id)
            .where(VideoFacet.video_id.in_(video_ids))
        )

        facets_by_video: dict[UUID, list[FacetTag]] = {vid: [] for vid in video_ids}
        for row in result.all():
            facet = row[1]
            facets_by_video[row.video_id].append(
                FacetTag(
                    facet_id=facet.facet_id,
                    name=facet.name,
                    type=facet.facet_type,
                )
            )

        return facets_by_video

    async def _get_channel_video_counts(self, channel_ids: list[UUID]) -> dict[UUID, int]:
        """Get video counts for multiple channels.

        Args:
            channel_ids: List of channel IDs.

        Returns:
            Dictionary mapping channel ID to video count.
        """
        if not channel_ids:
            return {}

        result = await self.session.execute(
            select(Video.channel_id, func.count().label("count"))
            .where(Video.channel_id.in_(channel_ids))
            .group_by(Video.channel_id)
        )

        return {row.channel_id: row.count for row in result.all()}

    async def _get_channel_top_facets(self, channel_id: UUID, limit: int = 10) -> list[FacetTag]:
        """Get top facets for a channel.

        Args:
            channel_id: Channel ID.
            limit: Maximum number of facets to return.

        Returns:
            List of top facet tags.
        """
        result = await self.session.execute(
            select(Facet, func.count().label("count"))
            .join(VideoFacet, Facet.facet_id == VideoFacet.facet_id)
            .join(Video, VideoFacet.video_id == Video.video_id)
            .where(Video.channel_id == channel_id)
            .group_by(Facet.facet_id)
            .order_by(func.count().desc())
            .limit(limit)
        )

        return [
            FacetTag(
                facet_id=row[0].facet_id,
                name=row[0].name,
                type=row[0].facet_type,
            )
            for row in result.all()
        ]
