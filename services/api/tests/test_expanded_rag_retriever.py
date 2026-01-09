"""Unit tests for the Expanded RAG Retriever.

Tests cover:
1. Query expansion parsing and fallback behavior
2. Deduplication across queries
3. RRF scoring correctness
4. Ensuring segments ranked >15 in single queries can appear via fusion
5. MMR diversity selection
"""

from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest

from api.models.copilot import (
    ScoredSegment,
    SegmentSearchResponse,
)
from api.services.expanded_rag_retriever import (
    ExpandedRagRetriever,
    FusedSegment,
    RetrievalResult,
    RetrievalTelemetry,
    compute_rrf_score,
    cosine_similarity,
    expand_query_for_retrieval,
    fuse_ranked_lists,
    jaccard_similarity,
    parse_query_expansion_response,
    select_mmr,
    select_top_k,
)
from api.services.llm_service import LLMService
from api.services.search_service import SearchService

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def mock_llm_service():
    """Create a mock LLM service."""
    service = MagicMock(spec=LLMService)
    service.client = MagicMock()
    service.settings = MagicMock()
    service.settings.openai.effective_model = "gpt-4o"
    service.get_embedding = AsyncMock(return_value=[0.1] * 1536)
    return service


@pytest.fixture
def mock_db_session():
    """Create a mock database session."""
    session = AsyncMock()
    session.execute = AsyncMock()
    return session


def create_segment(
    text: str = "Sample text",
    score: float = 0.5,
    video_id=None,
    segment_id=None,
) -> ScoredSegment:
    """Helper to create a scored segment for testing."""
    return ScoredSegment(
        segment_id=segment_id or uuid4(),
        video_id=video_id or uuid4(),
        video_title="Test Video",
        channel_name="Test Channel",
        text=text,
        start_time=0.0,
        end_time=60.0,
        youtube_url="https://youtube.com/watch?v=test&t=0s",
        score=score,
    )


# =============================================================================
# Query Expansion Tests
# =============================================================================


class TestQueryExpansionParsing:
    """Tests for query expansion JSON parsing."""

    def test_parse_simple_json_array(self):
        """Test parsing a simple JSON array response."""
        content = '["query 1", "query 2", "query 3"]'
        result = parse_query_expansion_response(content)
        assert result == ["query 1", "query 2", "query 3"]

    def test_parse_json_with_markdown_code_block(self):
        """Test parsing JSON wrapped in markdown code blocks."""
        content = '```json\n["query 1", "query 2"]\n```'
        result = parse_query_expansion_response(content)
        assert result == ["query 1", "query 2"]

    def test_parse_json_with_surrounding_text(self):
        """Test parsing JSON with extra text around it."""
        content = 'Here are the queries: ["query 1", "query 2"] Hope this helps!'
        result = parse_query_expansion_response(content)
        assert result == ["query 1", "query 2"]

    def test_parse_empty_array(self):
        """Test parsing an empty array."""
        content = "[]"
        result = parse_query_expansion_response(content)
        assert result == []

    def test_parse_invalid_json(self):
        """Test parsing invalid JSON returns empty list."""
        content = "not valid json at all"
        result = parse_query_expansion_response(content)
        assert result == []

    def test_parse_missing_brackets(self):
        """Test parsing content without JSON array brackets."""
        content = '"query 1", "query 2"'
        result = parse_query_expansion_response(content)
        assert result == []


class TestQueryExpansionFallback:
    """Tests for query expansion fallback behavior."""

    @pytest.mark.asyncio
    async def test_expansion_always_includes_original(self, mock_llm_service):
        """Original query should always be first, even on success."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = '["expanded 1", "expanded 2"]'

        mock_llm_service.client.chat.completions.create = AsyncMock(return_value=mock_response)

        result = await expand_query_for_retrieval(
            mock_llm_service,
            "original query",
            max_variants=5,
        )

        assert result[0] == "original query"
        assert len(result) >= 2

    @pytest.mark.asyncio
    async def test_expansion_fallback_on_api_error(self, mock_llm_service):
        """On API error, should return only original query."""
        mock_llm_service.client.chat.completions.create = AsyncMock(
            side_effect=Exception("API error")
        )

        result = await expand_query_for_retrieval(
            mock_llm_service,
            "original query",
        )

        assert result == ["original query"]

    @pytest.mark.asyncio
    async def test_expansion_fallback_on_invalid_json(self, mock_llm_service):
        """On invalid JSON, should return only original query."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "not json"

        mock_llm_service.client.chat.completions.create = AsyncMock(return_value=mock_response)

        result = await expand_query_for_retrieval(
            mock_llm_service,
            "original query",
        )

        assert result == ["original query"]

    @pytest.mark.asyncio
    async def test_expansion_respects_max_variants(self, mock_llm_service):
        """Should respect max_variants limit."""
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = '["q1", "q2", "q3", "q4", "q5", "q6", "q7"]'

        mock_llm_service.client.chat.completions.create = AsyncMock(return_value=mock_response)

        result = await expand_query_for_retrieval(
            mock_llm_service,
            "original query",
            max_variants=3,
        )

        # Original + 2 expansions = 3 max
        assert len(result) <= 3


# =============================================================================
# RRF Scoring Tests
# =============================================================================


class TestRRFScoring:
    """Tests for Reciprocal Rank Fusion scoring."""

    def test_rrf_score_rank_1(self):
        """RRF score for rank 1 with default k=60."""
        score = compute_rrf_score(1, k=60)
        assert score == pytest.approx(1 / 61)

    def test_rrf_score_rank_10(self):
        """RRF score for rank 10 with default k=60."""
        score = compute_rrf_score(10, k=60)
        assert score == pytest.approx(1 / 70)

    def test_rrf_score_decreases_with_rank(self):
        """Higher rank should have lower RRF score."""
        score_1 = compute_rrf_score(1)
        score_5 = compute_rrf_score(5)
        score_10 = compute_rrf_score(10)
        score_100 = compute_rrf_score(100)

        assert score_1 > score_5 > score_10 > score_100

    def test_rrf_score_with_different_k(self):
        """Different k values affect score distribution."""
        score_k20 = compute_rrf_score(1, k=20)
        score_k60 = compute_rrf_score(1, k=60)
        score_k100 = compute_rrf_score(1, k=100)

        # Lower k = higher score for top ranks
        assert score_k20 > score_k60 > score_k100


class TestRRFFusion:
    """Tests for RRF fusion of ranked lists."""

    def test_fusion_single_query(self):
        """Fusion with single query should preserve order."""
        seg1 = create_segment(text="Segment 1", score=0.1)
        seg2 = create_segment(text="Segment 2", score=0.2)
        seg3 = create_segment(text="Segment 3", score=0.3)

        ranked_lists = {
            "query1": [seg1, seg2, seg3],
        }

        fused = fuse_ranked_lists(ranked_lists)

        assert len(fused) == 3
        assert fused[0].segment.text == "Segment 1"
        assert fused[1].segment.text == "Segment 2"
        assert fused[2].segment.text == "Segment 3"

    def test_fusion_boosts_segments_in_multiple_queries(self):
        """Segments appearing in multiple queries should rank higher."""
        # Same segment ID appears in multiple queries
        shared_id = uuid4()

        seg1_q1 = create_segment(text="Shared", score=0.5, segment_id=shared_id)
        seg2_q1 = create_segment(text="Only Q1", score=0.1)

        seg1_q2 = create_segment(text="Shared", score=0.4, segment_id=shared_id)
        seg3_q2 = create_segment(text="Only Q2", score=0.1)

        ranked_lists = {
            "query1": [seg2_q1, seg1_q1],  # Shared is rank 2
            "query2": [seg3_q2, seg1_q2],  # Shared is rank 2
        }

        fused = fuse_ranked_lists(ranked_lists)

        # Find the shared segment
        shared_fused = next(f for f in fused if f.segment.segment_id == shared_id)

        # Should have contributions from both queries
        assert len(shared_fused.source_queries) == 2
        # RRF score is sum of both: 1/(60+2) + 1/(60+2) = 2/62
        expected_score = 2 * compute_rrf_score(2)
        assert shared_fused.rrf_score == pytest.approx(expected_score)

    def test_fusion_tracks_best_distance(self):
        """Fusion should track the best (lowest) distance across queries."""
        shared_id = uuid4()

        seg_q1 = create_segment(text="Shared", score=0.6, segment_id=shared_id)
        seg_q2 = create_segment(text="Shared", score=0.3, segment_id=shared_id)  # Better score
        seg_q3 = create_segment(text="Shared", score=0.5, segment_id=shared_id)

        ranked_lists = {
            "query1": [seg_q1],
            "query2": [seg_q2],
            "query3": [seg_q3],
        }

        fused = fuse_ranked_lists(ranked_lists)

        assert len(fused) == 1
        assert fused[0].best_distance == 0.3  # The lowest

    def test_fusion_respects_max_results(self):
        """Fusion should respect max_results limit."""
        segments = [create_segment(text=f"Seg {i}", score=i * 0.1) for i in range(10)]

        ranked_lists = {"query1": segments}

        fused = fuse_ranked_lists(ranked_lists, max_results=5)

        assert len(fused) == 5

    def test_deduplication_across_queries(self):
        """Same segment_id from different queries should be deduplicated."""
        shared_id = uuid4()
        unique_id1 = uuid4()
        unique_id2 = uuid4()

        seg_shared_q1 = create_segment(score=0.3, segment_id=shared_id)
        seg_unique_q1 = create_segment(score=0.2, segment_id=unique_id1)

        seg_shared_q2 = create_segment(score=0.4, segment_id=shared_id)
        seg_unique_q2 = create_segment(score=0.1, segment_id=unique_id2)

        ranked_lists = {
            "query1": [seg_unique_q1, seg_shared_q1],
            "query2": [seg_unique_q2, seg_shared_q2],
        }

        fused = fuse_ranked_lists(ranked_lists)

        # Should have 3 unique segments, not 4
        assert len(fused) == 3
        segment_ids = {f.segment.segment_id for f in fused}
        assert segment_ids == {shared_id, unique_id1, unique_id2}


class TestSegmentSurfacingViaFusion:
    """Test that segments ranked >15 in individual queries can surface via fusion."""

    def test_low_ranked_segment_surfaces_via_multiple_queries(self):
        """A segment at rank 32 in one query can surface if it appears in multiple queries."""
        target_id = uuid4()

        # Create 31 segments that rank above the target in query 1
        q1_segments = [create_segment(score=i * 0.01) for i in range(31)]
        q1_segments.append(create_segment(score=0.58, segment_id=target_id, text="Target"))

        # In query 2, the target ranks #5
        q2_segments = [create_segment(score=i * 0.01) for i in range(4)]
        q2_segments.append(create_segment(score=0.05, segment_id=target_id, text="Target"))

        # In query 3, the target ranks #3
        q3_segments = [create_segment(score=i * 0.01) for i in range(2)]
        q3_segments.append(create_segment(score=0.03, segment_id=target_id, text="Target"))

        ranked_lists = {
            "query1": q1_segments,
            "query2": q2_segments,
            "query3": q3_segments,
        }

        fused = fuse_ranked_lists(ranked_lists, max_results=15)

        # The target should be in the top 15 due to fusion
        target_in_top_15 = any(f.segment.segment_id == target_id for f in fused)
        assert target_in_top_15, (
            "Target segment should surface in top 15 via fusion even though it was rank 32 in one query"
        )

        # Verify it has high RRF score from multiple appearances
        target_fused = next(f for f in fused if f.segment.segment_id == target_id)
        assert len(target_fused.source_queries) == 3


# =============================================================================
# Similarity Tests
# =============================================================================


class TestSimilarityFunctions:
    """Tests for similarity computation functions."""

    def test_cosine_similarity_identical_vectors(self):
        """Identical vectors should have similarity 1.0."""
        vec = [1.0, 2.0, 3.0]
        assert cosine_similarity(vec, vec) == pytest.approx(1.0)

    def test_cosine_similarity_orthogonal_vectors(self):
        """Orthogonal vectors should have similarity 0.0."""
        vec1 = [1.0, 0.0]
        vec2 = [0.0, 1.0]
        assert cosine_similarity(vec1, vec2) == pytest.approx(0.0)

    def test_cosine_similarity_opposite_vectors(self):
        """Opposite vectors should have similarity -1.0."""
        vec1 = [1.0, 0.0]
        vec2 = [-1.0, 0.0]
        assert cosine_similarity(vec1, vec2) == pytest.approx(-1.0)

    def test_cosine_similarity_empty_vectors(self):
        """Empty vectors should return 0.0."""
        assert cosine_similarity([], []) == 0.0

    def test_jaccard_similarity_identical_texts(self):
        """Identical texts should have similarity 1.0."""
        text = "the quick brown fox"
        assert jaccard_similarity(text, text) == pytest.approx(1.0)

    def test_jaccard_similarity_no_overlap(self):
        """Texts with no common words should have similarity 0.0."""
        text1 = "apple banana cherry"
        text2 = "dog elephant frog"
        assert jaccard_similarity(text1, text2) == pytest.approx(0.0)

    def test_jaccard_similarity_partial_overlap(self):
        """Texts with partial overlap should have correct similarity."""
        text1 = "the quick brown fox"  # 4 words
        text2 = "the lazy brown dog"  # 4 words, 2 shared (the, brown)
        # Intersection: 2, Union: 6
        assert jaccard_similarity(text1, text2) == pytest.approx(2 / 6)


# =============================================================================
# MMR Selection Tests
# =============================================================================


class TestMMRSelection:
    """Tests for MMR diversity selection."""

    @pytest.mark.asyncio
    async def test_top_k_selection_without_mmr(self, mock_llm_service):
        """top_k should just take first k items by RRF score."""
        candidates = [
            FusedSegment(
                segment=create_segment(text=f"Seg {i}"),
                rrf_score=1.0 / (i + 1),
                best_distance=i * 0.1,
            )
            for i in range(20)
        ]

        selected = select_top_k(candidates, final_limit=5)

        assert len(selected) == 5
        # Should be top 5 by RRF score (which is highest for first items)
        assert selected[0].rrf_score == pytest.approx(1.0)
        assert selected[4].rrf_score == pytest.approx(1.0 / 5)

    @pytest.mark.asyncio
    async def test_mmr_promotes_diverse_content(self, mock_llm_service):
        """MMR should promote diverse content over redundant content."""
        # Create candidates with two clusters: similar segments and one unique
        # The diverse content should beat redundant similar content when diversity is weighted

        candidates = [
            FusedSegment(
                segment=create_segment(
                    text="The PM discussed public assemblies restrictions", score=0.1
                ),
                rrf_score=1.0,
                best_distance=0.1,
            ),
            FusedSegment(
                segment=create_segment(
                    text="Public assemblies were restricted by PM today", score=0.12
                ),
                rrf_score=0.95,  # Very similar RRF to first
                best_distance=0.12,
            ),
            FusedSegment(
                segment=create_segment(
                    text="PM announced restrictions on public gatherings in NSW", score=0.15
                ),
                rrf_score=0.90,  # Also similar RRF
                best_distance=0.15,
            ),
            FusedSegment(
                segment=create_segment(
                    text="Neo-Nazis marching down streets dressed in black clothes", score=0.3
                ),
                rrf_score=0.85,  # Close enough RRF that diversity can boost it
                best_distance=0.3,
            ),
        ]

        query_embedding = [0.1] * 1536

        # With lambda=0.5, diversity has strong influence
        selected = await select_mmr(
            candidates,
            query_embedding,
            mock_llm_service,
            final_limit=3,
            lambda_param=0.5,  # 50% relevance, 50% diversity
            use_embeddings=False,  # Use Jaccard
        )

        assert len(selected) == 3

        # The neo-Nazi content should be included because:
        # - First selection: highest RRF (PM discussed)
        # - Second selection: neo-Nazi is diverse from first, gets diversity boost
        # - Even if #2 or #3 win second, neo-Nazi should beat similar content for #3
        texts = [s.segment.text for s in selected]

        # At minimum, we should have diverse content - not all 3 being about PM restrictions
        unique_topics = sum([1 if "Neo-Nazi" in t or "marching" in t else 0 for t in texts])
        pm_topics = sum(
            [
                1
                if "PM" in t or "public assemblies" in t.lower() or "gatherings" in t.lower()
                else 0
                for t in texts
            ]
        )

        # With strong diversity weight, we shouldn't have all 3 being PM-related
        assert pm_topics < 3 or unique_topics >= 1, f"Expected diverse selection, got: {texts}"


# =============================================================================
# Integration Tests
# =============================================================================


class TestExpandedRagRetrieverIntegration:
    """Integration tests for the full retriever."""

    @pytest.mark.asyncio
    async def test_retriever_returns_correct_structure(self, mock_db_session, mock_llm_service):
        """Retriever should return properly structured result."""
        retriever = ExpandedRagRetriever(
            session=mock_db_session,
            llm_service=mock_llm_service,
            use_mmr=False,
            candidate_k=10,
        )

        # Mock query expansion
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = '["expanded query"]'
        mock_llm_service.client.chat.completions.create = AsyncMock(return_value=mock_response)

        # Mock search
        mock_search_result = SegmentSearchResponse(
            segments=[create_segment(score=0.3) for _ in range(5)],
            scope_echo=None,
        )

        retriever.search_service = MagicMock(spec=SearchService)
        retriever.search_service.search_segments = AsyncMock(return_value=mock_search_result)

        result = await retriever.retrieve("test query")

        assert isinstance(result, RetrievalResult)
        assert isinstance(result.telemetry, RetrievalTelemetry)
        assert result.telemetry.original_query == "test query"
        assert len(result.segments) <= 15

    @pytest.mark.asyncio
    async def test_retriever_handles_empty_results(self, mock_db_session, mock_llm_service):
        """Retriever should handle empty search results gracefully."""
        retriever = ExpandedRagRetriever(
            session=mock_db_session,
            llm_service=mock_llm_service,
        )

        # Mock query expansion
        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = '["expanded"]'
        mock_llm_service.client.chat.completions.create = AsyncMock(return_value=mock_response)

        # Mock empty search results
        mock_search_result = SegmentSearchResponse(segments=[], scope_echo=None)
        retriever.search_service = MagicMock(spec=SearchService)
        retriever.search_service.search_segments = AsyncMock(return_value=mock_search_result)

        result = await retriever.retrieve("test query with no matches")

        assert result.segments == []
        assert result.telemetry.union_size == 0

    @pytest.mark.asyncio
    async def test_retriever_respects_distance_threshold(self, mock_db_session, mock_llm_service):
        """Retriever should filter segments above max_distance threshold."""
        retriever = ExpandedRagRetriever(
            session=mock_db_session,
            llm_service=mock_llm_service,
            max_distance=0.5,  # Strict threshold
        )

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = "[]"
        mock_llm_service.client.chat.completions.create = AsyncMock(return_value=mock_response)

        # Return segments with various distances
        mock_search_result = SegmentSearchResponse(
            segments=[
                create_segment(score=0.3),  # Under threshold
                create_segment(score=0.4),  # Under threshold
                create_segment(score=0.6),  # Over threshold
                create_segment(score=0.8),  # Over threshold
            ],
            scope_echo=None,
        )
        retriever.search_service = MagicMock(spec=SearchService)
        retriever.search_service.search_segments = AsyncMock(return_value=mock_search_result)

        result = await retriever.retrieve("test query")

        # Only 2 segments should pass the 0.5 threshold
        assert len(result.segments) == 2
        assert all(seg.score <= 0.5 for seg in result.segments)

    @pytest.mark.asyncio
    async def test_telemetry_captures_all_metrics(self, mock_db_session, mock_llm_service):
        """Telemetry should capture all required metrics."""
        retriever = ExpandedRagRetriever(
            session=mock_db_session,
            llm_service=mock_llm_service,
            use_mmr=True,
            mmr_lambda=0.75,
        )

        mock_response = MagicMock()
        mock_response.choices = [MagicMock()]
        mock_response.choices[0].message.content = '["q1", "q2"]'
        mock_llm_service.client.chat.completions.create = AsyncMock(return_value=mock_response)

        mock_search_result = SegmentSearchResponse(
            segments=[create_segment(score=0.3) for _ in range(10)],
            scope_echo=None,
        )
        retriever.search_service = MagicMock(spec=SearchService)
        retriever.search_service.search_segments = AsyncMock(return_value=mock_search_result)

        result = await retriever.retrieve("test query")

        telemetry = result.telemetry
        assert telemetry.original_query == "test query"
        assert len(telemetry.query_variants) >= 1
        assert isinstance(telemetry.per_query_hits, dict)
        assert telemetry.union_size >= 0
        assert telemetry.fused_size >= 0
        assert telemetry.final_size >= 0
        assert isinstance(telemetry.final_segment_ids, list)
        assert telemetry.use_mmr is True
        assert telemetry.mmr_lambda == 0.75
