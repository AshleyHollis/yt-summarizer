"""Expanded RAG Retriever with Query Expansion, RRF Fusion, and MMR Diversity.

This module implements a higher-recall retrieval strategy for RAG (Retrieval-Augmented
Generation) that addresses the "vocabulary mismatch" problem where relevant content
uses different terminology than the user's query.

Architecture:
    1. Query Expansion: LLM generates 3-5 alternative search queries
    2. Multi-Query Retrieval: Each query searches with limit=CANDIDATE_K
    3. Deduplication: Merge results by segment_id
    4. RRF Fusion: Reciprocal Rank Fusion combines ranked lists
    5. MMR Diversity (optional): Maximal Marginal Relevance reduces redundancy
    6. Final Selection: Top FINAL_LIMIT segments sent to LLM

Tunable Parameters:
    CANDIDATE_K (default=100):
        Number of candidates to fetch per query variant.
        Increase for larger collections or when recall is critical.
        Higher values = more API latency but better recall.
    
    RRF_K (default=60):
        Smoothing constant for Reciprocal Rank Fusion.
        Lower values favor top-ranked results more strongly.
        Standard values: 60 (default), 20 (more aggressive), 100 (more balanced).
    
    FUSED_MAX (default=200):
        Maximum candidates to keep after RRF fusion before diversity selection.
        Set higher if you have many query variants.
    
    FINAL_LIMIT (default=15):
        Number of segments to send to the LLM for answer generation.
        Keep low to control token costs while ensuring quality.
    
    MAX_DISTANCE_FOR_RELEVANCE (default=0.8):
        Maximum cosine distance to consider a segment "relevant".
        Range 0-2 for cosine distance (0=identical, 1=orthogonal, 2=opposite).
        0.8 is permissive; 0.6 is strict.
    
    MMR_LAMBDA (default=0.8):
        Balance between relevance (1.0) and diversity (0.0).
        0.8 = strongly prefer relevance, mild diversity boost.
        0.5 = equal balance.
    
    USE_MMR (default=True):
        Whether to apply MMR diversity selection.
        Set False for pure RRF ranking without diversity.

Usage:
    retriever = ExpandedRagRetriever(
        session=db_session,
        llm_service=llm_service,
        use_mmr=True,
    )
    
    result = await retriever.retrieve(
        query="What has the PM said about public assemblies?",
        scope=None,  # Optional QueryScope
    )
    
    # result.segments contains top 15 diverse, relevant segments
    # result.telemetry has debugging info

Example tuning for different scenarios:
    
    # High recall, larger collection:
    retriever = ExpandedRagRetriever(..., candidate_k=200, fused_max=400)
    
    # Fast, lower recall:
    retriever = ExpandedRagRetriever(..., candidate_k=50, use_mmr=False)
    
    # More diverse results:
    retriever = ExpandedRagRetriever(..., mmr_lambda=0.6)
"""

import json
import math
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

# Import shared modules
try:
    from shared.logging.config import get_logger
except ImportError:
    import logging
    
    def get_logger(name):
        return logging.getLogger(name)


from ..models.copilot import (
    QueryScope,
    ScoredSegment,
    SegmentSearchRequest,
)
from .llm_service import LLMService, get_llm_service, retry_with_backoff
from .search_service import SearchService

logger = get_logger(__name__)


# =============================================================================
# Configuration Constants
# =============================================================================

# Query expansion
MAX_QUERY_VARIANTS = 5  # Maximum number of query variants (including original)

# Multi-query retrieval
CANDIDATE_K = 100  # Candidates per query variant (fetch wide)

# Relevance threshold
MAX_DISTANCE_FOR_RELEVANCE = 0.8  # Cosine distance threshold

# RRF Fusion
RRF_K = 60  # Smoothing constant (standard value)
FUSED_MAX = 200  # Max candidates after fusion

# Final selection
FINAL_LIMIT = 15  # Segments to send to LLM

# MMR Diversity
MMR_LAMBDA = 0.8  # Relevance vs diversity balance (1.0 = pure relevance)


# =============================================================================
# Data Models
# =============================================================================


@dataclass
class FusedSegment:
    """A segment with RRF score and source tracking."""
    
    segment: ScoredSegment
    rrf_score: float
    best_distance: float  # Best (lowest) distance across all queries
    source_queries: list[str] = field(default_factory=list)  # Which queries found it
    ranks_per_query: dict[str, int] = field(default_factory=dict)  # Rank in each query
    embedding: list[float] | None = None  # Cached embedding for MMR


@dataclass
class RetrievalTelemetry:
    """Telemetry data for debugging and monitoring."""
    
    original_query: str
    query_variants: list[str]
    per_query_hits: dict[str, int]  # hits under threshold per query
    union_size: int  # unique segments before fusion
    fused_size: int  # size after RRF fusion
    final_size: int  # final selected count
    final_segment_ids: list[str]
    use_mmr: bool
    mmr_lambda: float | None = None


@dataclass 
class RetrievalResult:
    """Result from the expanded RAG retriever."""
    
    segments: list[ScoredSegment]
    telemetry: RetrievalTelemetry


# =============================================================================
# Query Expansion
# =============================================================================


QUERY_EXPANSION_PROMPT = """Generate 3-5 alternative search queries that would help find relevant content for this question.

RULES:
1. Preserve the original intent - do NOT introduce new topics
2. Include entity/synonym variants:
   - "Prime Minister" ↔ "PM" ↔ "Anthony Albanese" ↔ "Albanese"
   - "public assemblies" ↔ "protests" ↔ "rallies" ↔ "demonstrations" ↔ "marching"
3. Include specific examples that might appear in videos
4. Keep each query short (3-8 words) - they're for semantic search, not questions

QUESTION: {query}

Return ONLY a JSON array of 3-5 short search phrases.
Example: ["PM public assembly restrictions", "protests marching demonstrations banned", "neo-Nazi extremist groups street"]

JSON array:"""


async def expand_query_for_retrieval(
    llm_service: LLMService,
    query: str,
    max_variants: int = MAX_QUERY_VARIANTS,
) -> list[str]:
    """Expand a query into multiple search variants using LLM.
    
    Always returns the original query as the first element, even if expansion fails.
    
    Args:
        llm_service: The LLM service for generating expansions.
        query: The user's original question.
        max_variants: Maximum total variants including original.
        
    Returns:
        List of query strings, with original first.
    """
    # Always include original
    result = [query]
    
    try:
        response = await retry_with_backoff(
            llm_service.client.chat.completions.create,
            model=llm_service.settings.openai.effective_model,
            messages=[
                {"role": "user", "content": QUERY_EXPANSION_PROMPT.format(query=query)}
            ],
            max_completion_tokens=200,  # Use max_completion_tokens for Azure AI compatibility
            # Note: temperature removed for Azure AI Foundry compatibility (only supports default=1)
        )
        
        content = response.choices[0].message.content.strip()
        
        # Parse JSON array - handle markdown code blocks
        if content.startswith("```"):
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
            content = content.strip()
        
        # Find JSON array in response
        start_idx = content.find("[")
        end_idx = content.rfind("]") + 1
        if start_idx != -1 and end_idx > start_idx:
            content = content[start_idx:end_idx]
        
        expanded = json.loads(content)
        
        if isinstance(expanded, list):
            # Add expansions (skip any that duplicate original)
            for variant in expanded:
                variant_str = str(variant).strip()
                if variant_str and variant_str.lower() != query.lower():
                    result.append(variant_str)
                    if len(result) >= max_variants:
                        break
        
        logger.debug(
            "Query expansion succeeded",
            original=query[:50],
            variant_count=len(result),
        )
        
    except json.JSONDecodeError as e:
        logger.warning(f"Query expansion JSON parse failed: {e}")
    except Exception as e:
        logger.warning(f"Query expansion failed, using original: {e}")
    
    return result


def parse_query_expansion_response(content: str) -> list[str]:
    """Parse LLM response into list of query variants.
    
    Handles various response formats including markdown code blocks.
    
    Args:
        content: Raw LLM response content.
        
    Returns:
        List of query strings (may be empty if parsing fails).
    """
    content = content.strip()
    
    # Handle markdown code blocks
    if content.startswith("```"):
        parts = content.split("```")
        if len(parts) >= 2:
            content = parts[1]
            if content.startswith("json"):
                content = content[4:]
            content = content.strip()
    
    # Find JSON array bounds
    start_idx = content.find("[")
    end_idx = content.rfind("]") + 1
    
    if start_idx == -1 or end_idx <= start_idx:
        return []
    
    try:
        result = json.loads(content[start_idx:end_idx])
        if isinstance(result, list):
            return [str(x).strip() for x in result if x]
    except json.JSONDecodeError:
        pass
    
    return []


# =============================================================================
# RRF Fusion
# =============================================================================


def compute_rrf_score(rank: int, k: int = RRF_K) -> float:
    """Compute Reciprocal Rank Fusion score for a given rank.
    
    RRF(doc) = 1.0 / (k + rank)
    
    Args:
        rank: 1-based rank in the result list.
        k: Smoothing constant (default 60).
        
    Returns:
        RRF score contribution.
    """
    return 1.0 / (k + rank)


def fuse_ranked_lists(
    ranked_lists: dict[str, list[ScoredSegment]],
    k: int = RRF_K,
    max_results: int = FUSED_MAX,
) -> list[FusedSegment]:
    """Fuse multiple ranked lists using Reciprocal Rank Fusion.
    
    Each segment's final score is the sum of its RRF contributions across
    all queries where it appeared.
    
    Args:
        ranked_lists: Dict mapping query string to ranked segment list.
        k: RRF smoothing constant.
        max_results: Maximum results to return.
        
    Returns:
        List of FusedSegment sorted by descending RRF score.
    """
    # Aggregate scores by segment_id
    segment_scores: dict[UUID, FusedSegment] = {}
    
    for query, segments in ranked_lists.items():
        for rank, segment in enumerate(segments, start=1):
            seg_id = segment.segment_id
            rrf_contribution = compute_rrf_score(rank, k)
            
            if seg_id not in segment_scores:
                segment_scores[seg_id] = FusedSegment(
                    segment=segment,
                    rrf_score=0.0,
                    best_distance=segment.score,
                    source_queries=[],
                    ranks_per_query={},
                )
            
            fused = segment_scores[seg_id]
            fused.rrf_score += rrf_contribution
            fused.source_queries.append(query)
            fused.ranks_per_query[query] = rank
            
            # Track best (lowest) distance
            if segment.score < fused.best_distance:
                fused.best_distance = segment.score
                fused.segment = segment  # Use the closest match's metadata
    
    # Sort by descending RRF score
    fused_list = sorted(
        segment_scores.values(),
        key=lambda x: x.rrf_score,
        reverse=True,
    )
    
    return fused_list[:max_results]


# =============================================================================
# MMR Diversity Selection
# =============================================================================


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Compute cosine similarity between two vectors.
    
    Args:
        a: First embedding vector.
        b: Second embedding vector.
        
    Returns:
        Cosine similarity in range [-1, 1].
    """
    if len(a) != len(b) or len(a) == 0:
        return 0.0
    
    dot_product = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(x * x for x in b))
    
    if norm_a == 0 or norm_b == 0:
        return 0.0
    
    return dot_product / (norm_a * norm_b)


def jaccard_similarity(text_a: str, text_b: str) -> float:
    """Compute Jaccard similarity between two texts (fallback for MMR).
    
    Uses word-level tokenization.
    
    Args:
        text_a: First text.
        text_b: Second text.
        
    Returns:
        Jaccard similarity in range [0, 1].
    """
    tokens_a = set(text_a.lower().split())
    tokens_b = set(text_b.lower().split())
    
    if not tokens_a or not tokens_b:
        return 0.0
    
    intersection = len(tokens_a & tokens_b)
    union = len(tokens_a | tokens_b)
    
    return intersection / union if union > 0 else 0.0


async def select_mmr(
    candidates: list[FusedSegment],
    query_embedding: list[float],
    llm_service: LLMService,
    final_limit: int = FINAL_LIMIT,
    lambda_param: float = MMR_LAMBDA,
    use_embeddings: bool = True,
) -> list[FusedSegment]:
    """Select diverse segments using Maximal Marginal Relevance.
    
    MMR balances relevance to the query with diversity from already-selected items:
    MMR(doc) = lambda * relevance(doc, query) - (1-lambda) * max_sim(doc, selected)
    
    Args:
        candidates: Fused candidates sorted by RRF score.
        query_embedding: The query's embedding vector.
        llm_service: LLM service for computing embeddings (if needed).
        final_limit: Number of segments to select.
        lambda_param: Balance between relevance (1.0) and diversity (0.0).
        use_embeddings: If True, use cosine similarity on embeddings.
                        If False, use Jaccard on text (fallback).
        
    Returns:
        Selected diverse segments.
    """
    if len(candidates) <= final_limit:
        return candidates
    
    # If using embeddings, we need to fetch/compute them
    # For now, we'll use Jaccard as it's simpler and doesn't require extra API calls
    # The segment embeddings are stored in the DB but not loaded by default
    
    selected: list[FusedSegment] = []
    remaining = list(candidates)
    
    while len(selected) < final_limit and remaining:
        best_score = float("-inf")
        best_idx = 0
        
        for i, candidate in enumerate(remaining):
            # Relevance: use RRF score (already normalized across queries)
            # Higher RRF = more relevant
            relevance = candidate.rrf_score
            
            # Diversity: max similarity to any already-selected segment
            if selected:
                if use_embeddings and candidate.embedding and all(s.embedding for s in selected):
                    max_sim = max(
                        cosine_similarity(candidate.embedding, s.embedding)
                        for s in selected
                    )
                else:
                    # Fallback to Jaccard on text
                    max_sim = max(
                        jaccard_similarity(candidate.segment.text, s.segment.text)
                        for s in selected
                    )
            else:
                max_sim = 0.0
            
            # MMR score
            mmr_score = lambda_param * relevance - (1 - lambda_param) * max_sim
            
            if mmr_score > best_score:
                best_score = mmr_score
                best_idx = i
        
        selected.append(remaining.pop(best_idx))
    
    return selected


def select_top_k(
    candidates: list[FusedSegment],
    final_limit: int = FINAL_LIMIT,
) -> list[FusedSegment]:
    """Simple top-k selection without diversity (when MMR is disabled).
    
    Args:
        candidates: Fused candidates sorted by RRF score.
        final_limit: Number of segments to select.
        
    Returns:
        Top k segments by RRF score.
    """
    return candidates[:final_limit]


# =============================================================================
# Main Retriever Class
# =============================================================================


class ExpandedRagRetriever:
    """Higher-recall RAG retriever with query expansion and fusion.
    
    Implements "fetch wide → fuse → select diverse" strategy to improve
    recall without adding noise to the LLM context.
    
    Attributes:
        session: Database session for search operations.
        llm_service: LLM service for embeddings and query expansion.
        search_service: Underlying search service.
        use_mmr: Whether to apply MMR diversity selection.
        candidate_k: Candidates to fetch per query.
        rrf_k: RRF smoothing constant.
        fused_max: Max candidates after fusion.
        final_limit: Final segments to return.
        max_distance: Maximum distance for relevance.
        mmr_lambda: MMR relevance vs diversity balance.
    """
    
    def __init__(
        self,
        session: AsyncSession,
        llm_service: LLMService | None = None,
        use_mmr: bool = True,
        candidate_k: int = CANDIDATE_K,
        rrf_k: int = RRF_K,
        fused_max: int = FUSED_MAX,
        final_limit: int = FINAL_LIMIT,
        max_distance: float = MAX_DISTANCE_FOR_RELEVANCE,
        mmr_lambda: float = MMR_LAMBDA,
    ):
        """Initialize the expanded RAG retriever.
        
        Args:
            session: Database session.
            llm_service: LLM service (uses singleton if not provided).
            use_mmr: Whether to apply MMR diversity selection.
            candidate_k: Candidates to fetch per query variant.
            rrf_k: RRF smoothing constant.
            fused_max: Maximum candidates after RRF fusion.
            final_limit: Final number of segments to return.
            max_distance: Maximum distance threshold for relevance.
            mmr_lambda: MMR balance (1.0=pure relevance, 0.0=pure diversity).
        """
        self.session = session
        self.llm_service = llm_service or get_llm_service()
        self.search_service = SearchService(session)
        self.use_mmr = use_mmr
        self.candidate_k = candidate_k
        self.rrf_k = rrf_k
        self.fused_max = fused_max
        self.final_limit = final_limit
        self.max_distance = max_distance
        self.mmr_lambda = mmr_lambda
    
    async def retrieve(
        self,
        query: str,
        scope: QueryScope | None = None,
    ) -> RetrievalResult:
        """Retrieve segments using expanded query and fusion.
        
        Steps:
        1. Expand query into multiple variants
        2. Search with each variant, collect candidates
        3. Deduplicate by segment_id
        4. Apply RRF fusion to combine rankings
        5. Apply MMR (if enabled) for diversity
        6. Return top segments with telemetry
        
        Args:
            query: User's question.
            scope: Optional scope filters.
            
        Returns:
            RetrievalResult with segments and telemetry.
        """
        # Step 1: Query expansion
        query_variants = await expand_query_for_retrieval(
            self.llm_service,
            query,
            max_variants=MAX_QUERY_VARIANTS,
        )
        
        logger.info(
            "Query expansion complete",
            original=query[:50],
            variant_count=len(query_variants),
        )
        
        # Step 2: Multi-query retrieval
        ranked_lists: dict[str, list[ScoredSegment]] = {}
        per_query_hits: dict[str, int] = {}
        seen_segment_ids: set[UUID] = set()
        
        for variant in query_variants:
            try:
                # Get embedding for this variant
                embedding = await self.llm_service.get_embedding(variant)
                
                # Search with large candidate pool
                request = SegmentSearchRequest(
                    query_text=variant,
                    scope=scope,
                    limit=self.candidate_k,
                )
                
                result = await self.search_service.search_segments(request, embedding)
                
                # Filter by distance threshold and collect
                filtered = [
                    seg for seg in result.segments
                    if seg.score <= self.max_distance
                ]
                
                ranked_lists[variant] = filtered
                per_query_hits[variant] = len(filtered)
                
                # Track unique segments
                for seg in filtered:
                    seen_segment_ids.add(seg.segment_id)
                
                logger.debug(
                    "Query variant search complete",
                    variant=variant[:30],
                    raw_count=len(result.segments),
                    filtered_count=len(filtered),
                )
                
            except Exception as e:
                logger.warning(f"Search failed for variant '{variant[:30]}': {e}")
                ranked_lists[variant] = []
                per_query_hits[variant] = 0
        
        union_size = len(seen_segment_ids)
        
        # Step 3: RRF Fusion
        fused = fuse_ranked_lists(
            ranked_lists,
            k=self.rrf_k,
            max_results=self.fused_max,
        )
        
        logger.info(
            "RRF fusion complete",
            union_size=union_size,
            fused_size=len(fused),
        )
        
        # Step 4: MMR or top-k selection
        if self.use_mmr and len(fused) > self.final_limit:
            # Get query embedding for MMR
            query_embedding = await self.llm_service.get_embedding(query)
            
            selected = await select_mmr(
                fused,
                query_embedding,
                self.llm_service,
                final_limit=self.final_limit,
                lambda_param=self.mmr_lambda,
                use_embeddings=False,  # Use Jaccard for now (embeddings not loaded)
            )
        else:
            selected = select_top_k(fused, self.final_limit)
        
        # Step 5: Build result
        final_segments = [fs.segment for fs in selected]
        
        # Update scores to reflect RRF
        # We keep the original distance but could add rrf_score to metadata
        
        telemetry = RetrievalTelemetry(
            original_query=query,
            query_variants=query_variants,
            per_query_hits=per_query_hits,
            union_size=union_size,
            fused_size=len(fused),
            final_size=len(final_segments),
            final_segment_ids=[str(seg.segment_id) for seg in final_segments],
            use_mmr=self.use_mmr,
            mmr_lambda=self.mmr_lambda if self.use_mmr else None,
        )
        
        logger.info(
            "Retrieval complete",
            query=query[:50],
            variants=len(query_variants),
            union_size=union_size,
            final_size=len(final_segments),
            use_mmr=self.use_mmr,
        )
        
        return RetrievalResult(
            segments=final_segments,
            telemetry=telemetry,
        )
    
    async def retrieve_with_rrf_scores(
        self,
        query: str,
        scope: QueryScope | None = None,
    ) -> tuple[list[FusedSegment], RetrievalTelemetry]:
        """Retrieve with full FusedSegment data including RRF scores.
        
        Use this when you need access to RRF scores and source tracking.
        
        Args:
            query: User's question.
            scope: Optional scope filters.
            
        Returns:
            Tuple of (selected FusedSegments, telemetry).
        """
        # Query expansion
        query_variants = await expand_query_for_retrieval(
            self.llm_service,
            query,
            max_variants=MAX_QUERY_VARIANTS,
        )
        
        # Multi-query retrieval
        ranked_lists: dict[str, list[ScoredSegment]] = {}
        per_query_hits: dict[str, int] = {}
        seen_segment_ids: set[UUID] = set()
        
        for variant in query_variants:
            try:
                embedding = await self.llm_service.get_embedding(variant)
                request = SegmentSearchRequest(
                    query_text=variant,
                    scope=scope,
                    limit=self.candidate_k,
                )
                result = await self.search_service.search_segments(request, embedding)
                
                filtered = [
                    seg for seg in result.segments
                    if seg.score <= self.max_distance
                ]
                
                ranked_lists[variant] = filtered
                per_query_hits[variant] = len(filtered)
                
                for seg in filtered:
                    seen_segment_ids.add(seg.segment_id)
                    
            except Exception as e:
                logger.warning(f"Search failed for variant '{variant[:30]}': {e}")
                ranked_lists[variant] = []
                per_query_hits[variant] = 0
        
        union_size = len(seen_segment_ids)
        
        # RRF Fusion
        fused = fuse_ranked_lists(
            ranked_lists,
            k=self.rrf_k,
            max_results=self.fused_max,
        )
        
        # Selection
        if self.use_mmr and len(fused) > self.final_limit:
            query_embedding = await self.llm_service.get_embedding(query)
            selected = await select_mmr(
                fused,
                query_embedding,
                self.llm_service,
                final_limit=self.final_limit,
                lambda_param=self.mmr_lambda,
                use_embeddings=False,
            )
        else:
            selected = select_top_k(fused, self.final_limit)
        
        telemetry = RetrievalTelemetry(
            original_query=query,
            query_variants=query_variants,
            per_query_hits=per_query_hits,
            union_size=union_size,
            fused_size=len(fused),
            final_size=len(selected),
            final_segment_ids=[str(fs.segment.segment_id) for fs in selected],
            use_mmr=self.use_mmr,
            mmr_lambda=self.mmr_lambda if self.use_mmr else None,
        )
        
        return selected, telemetry
