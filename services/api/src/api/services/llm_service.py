"""LLM service for Azure OpenAI chat completions.

Provides a wrapper around Azure OpenAI for copilot query processing.
Includes smart retry logic that respects API rate limit headers.
Instrumented with OpenTelemetry Gen AI semantic conventions for Aspire dashboard.
"""

import asyncio
import json
import random
import time
from typing import Any

from openai import (
    APIConnectionError,
    APITimeoutError,
    AsyncAzureOpenAI,
    AsyncOpenAI,
    RateLimitError,
)

# Import shared modules
try:
    from shared.config import get_settings
    from shared.logging.config import get_logger
    from shared.telemetry import add_span_event, get_tracer, record_exception_on_span
except ImportError:
    import logging
    import os

    def get_settings():
        class MockOpenAI:
            api_key = os.environ.get("OPENAI_API_KEY", "")
            model = "gpt-4o"
            max_tokens = 4096
            temperature = 0.3
            azure_endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "")
            azure_api_version = os.environ.get("AZURE_OPENAI_API_VERSION", "2024-02-01")

        class MockSettings:
            openai = MockOpenAI()

        return MockSettings()

    def get_logger(name):
        return logging.getLogger(name)

    def get_tracer(name):
        class NoOpSpan:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def set_attribute(self, k, v):
                pass

            def add_event(self, name, attributes=None):
                pass

            def record_exception(self, e, attributes=None):
                pass

        class NoOpTracer:
            def start_as_current_span(self, name, **kwargs):
                return NoOpSpan()

        return NoOpTracer()

    def add_span_event(span, name, attributes=None):
        pass

    def record_exception_on_span(span, e, attributes=None):
        pass


logger = get_logger(__name__)

# Get tracer for Gen AI operations
_tracer = get_tracer("llm_service")

# Retry configuration
MAX_RETRIES = 5
INITIAL_BACKOFF = 0.5  # seconds - fallback if no Retry-After header
MAX_BACKOFF = 60.0  # seconds - cap to prevent excessive waits
JITTER_FACTOR = 0.1  # ±10% jitter (small since we're using real Retry-After values)


class AdaptiveRateLimiter:
    """Adaptive rate limiter that learns from API responses.

    Uses rate limit headers from the API to intelligently throttle requests:
    - x-ratelimit-remaining-requests: requests left in window
    - x-ratelimit-remaining-tokens: tokens left in window
    - x-ratelimit-reset-requests: when request quota resets
    - retry-after: exact seconds to wait after 429
    """

    def __init__(self):
        self._lock = asyncio.Lock()
        self._next_request_time: float = 0  # Timestamp when next request is allowed
        self._requests_remaining: int | None = None
        self._reset_time: float | None = None

    async def wait_if_needed(self) -> None:
        """Wait if we need to respect rate limits."""
        async with self._lock:
            now = time.monotonic()
            if self._next_request_time > now:
                wait_time = self._next_request_time - now
                logger.debug(f"Rate limiter waiting {wait_time:.2f}s before next request")
                await asyncio.sleep(wait_time)

    def update_from_headers(self, headers: dict) -> None:
        """Update rate limit state from response headers."""
        # Parse remaining requests
        remaining = headers.get("x-ratelimit-remaining-requests")
        if remaining is not None:
            try:
                self._requests_remaining = int(remaining)
            except ValueError:
                pass

        # Parse reset time (could be seconds or timestamp)
        reset = headers.get("x-ratelimit-reset-requests")
        if reset is not None:
            try:
                # Azure uses relative seconds like "0.5s" or "1m0s"
                if reset.endswith("s") and "m" not in reset:
                    self._reset_time = time.monotonic() + float(reset[:-1])
                elif "m" in reset:
                    # Parse "1m30s" format
                    parts = reset.replace("m", " ").replace("s", "").split()
                    seconds = int(parts[0]) * 60 + (int(parts[1]) if len(parts) > 1 else 0)
                    self._reset_time = time.monotonic() + seconds
            except (ValueError, IndexError):
                pass

    def update_from_error(self, error: RateLimitError) -> float:
        """Extract wait time from rate limit error. Returns seconds to wait."""
        # OpenAI/Azure includes retry_after in the exception
        retry_after = getattr(error, "retry_after", None)
        if retry_after is not None:
            try:
                wait_time = float(retry_after)
                self._next_request_time = time.monotonic() + wait_time
                logger.info(f"Rate limit error with Retry-After: {wait_time:.1f}s")
                return wait_time
            except (ValueError, TypeError):
                pass

        # Try to parse from response headers in the error
        response = getattr(error, "response", None)
        if response is not None:
            headers = getattr(response, "headers", {})
            retry_header = headers.get("retry-after") or headers.get("Retry-After")
            if retry_header:
                try:
                    wait_time = float(retry_header)
                    self._next_request_time = time.monotonic() + wait_time
                    logger.info(f"Rate limit with Retry-After header: {wait_time:.1f}s")
                    return wait_time
                except ValueError:
                    pass

        # Try to extract from error message (Azure often puts it in the message)
        message = str(error)
        if "retry after" in message.lower():
            import re

            # Look for patterns like "retry after 10 seconds" or "retry after 10.5s"
            match = re.search(r"retry after (\d+\.?\d*)\s*(?:seconds?|s)?", message.lower())
            if match:
                try:
                    wait_time = float(match.group(1))
                    self._next_request_time = time.monotonic() + wait_time
                    logger.info(f"Rate limit extracted from message: {wait_time:.1f}s")
                    return wait_time
                except ValueError:
                    pass

        # Fallback - no retry info available
        return 0


# Global rate limiter instance
_rate_limiter: AdaptiveRateLimiter | None = None


def _get_rate_limiter() -> AdaptiveRateLimiter:
    """Get or create the global rate limiter."""
    global _rate_limiter
    if _rate_limiter is None:
        _rate_limiter = AdaptiveRateLimiter()
    return _rate_limiter


def _add_jitter(delay: float, jitter_factor: float = JITTER_FACTOR) -> float:
    """Add small jitter to delay to prevent thundering herd."""
    jitter = delay * jitter_factor * (2 * random.random() - 1)
    return max(0.1, delay + jitter)


async def retry_with_backoff(
    func,
    *args,
    max_retries: int = MAX_RETRIES,
    initial_backoff: float = INITIAL_BACKOFF,
    max_backoff: float = MAX_BACKOFF,
    **kwargs,
):
    """Execute an async function with smart retry on rate limits.

    Uses the Retry-After header from 429 responses to know exactly when
    to retry, rather than guessing with exponential backoff.

    Args:
        func: Async function to call
        max_retries: Maximum number of retry attempts
        initial_backoff: Fallback wait time if no Retry-After header
        max_backoff: Maximum wait time in seconds
        *args, **kwargs: Arguments to pass to the function

    Returns:
        Result of the function call

    Raises:
        The last exception if all retries fail
    """
    rate_limiter = _get_rate_limiter()
    fallback_backoff = initial_backoff
    last_exception = None

    for attempt in range(max_retries + 1):
        try:
            # Check if rate limiter says we should wait
            await rate_limiter.wait_if_needed()
            return await func(*args, **kwargs)
        except RateLimitError as e:
            last_exception = e
            if attempt < max_retries:
                # Get wait time from the error (Retry-After header)
                wait_time = rate_limiter.update_from_error(e)

                # Fallback to exponential backoff if no Retry-After
                if wait_time == 0:
                    wait_time = fallback_backoff
                    fallback_backoff = min(fallback_backoff * 2, max_backoff)

                # Cap and add small jitter
                wait_time = min(wait_time, max_backoff)
                wait_time = _add_jitter(wait_time)

                logger.warning(
                    f"Rate limited, waiting {wait_time:.1f}s (from {'API' if wait_time > 1 else 'fallback'})",
                    attempt=attempt + 1,
                    max_retries=max_retries,
                    wait_time=wait_time,
                )
                await asyncio.sleep(wait_time)
            else:
                logger.error(f"Rate limit exceeded after {max_retries} retries")
                raise
        except (APITimeoutError, APIConnectionError) as e:
            last_exception = e
            if attempt < max_retries:
                wait_time = _add_jitter(fallback_backoff)
                logger.warning(
                    f"API connection error, retrying in {wait_time:.1f}s",
                    attempt=attempt + 1,
                    error=str(e),
                )
                await asyncio.sleep(wait_time)
                fallback_backoff = min(fallback_backoff * 2, max_backoff)
            else:
                logger.error(f"API connection failed after {max_retries} retries")
                raise

    raise last_exception


COPILOT_SYSTEM_PROMPT = """You are a helpful assistant that answers questions about YouTube video content.

You have access to a library of transcribed and summarized YouTube videos. Your role is to:
1. ANSWER THE QUESTION FIRST - directly address what the user asked before anything else
2. SYNTHESIZE and TEACH - don't just quote transcripts, explain concepts in your own words
3. CLEARLY DISTINGUISH SOURCES - make it obvious what came from videos vs AI knowledge
4. Cite sources with video titles and timestamps as inline references like [Video Title, 2:30]
5. If you don't have enough information to answer directly, say so upfront

SOURCE ATTRIBUTION (CRITICAL):
When responding, ALWAYS make it clear where information comes from:
- **From your videos**: Use citations like [Video Title, 2:30] and phrases like "In your library..." or "The video shows..."
- **From AI knowledge**: Explicitly prefix with "Based on general knowledge..." or "Outside of your videos..."
- **NEVER mix sources in the same sentence** - keep video content and AI knowledge clearly separated

ANSWER STRUCTURE:
- First: Directly answer using video evidence (or acknowledge if videos don't cover this)
- Second: If offering AI knowledge, start a NEW paragraph with a clear transition like:
  "While your videos don't cover this, based on general knowledge..."
- This ensures users always know whether info came from their library or AI

ANSWER STYLE:
- Be DIRECT and CONCISE - answer in 2-4 sentences for simple questions
- SYNTHESIZE the information - explain the key points, don't dump raw transcript text
- Use simple, clear language - imagine teaching someone the concept
- Put inline citations at the end of relevant sentences, not quotes from transcripts
- Only include bullet points if the question asks for a list or multiple steps

BAD (mixes sources, unclear attribution):
"The clips show harvesting cabbage [Video, 8:19]. If you want, I can outline weed removal methods like mulching and herbicides."

GOOD (clear source separation):
"**From your videos:** The clips focus on meal prep—harvesting nappa cabbage and preparing vegetables [Video, 8:19; 9:23]—but don't cover weed removal.

**From AI knowledge:** Common weed removal methods include manual pulling, mulching, and targeted herbicide application."

IMPORTANT: You are READ-ONLY. You cannot:
- Trigger video ingestion or processing
- Modify any data
- Access external websites or the live internet
- Watch new videos

You can only search and analyze content that has already been ingested into the library."""


def _build_azure_openai_base_url(endpoint: str) -> str:
    """Build the correct base URL for Azure OpenAI or Azure AI Foundry endpoints.

    Azure AI Foundry endpoints (services.ai.azure.com):
        Input:  https://<resource>.services.ai.azure.com/api/projects/<project>
        Output: https://<resource>.services.ai.azure.com/openai

    Standard Azure OpenAI endpoints (openai.azure.com):
        Input:  https://<resource>.openai.azure.com
        Output: https://<resource>.openai.azure.com (unchanged)

    Args:
        endpoint: The Azure endpoint URL

    Returns:
        The correctly formatted base URL for OpenAI client.
    """
    endpoint = endpoint.rstrip("/")

    # Check if this is an Azure AI Foundry endpoint
    if "services.ai.azure.com" in endpoint:
        # Azure AI Foundry - strip off any /api/projects/<project> suffix
        if "/api/projects/" in endpoint:
            # Extract base: https://<resource>.services.ai.azure.com
            base = endpoint.split("/api/projects/")[0]
            return f"{base}/openai"
        else:
            return f"{endpoint}/openai"

    # Standard Azure OpenAI endpoint - return as-is
    return endpoint


class LLMService:
    """Service for LLM chat completions."""

    def __init__(self):
        """Initialize the LLM service."""
        self.settings = get_settings()
        self._client: AsyncOpenAI | AsyncAzureOpenAI | None = None

    @property
    def client(self) -> AsyncOpenAI | AsyncAzureOpenAI:
        """Get or create the OpenAI client."""
        if self._client is None:
            openai_settings = self.settings.openai

            # Check for Azure OpenAI configuration
            if openai_settings.is_azure_configured:
                base_url = openai_settings.azure_openai_base_url

                # Azure AI Foundry uses OpenAI-compatible API with /models endpoint
                if openai_settings.is_azure_ai_foundry:
                    logger.info(
                        "Using Azure AI Foundry for LLM",
                        original_endpoint=openai_settings.azure_endpoint,
                        base_url=base_url,
                        model=openai_settings.effective_model,
                    )
                    self._client = AsyncOpenAI(
                        api_key=openai_settings.effective_api_key,
                        base_url=base_url,
                        default_headers={"api-key": openai_settings.effective_api_key},
                    )
                else:
                    # Standard Azure OpenAI
                    logger.info(
                        "Using Azure OpenAI for LLM",
                        original_endpoint=openai_settings.azure_endpoint,
                        base_url=base_url,
                        deployment=openai_settings.effective_model,
                    )
                    self._client = AsyncAzureOpenAI(
                        api_key=openai_settings.effective_api_key,
                        azure_endpoint=base_url,
                        api_version=openai_settings.azure_api_version,
                    )
            else:
                # Use OpenAI directly
                self._client = AsyncOpenAI(
                    api_key=openai_settings.effective_api_key,
                )

        return self._client

    async def get_embedding(self, text: str) -> list[float]:
        """Get embedding vector for text.

        Args:
            text: The text to embed.

        Returns:
            Embedding vector (1536 dimensions for text-embedding-3-small).
        """
        model = self.settings.openai.effective_embedding_model

        with _tracer.start_as_current_span(
            "gen_ai.embeddings",
            attributes={
                "gen_ai.system": "openai",
                "gen_ai.request.model": model,
                "gen_ai.operation.name": "embeddings",
                "gen_ai.request.encoding_format": "float",
                "input.text_length": len(text),
            },
        ) as span:
            try:
                start_time = time.monotonic()

                # Use retry with backoff for rate limiting
                response = await retry_with_backoff(
                    self.client.embeddings.create,
                    model=model,
                    input=text,
                )

                elapsed_ms = (time.monotonic() - start_time) * 1000

                # Record Gen AI response attributes
                span.set_attribute("gen_ai.response.model", getattr(response, "model", model))
                span.set_attribute(
                    "gen_ai.usage.input_tokens", getattr(response.usage, "prompt_tokens", 0)
                )
                span.set_attribute(
                    "gen_ai.usage.total_tokens", getattr(response.usage, "total_tokens", 0)
                )
                span.set_attribute(
                    "gen_ai.response.embedding_dimensions", len(response.data[0].embedding)
                )
                span.set_attribute("duration_ms", elapsed_ms)

                return response.data[0].embedding
            except Exception as e:
                record_exception_on_span(span, e)
                logger.error(f"Failed to get embedding: {e}")
                raise

    async def expand_query(self, query: str) -> list[str]:
        """Expand a query with semantically related search terms.

        Uses LLM to generate alternative phrasings and related concepts
        that might appear in video transcripts. This helps surface content
        that uses different vocabulary than the user's query.

        Args:
            query: The user's original question.

        Returns:
            List of expanded query strings (including the original).
        """
        model = self.settings.openai.effective_model

        with _tracer.start_as_current_span(
            "gen_ai.chat",
            attributes={
                "gen_ai.system": "openai",
                "gen_ai.request.model": model,
                "gen_ai.operation.name": "query_expansion",
                "gen_ai.request.max_tokens": 150,
                "gen_ai.request.temperature": 0.3,
                "input.query_length": len(query),
            },
        ) as span:
            expansion_prompt = """Generate 2-3 alternative search queries that would help find relevant content for this question.

Think about:
- Synonyms and related terms (e.g., "public assemblies" → "marching", "protests", "demonstrations")
- Specific examples the user might be asking about (e.g., "extremist groups", "neo-Nazi")
- Different phrasings a speaker might use in a video

QUESTION: {query}

Respond with a JSON array of 2-3 short search phrases (not full questions).
Example: ["protests marching demonstrations", "neo-Nazi extremist groups", "public order restrictions"]

Return ONLY the JSON array, no other text."""

            try:
                start_time = time.monotonic()

                response = await retry_with_backoff(
                    self.client.chat.completions.create,
                    model=model,
                    messages=[{"role": "user", "content": expansion_prompt.format(query=query)}],
                    max_tokens=150,
                    temperature=0.3,
                )

                elapsed_ms = (time.monotonic() - start_time) * 1000

                # Record Gen AI response attributes
                usage = getattr(response, "usage", None)
                if usage:
                    span.set_attribute(
                        "gen_ai.usage.input_tokens", getattr(usage, "prompt_tokens", 0)
                    )
                    span.set_attribute(
                        "gen_ai.usage.output_tokens", getattr(usage, "completion_tokens", 0)
                    )
                    span.set_attribute(
                        "gen_ai.usage.total_tokens", getattr(usage, "total_tokens", 0)
                    )
                span.set_attribute("gen_ai.response.model", getattr(response, "model", model))
                span.set_attribute(
                    "gen_ai.response.finish_reason",
                    response.choices[0].finish_reason if response.choices else "unknown",
                )
                span.set_attribute("duration_ms", elapsed_ms)

                content = response.choices[0].message.content.strip()

                # Parse JSON array
                # Handle potential markdown code blocks
                if content.startswith("```"):
                    content = content.split("```")[1]
                    if content.startswith("json"):
                        content = content[4:]
                    content = content.strip()

                expanded_queries = json.loads(content)

                if isinstance(expanded_queries, list):
                    # Return original query plus expansions
                    result = [query] + [str(q) for q in expanded_queries[:3]]
                    span.set_attribute("output.expanded_query_count", len(result))
                    logger.debug(f"Query expanded: {query!r} → {result}")
                    return result

            except Exception as e:
                add_span_event(span, "query_expansion_failed", {"error": str(e)})
                logger.warning(f"Query expansion failed, using original: {e}")

            # Fallback to original query only
            span.set_attribute("output.expanded_query_count", 1)
            span.set_attribute("output.fallback", True)
            return [query]

    async def generate_answer(
        self,
        query: str,
        evidence: list[dict[str, Any]],
        video_context: list[dict[str, Any]] | None = None,
        conversation_history: list[dict[str, str]] | None = None,
        use_llm_knowledge: bool = True,
    ) -> dict[str, Any]:
        """Generate an answer based on the query and evidence.

        Args:
            query: The user's question.
            evidence: List of evidence segments with text, video info, timestamps.
            video_context: Optional list of relevant videos with summaries.
            conversation_history: Optional previous messages in the conversation.
            use_llm_knowledge: Whether to allow supplementing with AI's general knowledge.

        Returns:
            Dict with answer, citations, follow-ups, and uncertainty.
        """
        model = self.settings.openai.effective_model
        max_tokens = self.settings.openai.max_tokens
        temperature = self.settings.openai.temperature

        with _tracer.start_as_current_span(
            "gen_ai.chat",
            attributes={
                "gen_ai.system": "openai",
                "gen_ai.request.model": model,
                "gen_ai.operation.name": "generate_answer",
                "gen_ai.request.max_tokens": max_tokens,
                "gen_ai.request.temperature": temperature,
                "input.query_length": len(query),
                "input.evidence_count": len(evidence),
                "input.use_llm_knowledge": use_llm_knowledge,
                "input.has_conversation_history": conversation_history is not None,
            },
        ) as span:
            # Build context from evidence
            evidence_text = self._format_evidence(evidence)
            video_context_text = self._format_video_context(video_context) if video_context else ""

            # Build messages
            messages = [
                {"role": "system", "content": COPILOT_SYSTEM_PROMPT},
            ]

            # Add conversation history if provided
            if conversation_history:
                messages.extend(conversation_history[-6:])  # Keep last 3 exchanges

            # Build instructions based on whether AI knowledge is allowed
            if use_llm_knowledge:
                instructions = """INSTRUCTIONS:
- ANSWER THE QUESTION FIRST. Your first sentence should directly address what the user asked.
- If you can't directly answer from the evidence, say so upfront (e.g., "Your videos don't cover this topic.").
- CLEARLY SEPARATE SOURCES: Use "**From your videos:**" and "**From AI knowledge:**" headers
- SYNTHESIZE the information in your own words. Do NOT just quote transcripts.
- Add inline citations like [Video Title, 1:23] at the end of sentences using video content.
- If offering AI knowledge that's not from videos, put it in a separate paragraph with a clear header.

SOURCE ATTRIBUTION FORMAT:
When videos contain relevant info:
  "**From your videos:** [answer with citations]"

When videos don't cover the topic but you can help with AI knowledge:
  "**From your videos:** Your library doesn't cover [topic].

  **From AI knowledge:** [helpful information]"

When videos partially cover the topic:
  "**From your videos:** [relevant video content with citations]

  **From AI knowledge:** Additionally, [supplementary info not in videos]\""""
            else:
                instructions = """INSTRUCTIONS:
- ANSWER THE QUESTION using ONLY the evidence from the user's videos below. DO NOT add any information from your general AI knowledge.
- ANSWER THE QUESTION FIRST. Your first sentence should directly address what the user asked.
- If the evidence doesn't contain enough information to answer the question, say: "Your videos don't contain information about this topic."
- SYNTHESIZE the information in your own words. Do NOT just quote transcripts.
- Add inline citations like [Video Title, 1:23] at the end of sentences using video content.
- Use ONLY "**From your videos:**" header - do NOT include any "**From AI knowledge:**" section.
- If you cannot answer from the evidence, DO NOT supplement with general knowledge - just say the videos don't cover this topic.

SOURCE ATTRIBUTION FORMAT:
Always use only:
  "**From your videos:** [answer with citations from the evidence]"

If the evidence doesn't cover the topic:
  "**From your videos:** Your library doesn't contain information about [topic]. Try enabling 'AI Knowledge' for general information.\""""

            # Build the user message with evidence
            user_message = f"""Answer this question using the evidence below:

QUESTION: {query}

EVIDENCE:
{evidence_text}

{f"VIDEO CONTEXT:{chr(10)}{video_context_text}" if video_context_text else ""}

{instructions}

Respond in JSON:
{{
    "answer": "Use **From your videos:** and **From AI knowledge:** headers to clearly show where each piece of information comes from.",
    "confidence": "high|medium|low",
    "cited_videos": ["video_id1"],
    "follow_ups": ["3-4 specific follow-up questions the user might ask next"],
    "uncertainty": null,
    "video_explanations": {{
        "video_id1": {{
            "summary": "ONE sentence explaining how this specific video answers the user's question. Focus on the RELEVANCE to their query, not generic takeaways. Example: 'Demonstrates the exact push-up technique you asked about with clear form cues.'",
            "key_moments": [
                {{"timestamp": "2:34", "description": "Brief moment description (what happens at this timestamp)"}}
            ],
            "related_to": null
        }}
    }}
}}

FOLLOW-UP QUESTION RULES:
- Generate 3-4 specific questions the user might naturally ask next
- Write from user's perspective: "What did X say about Y?" not "Would you like to know about Y?"
- NO binary yes/no questions like "Do you want..." or "Would you like..."
- Each question should explore a different angle or topic from the evidence
- Make them specific and actionable, not vague

GOOD follow-ups:
- "What specific powers can police use during a terrorist incident?"
- "When did the government announce the gun buyback scheme?"
- "What are the new hate-speech thresholds being proposed?"

BAD follow-ups:
- "Would you like more details on this topic?"
- "Do you want to know about the gun buyback or hate speech measures?"
- "Should I explain more about Minns's announcement?\""""

            messages.append({"role": "user", "content": user_message})

            # Record message count for tracing
            span.set_attribute("gen_ai.request.message_count", len(messages))

            try:
                start_time = time.monotonic()

                # Build kwargs for chat completion
                completion_kwargs = {
                    "model": model,
                    "messages": messages,
                    "response_format": {"type": "json_object"},
                }

                # Use max_completion_tokens for newer models (gpt-4o, gpt-5, o1, DeepSeek, etc.)
                # Use max_tokens for older models (gpt-3.5, gpt-4)
                # Some models don't support temperature parameter
                model_lower = model.lower()
                if any(m in model_lower for m in ["gpt-5", "o1", "o3", "deepseek"]):
                    completion_kwargs["max_completion_tokens"] = max_tokens
                    # DeepSeek supports temperature, add it for those models
                    if "deepseek" in model_lower:
                        completion_kwargs["temperature"] = temperature
                    # gpt-5 and o-series don't support temperature parameter
                else:
                    completion_kwargs["max_tokens"] = max_tokens
                    completion_kwargs["temperature"] = temperature

                # Use retry with backoff for rate limiting
                response = await retry_with_backoff(
                    self.client.chat.completions.create, **completion_kwargs
                )

                elapsed_ms = (time.monotonic() - start_time) * 1000

                # Record Gen AI response attributes
                usage = getattr(response, "usage", None)
                if usage:
                    span.set_attribute(
                        "gen_ai.usage.input_tokens", getattr(usage, "prompt_tokens", 0)
                    )
                    span.set_attribute(
                        "gen_ai.usage.output_tokens", getattr(usage, "completion_tokens", 0)
                    )
                    span.set_attribute(
                        "gen_ai.usage.total_tokens", getattr(usage, "total_tokens", 0)
                    )
                span.set_attribute("gen_ai.response.model", getattr(response, "model", model))
                span.set_attribute(
                    "gen_ai.response.finish_reason",
                    response.choices[0].finish_reason if response.choices else "unknown",
                )
                span.set_attribute("duration_ms", elapsed_ms)

                content = response.choices[0].message.content
                result = json.loads(content)

                # Handle LLM returning literal "null" string instead of JSON null
                uncertainty_value = result.get("uncertainty")
                if uncertainty_value == "null" or uncertainty_value == "":
                    uncertainty_value = None

                # Record response quality metrics
                confidence = result.get("confidence", "low")
                span.set_attribute("output.confidence", confidence)
                span.set_attribute("output.cited_video_count", len(result.get("cited_videos", [])))
                span.set_attribute("output.follow_up_count", len(result.get("follow_ups", [])))
                span.set_attribute("output.has_uncertainty", uncertainty_value is not None)
                span.set_attribute("output.answer_length", len(result.get("answer", "")))

                return {
                    "answer": result.get("answer", "I couldn't generate an answer."),
                    "confidence": confidence,
                    "cited_videos": result.get("cited_videos", []),
                    "follow_ups": result.get("follow_ups", []),
                    "uncertainty": uncertainty_value,
                    "video_explanations": result.get("video_explanations", {}),
                }
            except json.JSONDecodeError as e:
                add_span_event(span, "json_parse_failed", {"error": str(e)})
                logger.warning(f"Failed to parse LLM response as JSON: {e}")
                # Return the raw content as answer
                return {
                    "answer": response.choices[0].message.content
                    if response
                    else "Failed to generate answer",
                    "confidence": "low",
                    "cited_videos": [],
                    "follow_ups": [],
                    "uncertainty": "Response format was unexpected",
                    "video_explanations": {},
                }
            except Exception as e:
                record_exception_on_span(span, e)
                logger.error(f"Failed to generate answer: {e}")
                raise

    async def generate_follow_ups(
        self,
        query: str,
        answer: str,
        available_topics: list[str] | None = None,
    ) -> list[str]:
        """Generate follow-up question suggestions.

        Args:
            query: The original query.
            answer: The answer that was provided.
            available_topics: Topics available in the current scope.

        Returns:
            List of suggested follow-up questions.
        """
        model = self.settings.openai.model

        with _tracer.start_as_current_span(
            "gen_ai.chat",
            attributes={
                "gen_ai.system": "openai",
                "gen_ai.request.model": model,
                "gen_ai.operation.name": "generate_follow_ups",
                "gen_ai.request.max_tokens": 256,
                "gen_ai.request.temperature": 0.7,
                "input.query_length": len(query),
                "input.answer_length": len(answer),
            },
        ) as span:
            topics_context = ""
            if available_topics:
                topics_context = (
                    f"\nAvailable topics in the library: {', '.join(available_topics[:20])}"
                )

            prompt = f"""Given this Q&A exchange, suggest 3 natural follow-up questions.

IMPORTANT: Write questions from the USER'S perspective (first person), as if they are asking the question themselves.
- GOOD: "How do I practice this technique?", "What equipment do I need?", "Can I do this at home?"
- BAD: "How to practice this technique?", "What equipment is needed?", "Can this be done at home?"
{topics_context}

Original Question: {query}
Answer: {answer}

Return a JSON array of 3 follow-up questions (first-person, user perspective):
["How do I...", "What should I...", "Can I..."]"""

            try:
                start_time = time.monotonic()

                # Use retry with backoff for rate limiting
                response = await retry_with_backoff(
                    self.client.chat.completions.create,
                    model=model,
                    messages=[
                        {
                            "role": "system",
                            "content": "You suggest helpful follow-up questions written from the user's perspective (first person, e.g. 'How do I...' not 'How to...').",
                        },
                        {"role": "user", "content": prompt},
                    ],
                    max_tokens=256,
                    temperature=0.7,
                    response_format={"type": "json_object"},
                )

                elapsed_ms = (time.monotonic() - start_time) * 1000

                # Record Gen AI response attributes
                usage = getattr(response, "usage", None)
                if usage:
                    span.set_attribute(
                        "gen_ai.usage.input_tokens", getattr(usage, "prompt_tokens", 0)
                    )
                    span.set_attribute(
                        "gen_ai.usage.output_tokens", getattr(usage, "completion_tokens", 0)
                    )
                    span.set_attribute(
                        "gen_ai.usage.total_tokens", getattr(usage, "total_tokens", 0)
                    )
                span.set_attribute("gen_ai.response.model", getattr(response, "model", model))
                span.set_attribute("duration_ms", elapsed_ms)

                content = response.choices[0].message.content
                # Parse JSON - might be wrapped in an object
                parsed = json.loads(content)

                if isinstance(parsed, list):
                    span.set_attribute("output.follow_up_count", len(parsed[:3]))
                    return parsed[:3]
                elif isinstance(parsed, dict):
                    # Look for an array in the response
                    for key, value in parsed.items():
                        if isinstance(value, list):
                            span.set_attribute("output.follow_up_count", len(value[:3]))
                            return value[:3]

                span.set_attribute("output.follow_up_count", 0)
                return []
            except Exception as e:
                add_span_event(span, "follow_up_generation_failed", {"error": str(e)})
                logger.warning(f"Failed to generate follow-ups: {e}")
                return []

    async def generate_answer_without_evidence(
        self,
        query: str,
        allow_general_knowledge: bool = True,
    ) -> dict[str, Any]:
        """Generate an answer using only LLM knowledge (no video library context).

        Used when the user has disabled video library search but still wants
        the AI to answer using its general trained knowledge.

        Args:
            query: The user's question.
            allow_general_knowledge: Whether to allow general knowledge in answers.

        Returns:
            Dict with answer and follow-ups.
        """
        if not allow_general_knowledge:
            return {
                "answer": "I cannot answer this question because AI knowledge is disabled. Please enable at least one knowledge source.",
                "follow_ups": ["Enable 'AI Knowledge' to get answers"],
            }

        model = self.settings.openai.effective_model
        max_tokens = self.settings.openai.max_tokens
        temperature = self.settings.openai.temperature

        with _tracer.start_as_current_span(
            "gen_ai.chat",
            attributes={
                "gen_ai.system": "openai",
                "gen_ai.request.model": model,
                "gen_ai.operation.name": "generate_answer_without_evidence",
                "gen_ai.request.max_tokens": max_tokens,
                "input.query_length": len(query),
                "input.allow_general_knowledge": allow_general_knowledge,
            },
        ) as span:
            system_prompt = """You are a helpful AI assistant. The user has chosen not to search their video library, so you should answer based on your general knowledge.

IMPORTANT:
- Answer the question directly using your training knowledge
- Be clear that this answer is from general AI knowledge, not from the user's video library
- Be concise and helpful
- If you're uncertain, say so

Respond in JSON:
{
    "answer": "Your helpful answer based on general knowledge",
    "follow_ups": ["Suggested follow-up question 1", "Suggested follow-up question 2"]
}"""

            try:
                start_time = time.monotonic()

                # Build completion kwargs based on model type
                model_lower = model.lower()
                completion_kwargs = {
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": query},
                    ],
                }

                # Use max_completion_tokens for newer models, max_tokens for older ones
                if any(m in model_lower for m in ["gpt-5", "o1", "o3", "deepseek"]):
                    completion_kwargs["max_completion_tokens"] = max_tokens
                    # DeepSeek supports temperature
                    if "deepseek" in model_lower:
                        completion_kwargs["temperature"] = temperature
                else:
                    completion_kwargs["max_tokens"] = max_tokens
                    completion_kwargs["temperature"] = temperature

                response = await retry_with_backoff(
                    self.client.chat.completions.create, **completion_kwargs
                )

                elapsed_ms = (time.monotonic() - start_time) * 1000

                # Record Gen AI response attributes
                usage = getattr(response, "usage", None)
                if usage:
                    span.set_attribute(
                        "gen_ai.usage.input_tokens", getattr(usage, "prompt_tokens", 0)
                    )
                    span.set_attribute(
                        "gen_ai.usage.output_tokens", getattr(usage, "completion_tokens", 0)
                    )
                    span.set_attribute(
                        "gen_ai.usage.total_tokens", getattr(usage, "total_tokens", 0)
                    )
                span.set_attribute("gen_ai.response.model", getattr(response, "model", model))
                span.set_attribute(
                    "gen_ai.response.finish_reason",
                    response.choices[0].finish_reason if response.choices else "unknown",
                )
                span.set_attribute("duration_ms", elapsed_ms)

                content = response.choices[0].message.content.strip()

                # Handle markdown code blocks
                if content.startswith("```"):
                    content = content.split("```")[1]
                    if content.startswith("json"):
                        content = content[4:]
                    content = content.strip()

                result = json.loads(content)
                span.set_attribute("output.answer_length", len(result.get("answer", "")))
                span.set_attribute("output.follow_up_count", len(result.get("follow_ups", [])))
                return result

            except Exception as e:
                record_exception_on_span(span, e)
                logger.error(f"Failed to generate answer without evidence: {e}")
                return {
                    "answer": "I encountered an error while processing your question. Please try again.",
                    "follow_ups": ["Try rephrasing your question"],
                }

    def _format_evidence(self, evidence: list[dict[str, Any]]) -> str:
        """Format evidence segments for the LLM prompt.

        Args:
            evidence: List of evidence dicts.

        Returns:
            Formatted evidence text.
        """
        if not evidence:
            return "No relevant evidence found in the library."

        formatted = []
        for i, ev in enumerate(evidence[:10], 1):  # Limit to 10 pieces of evidence
            video_title = ev.get("video_title", "Unknown Video")
            start_time = ev.get("start_time", 0)
            text = ev.get("text", ev.get("segment_text", ""))

            # Format timestamp
            minutes = int(start_time // 60)
            seconds = int(start_time % 60)
            timestamp = f"{minutes}:{seconds:02d}"

            formatted.append(f'[{i}] {video_title} at {timestamp}:\n"{text}"')

        return "\n\n".join(formatted)

    def _format_video_context(self, videos: list[dict[str, Any]]) -> str:
        """Format video context for the LLM prompt.

        Args:
            videos: List of video dicts with summaries.

        Returns:
            Formatted video context.
        """
        if not videos:
            return ""

        formatted = []
        for video in videos[:5]:  # Limit to 5 videos
            title = video.get("title", "Unknown")
            summary = video.get("summary", "No summary available")
            formatted.append(f"- {title}: {summary[:500]}")

        return "\n".join(formatted)

    async def generate_structured_output(
        self,
        system_prompt: str,
        user_prompt: str,
    ) -> dict[str, Any]:
        """Generate a structured JSON output from the LLM.

        Used for synthesis operations like learning paths and watch lists.

        Args:
            system_prompt: The system prompt with instructions.
            user_prompt: The user's request.

        Returns:
            Parsed JSON response from LLM.
        """
        model = self.settings.openai.effective_model
        max_tokens = self.settings.openai.max_tokens
        temperature = self.settings.openai.temperature

        with _tracer.start_as_current_span(
            "gen_ai.chat",
            attributes={
                "gen_ai.system": "openai",
                "gen_ai.request.model": model,
                "gen_ai.operation.name": "generate_structured_output",
                "gen_ai.request.max_tokens": max_tokens,
                "input.system_prompt_length": len(system_prompt),
                "input.user_prompt_length": len(user_prompt),
            },
        ) as span:
            try:
                start_time = time.monotonic()

                # Build completion kwargs based on model type
                model_lower = model.lower()
                completion_kwargs = {
                    "model": model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                }

                # Use max_completion_tokens for newer models, max_tokens for older ones
                if any(m in model_lower for m in ["gpt-5", "o1", "o3", "deepseek"]):
                    completion_kwargs["max_completion_tokens"] = max_tokens
                    # DeepSeek supports temperature
                    if "deepseek" in model_lower:
                        completion_kwargs["temperature"] = temperature
                else:
                    completion_kwargs["max_tokens"] = max_tokens
                    completion_kwargs["temperature"] = temperature

                response = await retry_with_backoff(
                    self.client.chat.completions.create, **completion_kwargs
                )

                elapsed_ms = (time.monotonic() - start_time) * 1000

                # Record Gen AI response attributes
                usage = getattr(response, "usage", None)
                if usage:
                    span.set_attribute(
                        "gen_ai.usage.input_tokens", getattr(usage, "prompt_tokens", 0)
                    )
                    span.set_attribute(
                        "gen_ai.usage.output_tokens", getattr(usage, "completion_tokens", 0)
                    )
                    span.set_attribute(
                        "gen_ai.usage.total_tokens", getattr(usage, "total_tokens", 0)
                    )
                span.set_attribute("gen_ai.response.model", getattr(response, "model", model))
                span.set_attribute(
                    "gen_ai.response.finish_reason",
                    response.choices[0].finish_reason if response.choices else "unknown",
                )
                span.set_attribute("duration_ms", elapsed_ms)

                content = response.choices[0].message.content.strip()

                # Handle markdown code blocks
                if content.startswith("```"):
                    content = content.split("```")[1]
                    if content.startswith("json"):
                        content = content[4:]
                    content = content.strip()

                result = json.loads(content)
                span.set_attribute("output.item_count", len(result.get("items", [])))
                return result

            except json.JSONDecodeError as e:
                add_span_event(span, "json_parse_failed", {"error": str(e)})
                logger.warning(f"Failed to parse LLM structured output as JSON: {e}")
                # Return a minimal valid structure
                return {
                    "title": "Generated Output",
                    "description": "Unable to parse LLM response",
                    "items": [],
                    "gaps": [],
                }
            except Exception as e:
                record_exception_on_span(span, e)
                logger.error(f"Failed to generate structured output: {e}")
                raise


# Singleton instance
_llm_service: LLMService | None = None


def get_llm_service() -> LLMService:
    """Get or create the LLM service singleton.

    Returns:
        The LLM service instance.
    """
    global _llm_service
    if _llm_service is None:
        _llm_service = LLMService()
    return _llm_service
