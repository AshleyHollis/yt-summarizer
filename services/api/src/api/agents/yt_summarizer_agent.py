"""YT Summarizer Agent for CopilotKit integration.

Uses Microsoft Agent Framework with AG-UI protocol to provide
a self-hosted chat agent for the YT Summarizer application.

See: https://docs.copilotkit.ai/microsoft-agent-framework
See: https://learn.microsoft.com/en-us/agent-framework/
"""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Annotated, Any

import httpx

# Import Agent Framework components
try:
    from agent_framework import Agent, BaseChatClient, tool as agent_tool
    from agent_framework.openai import OpenAIChatClient

    AGENT_FRAMEWORK_AVAILABLE = True
except ImportError:
    Agent = None  # type: ignore
    agent_tool = None  # type: ignore
    BaseChatClient = None  # type: ignore
    OpenAIChatClient = None  # type: ignore
    AGENT_FRAMEWORK_AVAILABLE = False

# Import shared logging
try:
    from shared.logging.config import get_logger
except ImportError:
    import logging

    def get_logger(name: str) -> logging.Logger:
        return logging.getLogger(name)


logger = get_logger(__name__)


# =============================================================================
# Configuration
# =============================================================================

AGENT_NAME = "yt-summarizer"
AGENT_DESCRIPTION = "An AI assistant for searching and exploring your YouTube video library"

# System prompt for the agent
SYSTEM_INSTRUCTIONS = """<role>
You are an AI assistant for YT Summarizer, a YouTube video knowledge base application.
Your purpose is to help users search, discover, and learn from their video library.
</role>

<instructions>
# Tool Usage Rules

## Primary Tool (Use First)
- **query_library**: The PRIMARY tool for answering user questions
  - Returns: Rich answer with video cards, evidence citations, and follow-up suggestions
  - When: Use for ALL user questions unless a specific secondary tool is explicitly needed
  - Important: Frontend renders the complete response - do NOT add text after calling this tool

## Synthesis Tools (Structured Outputs)
- **synthesize_learning_path**: Creates beginner-to-advanced ordered content
  - When: "Create a learning path", "What order should I watch", "Progressive tutorial for", "Beginner to advanced"
- **synthesize_watch_list**: Creates a prioritized recommendation list
  - When: "What should I watch", "Recommend videos", "Best videos on", "Top videos for"

## Secondary Tools (Specific Use Cases Only)
- **search_videos**: Simple video search by title (not content)
- **search_segments**: Find specific quotes/timestamps
- **get_video_summary**: Get summary of a specific video (when user explicitly requests it)
- **get_library_coverage**: Library statistics ("how many videos", "what's in my library")
- **get_topics_for_channel**: Topic/category information

# Response Protocol
1. Call ONE tool per response (never multiple tools for the same question)
2. Do NOT add explanatory text after calling a tool
3. Let the tool result speak for itself - the UI handles rendering
4. Be proactive - search first, ask for clarification only if results are unclear

# Context Awareness

## Search Scope
The context may include search scope settings:
- `videoIds` present: ONLY search those specific videos (pass video_id to query_library)
- `channels` present: ONLY search videos from those channels (pass channel_id to query_library)
- Empty scope ({}): Search the entire library (no filters)

## AI Knowledge Settings (CRITICAL)
When context includes "aiSettings", ALWAYS pass these to query_library:
- `useVideoContext`: Controls video library search
  - false → set use_video_context=false
- `useLLMKnowledge`: Controls your general knowledge
  - false → set use_llm_knowledge=false
- `useWebSearch`: Controls web search
  - true → set use_web_search=true

<example>
User settings: {"useVideoContext": false, "useLLMKnowledge": true, "useWebSearch": false}
Your call: query_library(query="...", use_video_context=false, use_llm_knowledge=true, use_web_search=false)
</example>

This gives users full control over knowledge sources (library, AI knowledge, or web).
</instructions>

<tool_selection_guide>
| User Query | Tool to Use | Rationale |
|------------|-------------|-----------|
| "What videos do I have?" | query_library | Returns contextual answer with video cards |
| "Tell me about X" | query_library | Primary tool for content questions |
| "How many videos?" | get_library_coverage | Specific stats request |
| "Summarize video Y" | get_video_summary | Explicit summary request |
| "Create a learning path for X" | synthesize_learning_path | Ordered progression |
| "What order should I watch these?" | synthesize_learning_path | Ordered progression |
| "Recommend videos about X" | synthesize_watch_list | Prioritized recommendations |
| "Best videos for learning X" | synthesize_watch_list | Prioritized recommendations |
| Any other question | query_library | Default primary tool |
</tool_selection_guide>
"""

# Default configuration values
DEFAULT_TIMEOUT = 30.0


# =============================================================================
# HTTP Client Management
# =============================================================================


def get_api_base_url() -> str:
    """Get the API base URL for internal tool calls."""
    return os.getenv("API_BASE_URL", "http://localhost:8000")


@asynccontextmanager
async def get_http_client() -> AsyncGenerator[httpx.AsyncClient, None]:
    """Get an async HTTP client for API calls.

    Uses a context manager to ensure proper cleanup.
    """
    async with httpx.AsyncClient(
        base_url=get_api_base_url(),
        timeout=DEFAULT_TIMEOUT,
        headers={"Content-Type": "application/json"},
    ) as client:
        yield client


async def safe_api_call(
    method: str,
    path: str,
    *,
    json: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Make a safe API call with error handling.

    Args:
        method: HTTP method (GET, POST, etc.)
        path: API endpoint path
        json: Optional JSON body for POST requests
        params: Optional query parameters

    Returns:
        API response as dict, or error dict on failure
    """
    try:
        async with get_http_client() as client:
            response = await client.request(
                method=method,
                url=path,
                json=json,
                params=params,
            )
            response.raise_for_status()
            return response.json()
    except httpx.HTTPStatusError as e:
        logger.error(f"API call failed: {method} {path} - Status {e.response.status_code}")
        return {"error": f"API returned status {e.response.status_code}"}
    except httpx.TimeoutException:
        logger.error(f"API call timed out: {method} {path}")
        return {"error": "Request timed out"}
    except Exception as e:
        logger.error(f"API call failed: {method} {path} - {e}")
        return {"error": str(e)}


# =============================================================================
# Agent Tools
# =============================================================================

if agent_tool is not None:
    # Import the context accessor for AI settings
    from .agui_endpoint import get_current_ai_settings

    @agent_tool
    async def query_library(
        query: Annotated[str, "The question to ask about the video library"],
        video_id: Annotated[str | None, "Optional video ID to focus the search on"] = None,
        channel_id: Annotated[str | None, "Optional channel ID to filter by"] = None,
        use_video_context: Annotated[
            bool, "Whether to search the video library for context (default: true)"
        ] = True,
        use_llm_knowledge: Annotated[
            bool, "Whether to include AI's general knowledge in the answer (default: true)"
        ] = True,
        use_web_search: Annotated[
            bool, "Whether to search the web for current information (default: false)"
        ] = False,
    ) -> dict[str, Any]:
        """Ask a question about the video library and get a rich answer with citations.

        This is the PRIMARY tool for answering user questions about video content.

        Knowledge source control:
        - use_video_context: Search transcripts & summaries from the library
        - use_llm_knowledge: Allow AI to use its general trained knowledge
        - use_web_search: Search the web for current information (not yet implemented)

        Returns:
        - answer: A conversational answer to the question
        - videoCards: Relevant videos with explanations
        - evidence: Specific transcript segments that support the answer
        - followups: Suggested follow-up questions

        The frontend will render this as a rich UI with video cards and citations.
        Do NOT add additional text after calling this tool.
        """
        # Get AI settings from request context (set by agui_endpoint from CopilotKit context)
        # This overrides any LLM-provided parameter values with the actual user preferences
        context_settings = get_current_ai_settings()
        actual_use_video_context = context_settings.get("useVideoContext", use_video_context)
        actual_use_llm_knowledge = context_settings.get("useLLMKnowledge", use_llm_knowledge)
        actual_use_web_search = context_settings.get("useWebSearch", use_web_search)

        logger.info(
            f"query_library using AI settings - video_context={actual_use_video_context}, "
            f"llm_knowledge={actual_use_llm_knowledge}, web_search={actual_use_web_search} "
            f"(context: {context_settings})"
        )

        body: dict[str, Any] = {
            "query": query,
            "scope": {},
            "aiSettings": {
                "useVideoContext": actual_use_video_context,
                "useLLMKnowledge": actual_use_llm_knowledge,
                "useWebSearch": actual_use_web_search,
            },
        }
        if video_id:
            body["scope"]["video_ids"] = [video_id]
        if channel_id:
            body["scope"]["channel_id"] = channel_id

        result = await safe_api_call("POST", "/api/v1/copilot/query", json=body)
        if "error" not in result:
            video_count = len(result.get("videoCards", []))
            evidence_count = len(result.get("evidence", []))
            logger.info(
                f"query_library: {video_count} videos, {evidence_count} evidence for '{query}'"
            )
        return result

    @agent_tool
    async def search_videos(
        query: Annotated[str, "The search query to find videos"],
        channel_filter: Annotated[str | None, "Optional channel name to filter by"] = None,
        limit: Annotated[int, "Maximum number of results to return (1-20)"] = 5,
    ) -> dict[str, Any]:
        """Search for videos in the library by title, description, or content.

        Use this to find videos that match a topic or keyword.
        Returns a list of videos with their metadata and relevance scores.
        """
        body: dict[str, Any] = {
            "query_text": query,
            "limit": min(max(limit, 1), 20),  # Clamp to valid range
        }
        if channel_filter:
            body["channel_filter"] = channel_filter

        result = await safe_api_call("POST", "/api/v1/copilot/search/videos", json=body)
        if "error" not in result:
            logger.info(
                f"search_videos found {len(result.get('videos', []))} results for '{query}'"
            )
        return result

    @agent_tool
    async def search_segments(
        query: Annotated[str, "The search query to find transcript segments"],
        video_ids: Annotated[
            list[str] | None, "Optional list of video IDs to search within"
        ] = None,
        limit: Annotated[int, "Maximum number of segments to return (1-20)"] = 10,
    ) -> dict[str, Any]:
        """Search for specific transcript segments across videos.

        Use this to find exact quotes or specific moments in videos.
        Returns segments with timestamps and video context.
        """
        body: dict[str, Any] = {
            "query_text": query,
            "limit": min(max(limit, 1), 20),
        }
        if video_ids:
            body["scope"] = {"video_ids": video_ids}

        result = await safe_api_call("POST", "/api/v1/copilot/search/segments", json=body)
        if "error" not in result:
            logger.info(
                f"search_segments found {len(result.get('segments', []))} results for '{query}'"
            )
        return result

    @agent_tool
    async def get_video_summary(
        video_id: Annotated[str, "The UUID of the video to get the summary for"],
    ) -> dict[str, Any]:
        """Get the summary and key points for a specific video.

        Use this when you need detailed information about a particular video,
        including its summary, key points, and metadata.
        """
        result = await safe_api_call("GET", f"/api/v1/videos/{video_id}/summary")
        if "error" not in result:
            logger.info(f"get_video_summary retrieved summary for video {video_id}")
        return result

    @agent_tool
    async def get_library_coverage(
        channel_id: Annotated[str | None, "Optional channel ID to get coverage for"] = None,
    ) -> dict[str, Any]:
        """Get statistics about the video library coverage.

        Returns counts of videos, channels, segments, and topics in the library.
        Use this to understand what content is available before searching.
        """
        body: dict[str, Any] = {"scope": {}}
        if channel_id:
            body["scope"]["channel_id"] = channel_id
        result = await safe_api_call("POST", "/api/v1/copilot/coverage", json=body)
        if "error" not in result:
            logger.info(f"get_library_coverage: {result.get('videoCount', 0)} videos")
        return result

    @agent_tool
    async def get_topics_for_channel(
        channel_id: Annotated[str | None, "Optional UUID of the channel to get topics for"] = None,
    ) -> dict[str, Any]:
        """Get the topics covered by the library or a specific channel.

        Use this to understand what subjects are covered,
        helping users discover relevant content.
        """
        body: dict[str, Any] = {"scope": {}}
        if channel_id:
            body["scope"]["channel_id"] = channel_id
        result = await safe_api_call("POST", "/api/v1/copilot/topics", json=body)
        if "error" not in result:
            logger.info(f"get_topics_for_channel: {len(result.get('topics', []))} topics")
        return result

    @agent_tool
    async def synthesize_learning_path(
        query: Annotated[
            str,
            "Description of the learning path to create (e.g., 'beginner to advanced push-ups')",
        ],
        max_items: Annotated[int, "Maximum number of videos to include (1-20)"] = 10,
        channel_id: Annotated[str | None, "Optional channel ID to restrict to"] = None,
    ) -> dict[str, Any]:
        """Create a learning path from videos in the library.

        Synthesizes an ordered sequence of videos for progressive learning.
        The learning path orders videos from beginner to advanced based on content analysis.

        Returns:
        - learningPath: Ordered list of videos with rationale, prerequisites, and evidence
        - insufficientContent: True if not enough videos available
        - insufficientMessage: Explanation if content is insufficient

        Use this when users ask for:
        - "Create a learning path for..."
        - "What order should I watch..."
        - "Progressive tutorial for..."
        - "Beginner to advanced..."
        """
        body: dict[str, Any] = {
            "synthesisType": "learning_path",
            "query": query,
            "maxItems": min(max(max_items, 1), 20),
        }
        if channel_id:
            body["scope"] = {"channels": [channel_id]}

        result = await safe_api_call("POST", "/api/v1/copilot/synthesize", json=body)
        if "error" not in result:
            if result.get("insufficientContent"):
                logger.info(f"synthesize_learning_path: insufficient content for '{query}'")
            else:
                item_count = len(result.get("learningPath", {}).get("items", []))
                logger.info(f"synthesize_learning_path: {item_count} items for '{query}'")
        return result

    @agent_tool
    async def synthesize_watch_list(
        query: Annotated[
            str, "Description of what videos to recommend (e.g., 'fitness for beginners')"
        ],
        max_items: Annotated[int, "Maximum number of videos to include (1-20)"] = 10,
        channel_id: Annotated[str | None, "Optional channel ID to restrict to"] = None,
    ) -> dict[str, Any]:
        """Create a prioritized watch list from videos in the library.

        Synthesizes a prioritized collection of recommended videos based on user interests.
        Videos are assigned high/medium/low priority with reasons for inclusion.

        Returns:
        - watchList: Prioritized list of videos with reasons, tags, and priority levels
        - insufficientContent: True if no videos available
        - insufficientMessage: Explanation if content is insufficient

        Use this when users ask for:
        - "What should I watch about..."
        - "Recommend videos for..."
        - "Best videos on..."
        - "Top videos for..."
        """
        body: dict[str, Any] = {
            "synthesisType": "watch_list",
            "query": query,
            "maxItems": min(max(max_items, 1), 20),
        }
        if channel_id:
            body["scope"] = {"channels": [channel_id]}

        result = await safe_api_call("POST", "/api/v1/copilot/synthesize", json=body)
        if "error" not in result:
            if result.get("insufficientContent"):
                logger.info(f"synthesize_watch_list: insufficient content for '{query}'")
            else:
                item_count = len(result.get("watchList", {}).get("items", []))
                logger.info(f"synthesize_watch_list: {item_count} items for '{query}'")
        return result


# =============================================================================
# OpenAI Client Factory
# =============================================================================


def create_openai_chat_client() -> "BaseChatClient | None":
    """Create an OpenAI-compatible chat client.

    Supports Azure AI Foundry, Azure OpenAI, and standard OpenAI based on environment variables.

    Environment Variables:
        Azure AI Foundry / Azure OpenAI:
            - AZURE_OPENAI_ENDPOINT: The Azure endpoint URL
              - Foundry format: https://<resource>.services.ai.azure.com/api/projects/<project>
              - OpenAI format: https://<resource>.openai.azure.com
            - AZURE_OPENAI_API_KEY: The API key
            - AZURE_OPENAI_DEPLOYMENT: The deployment/model name (default: gpt-4o)

        Standard OpenAI:
            - OPENAI_API_KEY: The OpenAI API key
            - OPENAI_MODEL: The model to use (default: gpt-4o)

    Returns:
        Configured chat client or None if not configured.
    """
    if OpenAIChatClient is None:
        logger.warning("agent_framework not available - chat client cannot be created")
        return None

    # Check for Azure OpenAI / Azure AI Foundry configuration
    azure_endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
    azure_api_key = os.getenv("AZURE_OPENAI_API_KEY")
    azure_deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")

    if azure_endpoint and azure_api_key:
        # Detect endpoint type and construct appropriate base_url
        base_url = _build_azure_openai_base_url(azure_endpoint, azure_deployment)

        logger.info(f"Using Azure OpenAI - deployment: {azure_deployment}, base_url: {base_url}")

        return OpenAIChatClient(
            model_id=azure_deployment,
            api_key=azure_api_key,
            base_url=base_url,
            default_headers={"api-version": "2024-12-01-preview"},
        )

    # Fall back to standard OpenAI
    openai_api_key = os.getenv("OPENAI_API_KEY")
    if openai_api_key:
        model = os.getenv("OPENAI_MODEL", "gpt-4o")
        logger.info(f"Using OpenAI - model: {model}")
        return OpenAIChatClient(
            model_id=model,
            api_key=openai_api_key,
        )

    logger.warning(
        "No LLM configuration found. Set one of:\n"
        "  - AZURE_OPENAI_ENDPOINT + AZURE_OPENAI_API_KEY\n"
        "  - OPENAI_API_KEY"
    )
    return None


def _build_azure_openai_base_url(endpoint: str, deployment: str) -> str:
    """Build the correct base URL for Azure OpenAI or Azure AI Foundry endpoints.

    Azure AI Foundry endpoints (services.ai.azure.com):
        Input:  https://<resource>.services.ai.azure.com/api/projects/<project>
        Output: https://<resource>.services.ai.azure.com/models

    Standard Azure OpenAI endpoints (openai.azure.com):
        Input:  https://<resource>.openai.azure.com
        Output: https://<resource>.openai.azure.com/openai/deployments/<deployment>

    Args:
        endpoint: The Azure endpoint URL
        deployment: The deployment/model name

    Returns:
        The correctly formatted base URL for OpenAI client.
    """
    endpoint = endpoint.rstrip("/")

    # Check if this is an Azure AI Foundry endpoint
    if "services.ai.azure.com" in endpoint:
        # Azure AI Foundry uses the /models endpoint for OpenAI-compatible inference
        # Strip off any /api/projects/<project> suffix and use /models
        if "/api/projects/" in endpoint:
            # Extract base: https://<resource>.services.ai.azure.com
            base = endpoint.split("/api/projects/")[0]
            return f"{base}/models"
        else:
            return f"{endpoint}/models"

    # Standard Azure OpenAI endpoint
    # Format: https://<resource>.openai.azure.com/openai/deployments/<deployment>
    return f"{endpoint}/openai/deployments/{deployment}"


# =============================================================================
# Agent Factory
# =============================================================================


def get_agent_tools() -> list:
    """Get the list of available agent tools.

    Returns an empty list if agent_framework is not available.
    """
    if not AGENT_FRAMEWORK_AVAILABLE:
        return []

    return [
        query_library,  # PRIMARY tool for user questions
        search_videos,
        search_segments,
        get_video_summary,
        get_library_coverage,
        get_topics_for_channel,
        synthesize_learning_path,  # US6: Structured output tools
        synthesize_watch_list,  # US6: Structured output tools
    ]


def create_yt_summarizer_agent() -> "Agent | None":
    """Create the YT Summarizer agent with tools.

    Creates an Agent configured with:
    - System instructions for the YT Summarizer use case
    - Tools for searching videos, segments, and getting summaries
    - Appropriate temperature settings

    Returns:
        Configured Agent or None if dependencies not available.
    """
    if not AGENT_FRAMEWORK_AVAILABLE:
        logger.warning("agent_framework not installed - agent cannot be created")
        return None

    chat_client = create_openai_chat_client()
    if chat_client is None:
        return None

    tools = get_agent_tools()

    # Create the agent using the new Agent API (b260212+)
    # Note: Reasoning models (o1, o3, gpt-5-mini, etc.) only support:
    # - temperature=1 (the only allowed value)
    # We explicitly set temperature=1 for compatibility with all models.
    agent = Agent(
        chat_client=chat_client,
        name=AGENT_NAME,
        description=AGENT_DESCRIPTION,
        instructions=SYSTEM_INSTRUCTIONS,
        tools=tools,
        temperature=1,  # Only value supported by reasoning models
    )

    # Get tool names - FunctionTool objects use .name
    tool_names = [getattr(t, "name", getattr(t, "__name__", str(t))) for t in tools]
    logger.info(f"Created YT Summarizer agent with {len(tools)} tools: {', '.join(tool_names)}")
    return agent
