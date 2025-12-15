"""YT Summarizer Agent for CopilotKit integration.

Uses Microsoft Agent Framework with AG-UI protocol to provide
a self-hosted chat agent for the YT Summarizer application.

See: https://docs.copilotkit.ai/microsoft-agent-framework
See: https://learn.microsoft.com/en-us/agent-framework/
"""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from typing import Annotated, Any, AsyncGenerator

import httpx

# Import Agent Framework components
try:
    from agent_framework import BaseChatClient, ChatAgent, ai_function
    from agent_framework.openai import OpenAIChatClient
    AGENT_FRAMEWORK_AVAILABLE = True
except ImportError:
    ChatAgent = None  # type: ignore
    ai_function = None  # type: ignore
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
SYSTEM_INSTRUCTIONS = """You are a helpful AI assistant for YT Summarizer, a YouTube video knowledge base application.

Your role is to help users:
1. Search and explore their video library
2. Find specific information across video transcripts
3. Understand video content through summaries and key points
4. Discover relationships between videos and topics

CONTEXT AWARENESS:
You receive context about the user's current view. Pay attention to:
- "currentVideo": If not null, the user is viewing a SPECIFIC video. When they ask a question, 
  they are almost certainly asking about THIS video. Use the videoId and title to search.
- If currentVideo is null, the user is on the library page browsing all videos.

When the user is viewing a specific video and asks a question:
1. PRIORITIZE searching within that video's content using search_segments with the videoId
2. Use the video's title and channel to provide context
3. Reference the specific video in your response

PROACTIVE TOOL USE:
You have access to tools to search videos and segments. ALWAYS use them 
proactively when a user asks a question. DO NOT ask for clarification - instead:
- Use search_segments to find relevant transcript content
- Use search_videos to find videos matching the query
- Use get_library_coverage to understand what's available

When a user asks something like "How many albums were sold?" or any factual question:
1. IMMEDIATELY search the library using search_segments with relevant keywords
2. If currentVideo context is available, search within that video first
3. Return the results with video titles and timestamps
4. Only ask for clarification if the search returns no results

When answering:
- Be concise but thorough
- ALWAYS cite your sources with video titles and timestamps
- Include direct quotes from transcripts when relevant
- If search returns no results, say so and suggest alternative search terms

The user's library contains YouTube videos that have been transcribed and analyzed.
Always search first, ask questions later.
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

if ai_function is not None:
    @ai_function
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
            logger.info(f"search_videos found {len(result.get('videos', []))} results for '{query}'")
        return result


    @ai_function
    async def search_segments(
        query: Annotated[str, "The search query to find transcript segments"],
        video_ids: Annotated[list[str] | None, "Optional list of video IDs to search within"] = None,
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
            logger.info(f"search_segments found {len(result.get('segments', []))} results for '{query}'")
        return result


    @ai_function
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


    @ai_function
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


    @ai_function
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


# =============================================================================
# OpenAI Client Factory
# =============================================================================

def create_openai_chat_client() -> BaseChatClient | None:
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
    endpoint = endpoint.rstrip('/')
    
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
        search_videos,
        search_segments,
        get_video_summary,
        get_library_coverage,
        get_topics_for_channel,
    ]


def create_yt_summarizer_agent() -> ChatAgent | None:
    """Create the YT Summarizer agent with tools.
    
    Creates a ChatAgent configured with:
    - System instructions for the YT Summarizer use case
    - Tools for searching videos, segments, and getting summaries
    - Appropriate temperature settings
    
    Returns:
        Configured ChatAgent or None if dependencies not available.
    """
    if not AGENT_FRAMEWORK_AVAILABLE:
        logger.warning("agent_framework not installed - agent cannot be created")
        return None
    
    chat_client = create_openai_chat_client()
    if chat_client is None:
        return None
    
    tools = get_agent_tools()
    
    # Create the agent
    # Note: Reasoning models (o1, o3, gpt-5-mini, etc.) only support:
    # - temperature=1 (the only allowed value)
    # - max_completion_tokens instead of max_tokens
    # We explicitly set temperature=1 for compatibility with all models.
    agent = ChatAgent(
        chat_client=chat_client,
        name=AGENT_NAME,
        description=AGENT_DESCRIPTION,
        instructions=SYSTEM_INSTRUCTIONS,
        tools=tools,
        temperature=1,  # Only value supported by reasoning models
    )
    
    # Get tool names - AIFunction objects use .name, not __name__
    tool_names = [getattr(t, 'name', getattr(t, '__name__', str(t))) for t in tools]
    logger.info(
        f"Created YT Summarizer agent with {len(tools)} tools: "
        f"{', '.join(tool_names)}"
    )
    return agent
