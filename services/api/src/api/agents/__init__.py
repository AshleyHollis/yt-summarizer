"""Agent modules for Microsoft Agent Framework integration.

This package provides the YT Summarizer agent and AG-UI endpoint
for CopilotKit integration.

See: https://docs.copilotkit.ai/microsoft-agent-framework
"""

from .agui_endpoint import AGUIEndpoint, setup_agui_endpoint
from .yt_summarizer_agent import (
    AGENT_DESCRIPTION,
    AGENT_NAME,
    create_openai_chat_client,
    create_yt_summarizer_agent,
    get_agent_tools,
)

__all__ = [
    "AGENT_NAME",
    "AGENT_DESCRIPTION",
    "AGUIEndpoint",
    "create_openai_chat_client",
    "create_yt_summarizer_agent",
    "get_agent_tools",
    "setup_agui_endpoint",
]
