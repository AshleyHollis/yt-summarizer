"""AG-UI endpoint handler for CopilotKit integration.

This module provides a self-hosted AG-UI runtime endpoint that CopilotKit
can connect to using the Microsoft Agent Framework.

The endpoint supports both transport modes:
- "single" mode: POST requests with {"method": "info"} for discovery
- "standard" mode: GET requests to /info for discovery

See: https://docs.copilotkit.ai/microsoft-agent-framework
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.responses import StreamingResponse

if TYPE_CHECKING:
    from fastapi import FastAPI

# Import shared logging
try:
    from shared.logging.config import get_logger
except ImportError:
    import logging
    def get_logger(name: str) -> logging.Logger:
        return logging.getLogger(name)


logger = get_logger(__name__)


class AGUIEndpoint:
    """AG-UI endpoint handler for CopilotKit integration.
    
    Handles both agent discovery (info) requests and agent execution requests.
    Supports CopilotKit's "single" transport mode which sends POST requests
    with {"method": "info"} for agent discovery.
    """
    
    def __init__(
        self,
        agent_name: str,
        agent_description: str,
        version: str = "1.0.0",
    ) -> None:
        """Initialize the AG-UI endpoint.
        
        Args:
            agent_name: The unique identifier for the agent.
            agent_description: Human-readable description of the agent.
            version: API version string.
        """
        self.agent_name = agent_name
        self.agent_description = agent_description
        self.version = version
        self._wrapped_agent: Any = None
        self._event_encoder: Any = None
    
    @property
    def info_response(self) -> dict[str, Any]:
        """Get the agent info response for CopilotKit discovery."""
        return {
            "version": self.version,
            "agents": {
                self.agent_name: {
                    "description": self.agent_description,
                }
            }
        }
    
    def setup(self, app: FastAPI, path: str = "/api/copilotkit") -> bool:
        """Set up the AG-UI endpoint on the FastAPI app.
        
        Args:
            app: The FastAPI application instance.
            path: The endpoint path (default: /api/copilotkit).
            
        Returns:
            True if setup succeeded, False otherwise.
        """
        try:
            from agent_framework_ag_ui import AgentFrameworkAgent
            from agent_framework_ag_ui._endpoint import EventEncoder
            from .yt_summarizer_agent import create_yt_summarizer_agent
            
            # Create the underlying agent
            agent = create_yt_summarizer_agent()
            if agent is None:
                logger.warning(
                    "YT Summarizer agent not created - AG-UI endpoint disabled. "
                    "Check AZURE_OPENAI_ENDPOINT/AZURE_OPENAI_API_KEY or OPENAI_API_KEY."
                )
                return False
            
            # Wrap the agent for AG-UI protocol
            self._wrapped_agent = AgentFrameworkAgent(
                agent=agent,
                name=self.agent_name,
                description=self.agent_description,
            )
            self._event_encoder = EventEncoder()
            
            # Register the POST handler for agent requests
            # Use response_model=None to allow returning StreamingResponse or JSONResponse
            app.post(path, response_model=None)(self._handle_post_request)
            
            # Register the GET handler for info discovery (standard transport)
            app.get(f"{path}/info")(self._handle_info_request)
            
            logger.info(f"AG-UI endpoint registered at {path}")
            return True
            
        except ImportError as e:
            logger.warning(f"AG-UI integration not available: {e}")
            return False
        except Exception as e:
            logger.error(f"Failed to set up AG-UI endpoint: {e}", exc_info=True)
            return False
    
    async def _handle_post_request(self, request: Request) -> StreamingResponse | JSONResponse:
        """Handle POST requests to the AG-UI endpoint.
        
        Intercepts info requests for CopilotKit's "single" transport mode
        and delegates agent execution requests to the wrapped agent.
        
        CopilotKit "single" transport sends requests in two formats:
        1. Info requests: {"method": "info"}
        2. Agent requests: {"method": "agent/run" or "agent/connect", "body": {...}}
        
        The actual agent data is in the "body" field for method-wrapped requests.
        """
        try:
            input_data = await request.json()
        except Exception as e:
            logger.error(f"Failed to parse request body: {e}")
            return JSONResponse(
                status_code=400,
                content={"error": "Invalid JSON in request body"}
            )
        
        # Handle info requests (CopilotKit "single" transport mode)
        method = input_data.get("method")
        if method == "info":
            return JSONResponse(content=self.info_response)
        
        # Handle CopilotKit's method-wrapped requests
        # The actual agent data is in the "body" field
        # CopilotKit sends various method names: "agent/run", "agent/connect", "runs/stream", etc.
        if "body" in input_data and method:
            agent_data = input_data.get("body", {})
            logger.debug(f"Unwrapped CopilotKit {method} request")
        else:
            # Direct AG-UI format (messages at top level)
            agent_data = input_data
        
        # Log the incoming request with detailed context for debugging
        run_id = agent_data.get("runId", agent_data.get("run_id", "unknown"))
        thread_id = agent_data.get("threadId", agent_data.get("thread_id", "unknown"))
        message_count = len(agent_data.get("messages", []))
        
        logger.info(
            f"Agent request received - method={method}, run_id={run_id}, "
            f"thread_id={thread_id}, messages={message_count}"
        )
        
        # Log the full request to understand what CopilotKit sends
        import json
        logger.debug(f"Full agent_data keys: {list(agent_data.keys())}")
        
        # Check for context in various locations CopilotKit might send it
        context = agent_data.get("context")
        properties = agent_data.get("properties")
        readable = agent_data.get("readable")
        frontend_context = agent_data.get("frontendContext")
        
        logger.info(
            f"Context debug - context={context is not None}, properties={properties is not None}, "
            f"readable={readable is not None}, frontend_context={frontend_context is not None}"
        )
        
        if context:
            logger.info(f"Context content: {json.dumps(context, indent=2)[:500]}")
        if properties:
            logger.info(f"Properties content: {json.dumps(properties, indent=2)[:500]}")
        if readable:
            logger.info(f"Readable content: {json.dumps(readable, indent=2)[:500]}")
        
        # Extract context from AG-UI format and inject as system message
        # CopilotKit sends useCopilotReadable data in the 'context' field
        # Format: List[{description: str, value: str}]
        context_list = agent_data.get("context", [])
        if context_list:
            context_parts = []
            for ctx in context_list:
                if isinstance(ctx, dict) and "description" in ctx and "value" in ctx:
                    desc = ctx.get("description", "")
                    value = ctx.get("value")
                    if value is not None:
                        # Handle JSON-serialized values
                        if isinstance(value, str):
                            context_parts.append(f"- {desc}: {value}")
                        else:
                            import json
                            context_parts.append(f"- {desc}: {json.dumps(value)}")
            
            if context_parts:
                context_message_content = (
                    "The following context from the user's application is available:\n" +
                    "\n".join(context_parts)
                )
                # Inject context as a system message at the beginning of the messages
                messages = agent_data.get("messages", [])
                context_system_message = {
                    "id": "context-injection",
                    "role": "system",
                    "content": context_message_content
                }
                # Insert context message after any existing system messages
                agent_data["messages"] = [context_system_message] + messages
                logger.info(f"Injected context as system message: {context_message_content[:500]}")
        
        # Stream the agent response
        return StreamingResponse(
            self._generate_events(agent_data),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )
    
    async def _generate_events(self, input_data: dict[str, Any]):
        """Generate SSE events from the agent execution.
        
        Yields:
            Encoded SSE event strings.
        """
        event_count = 0
        event_types = []
        try:
            logger.info(f"Starting agent execution with input: {list(input_data.keys())}")
            logger.info(f"Messages count: {len(input_data.get('messages', []))}")
            
            async for event in self._wrapped_agent.run_agent(input_data):
                event_count += 1
                event_type = getattr(event, 'type', type(event).__name__)
                event_types.append(event_type)
                logger.debug(f"Event {event_count}: {event_type} - {event}")
                encoded = self._event_encoder.encode(event)
                yield encoded
        except Exception as e:
            logger.error(f"Error during agent execution: {e}", exc_info=True)
            # Yield an error event
            error_event = {
                "type": "RUN_ERROR",
                "error": str(e),
            }
            import json
            yield f"data: {json.dumps(error_event)}\n\n"
        
        logger.info(f"Agent execution completed - {event_count} events streamed: {event_types}")
    
    async def _handle_info_request(self) -> dict[str, Any]:
        """Handle GET requests for agent info (standard transport mode)."""
        return self.info_response


def setup_agui_endpoint(app: FastAPI) -> None:
    """Set up the AG-UI endpoint for CopilotKit integration.
    
    This is the main entry point for registering the AG-UI endpoint.
    
    Args:
        app: The FastAPI application instance.
    """
    endpoint = AGUIEndpoint(
        agent_name="yt-summarizer",
        agent_description="An AI assistant for searching and exploring your YouTube video library",
    )
    endpoint.setup(app, path="/api/copilotkit")
