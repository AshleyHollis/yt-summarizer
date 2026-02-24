"""AG-UI endpoint handler for CopilotKit integration.

This module provides a self-hosted AG-UI runtime endpoint that CopilotKit
can connect to using the Microsoft Agent Framework.

The endpoint supports both transport modes:
- "single" mode: POST requests with {"method": "info"} for discovery
- "standard" mode: GET requests to /info for discovery

Thread Persistence:
- Threads are persisted to the database when agent execution completes
- When a request includes a threadId, the server loads existing messages
- This enables reliable thread switching without client-side race conditions

See: https://docs.copilotkit.ai/microsoft-agent-framework
"""

from __future__ import annotations

import contextvars
import hashlib
import json
import uuid
from typing import TYPE_CHECKING, Any

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.responses import StreamingResponse

if TYPE_CHECKING:
    from fastapi import FastAPI

# Import shared logging and database
try:
    from shared.db.connection import get_db
    from shared.logging.config import get_logger
except ImportError:
    import logging

    def get_logger(name: str) -> logging.Logger:
        return logging.getLogger(name)

    get_db = None

from ..services.thread_service import ThreadService

logger = get_logger(__name__)

# Context variable for AI settings - allows tools to access settings without parameter passing
# This is set at the start of each request and read by query_library tool
current_ai_settings: contextvars.ContextVar[dict[str, Any] | None] = contextvars.ContextVar(
    "current_ai_settings", default=None
)


def get_current_ai_settings() -> dict[str, Any]:
    """Get the current AI settings from request context.

    Returns default settings if none are set.
    """
    settings = current_ai_settings.get()
    if settings is None:
        return {
            "useVideoContext": True,
            "useLLMKnowledge": True,
            "useWebSearch": False,
        }
    return settings


_TOOL_CALL_ID_MAX_LEN = 40


def _sanitize_tool_call_id(tc_id: str) -> str:
    """Truncate a tool_call ID to the Azure AI Foundry maximum length of 40 chars.

    If the ID exceeds the limit, it is replaced with a stable 40-char hex digest
    so that any corresponding tool-result messages can still be matched.
    """
    if len(tc_id) <= _TOOL_CALL_ID_MAX_LEN:
        return tc_id
    return hashlib.sha1(tc_id.encode(), usedforsecurity=False).hexdigest()[:_TOOL_CALL_ID_MAX_LEN]  # nosec B324


def _sanitize_messages_tool_call_ids(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Walk all messages and sanitize any tool_call IDs that exceed 40 chars.

    Azure AI Foundry rejects IDs longer than 40 characters, which can happen when
    the agent framework injects synthetic 'coagent-state-render-…' IDs.

    The remap is applied consistently to:
    - ``message.tool_calls[*].id`` (OpenAI-style assistant messages)
    - ``message.toolCalls[*].id`` (CopilotKit camelCase variant)
    - ``message.tool_call_id``    (tool-result messages, snake_case)
    - ``message.toolCallId``      (tool-result messages, camelCase)
    """
    # Build a remap table so we can update matching toolCallId fields consistently
    id_remap: dict[str, str] = {}

    sanitized: list[dict[str, Any]] = []
    for msg in messages:
        msg = dict(msg)  # shallow copy

        # --- assistant messages with tool_calls (OpenAI snake_case) ---
        if "tool_calls" in msg and isinstance(msg["tool_calls"], list):
            new_tcs = []
            for tc in msg["tool_calls"]:
                tc = dict(tc)
                orig = tc.get("id", "")
                fixed = _sanitize_tool_call_id(orig)
                if orig != fixed:
                    id_remap[orig] = fixed
                    logger.info(f"Sanitized tool_call_id (tool_calls): {orig!r} -> {fixed!r}")
                tc["id"] = fixed
                new_tcs.append(tc)
            msg["tool_calls"] = new_tcs

        # --- assistant messages with toolCalls (camelCase) ---
        if "toolCalls" in msg and isinstance(msg["toolCalls"], list):
            new_tcs = []
            for tc in msg["toolCalls"]:
                tc = dict(tc)
                orig = tc.get("id", "")
                fixed = _sanitize_tool_call_id(orig)
                if orig != fixed:
                    id_remap[orig] = fixed
                    logger.info(f"Sanitized tool_call_id (toolCalls): {orig!r} -> {fixed!r}")
                tc["id"] = fixed
                new_tcs.append(tc)
            msg["toolCalls"] = new_tcs

        # --- tool-result messages (snake_case) ---
        if "tool_call_id" in msg:
            orig = msg["tool_call_id"]
            msg["tool_call_id"] = id_remap.get(orig, _sanitize_tool_call_id(orig))
            if msg["tool_call_id"] != orig:
                logger.info(f"Sanitized tool_call_id (tool_call_id): {orig!r}")

        # --- tool-result messages (camelCase) ---
        if "toolCallId" in msg:
            orig = msg["toolCallId"]
            msg["toolCallId"] = id_remap.get(orig, _sanitize_tool_call_id(orig))
            if msg["toolCallId"] != orig:
                logger.info(f"Sanitized tool_call_id (toolCallId): {orig!r}")

        sanitized.append(msg)

    return sanitized


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
            },
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

        Thread Persistence:
        - When threadId is provided, loads existing messages from database
        - After execution completes, saves updated thread state
        """
        try:
            input_data = await request.json()
        except Exception as e:
            logger.error(f"Failed to parse request body: {e}")
            return JSONResponse(status_code=400, content={"error": "Invalid JSON in request body"})

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
        thread_id = agent_data.get("threadId", agent_data.get("thread_id"))
        message_count = len(agent_data.get("messages", []))

        logger.info(
            f"Agent request received - method={method}, run_id={run_id}, "
            f"thread_id={thread_id}, messages={message_count}"
        )

        # Load existing thread if threadId provided and we have DB access
        existing_thread = None
        if thread_id and get_db is not None:
            try:
                db = get_db()
                async with db.session() as session:
                    thread_service = ThreadService(session)
                    existing_thread = await thread_service.get_thread(thread_id)

                    if existing_thread:
                        # Merge existing messages with incoming messages
                        # CopilotKit may send partial history, server is source of truth
                        server_messages = existing_thread.get("messages", [])
                        client_messages = agent_data.get("messages", [])

                        # Use server messages as base, but allow client to add new messages
                        # The client sends the latest user message, we need to append it
                        if client_messages:
                            # Find new messages from client (not in server history)
                            server_msg_ids = {m.get("id") for m in server_messages if m.get("id")}
                            new_messages = [
                                m for m in client_messages if m.get("id") not in server_msg_ids
                            ]

                            if new_messages:
                                merged_messages = server_messages + new_messages
                                agent_data["messages"] = merged_messages
                                logger.info(
                                    f"Merged thread {thread_id}: {len(server_messages)} server + "
                                    f"{len(new_messages)} new = {len(merged_messages)} total"
                                )
                            else:
                                # Client sent same messages, use server version
                                agent_data["messages"] = server_messages
                                logger.info(
                                    f"Using server thread {thread_id} with {len(server_messages)} messages"
                                )
                        else:
                            agent_data["messages"] = server_messages
                            logger.info(
                                f"Loaded thread {thread_id} with {len(server_messages)} messages"
                            )
            except Exception as e:
                logger.warning(f"Failed to load thread {thread_id}: {e}", exc_info=True)
                # Continue without thread data

        # Log the full request to understand what CopilotKit sends
        logger.debug(f"Full agent_data keys: {list(agent_data.keys())}")

        # Check for frontend tools in the request
        tools = agent_data.get("tools")
        if tools:
            tool_names = [t.get("name") for t in tools if isinstance(t, dict)]
            logger.info(f"Frontend tools received: {tool_names}")
        else:
            logger.info("No frontend tools in request")

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
        extracted_ai_settings = None

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
                            context_parts.append(f"- {desc}: {json.dumps(value)}")

                        # Extract AI settings from context for tool use
                        # Look for the aiSettings context item by checking the description
                        if "AI knowledge source settings" in desc or "aiSettings" in desc.lower():
                            # Value might be a dict (already parsed) or a JSON string
                            if isinstance(value, dict):
                                extracted_ai_settings = value
                            elif isinstance(value, str):
                                try:
                                    parsed_value = json.loads(value)
                                    if isinstance(parsed_value, dict):
                                        extracted_ai_settings = parsed_value
                                except (json.JSONDecodeError, TypeError):
                                    logger.warning(
                                        f"Failed to parse AI settings value: {value[:100]}"
                                    )
                            if extracted_ai_settings:
                                logger.info(
                                    f"Extracted AI settings from context: {extracted_ai_settings}"
                                )

            if context_parts:
                context_message_content = (
                    "The following context from the user's application is available:\n"
                    + "\n".join(context_parts)
                )
                # Inject context as a system message at the beginning of the messages
                messages = agent_data.get("messages", [])
                context_system_message = {
                    "id": "context-injection",
                    "role": "system",
                    "content": context_message_content,
                }
                # Insert context message after any existing system messages
                agent_data["messages"] = [context_system_message] + messages
                logger.info(f"Injected context as system message: {context_message_content[:500]}")

        # Store extracted AI settings in context variable for tools to access
        if extracted_ai_settings:
            current_ai_settings.set(extracted_ai_settings)
            logger.info(f"Set AI settings context variable: {extracted_ai_settings}")
        else:
            # Reset to None so tools use defaults
            current_ai_settings.set(None)
            logger.debug("No AI settings found in context, using defaults")

        # Check if we should run the agent:
        # Use run_id tracking to prevent re-running the agent for the same run
        # This is more reliable than checking message roles, which can be ambiguous
        all_messages = agent_data.get("messages", [])

        # Get the last_run_id from the existing thread (if loaded)
        last_run_id = existing_thread.get("last_run_id") if existing_thread else None

        # Determine if we need to generate a response
        should_run_agent = False

        # If we have a last_run_id and it matches the current run_id, skip
        if last_run_id and last_run_id == run_id:
            logger.info(
                f"Run {run_id} already processed for thread {thread_id} - skipping agent run"
            )
        else:
            # Check if there are any user messages that need a response
            non_system_messages = [m for m in all_messages if m.get("role") != "system"]

            if non_system_messages:
                last_message = non_system_messages[-1]
                last_role = last_message.get("role")
                if last_role == "user":
                    # Last message is from user - needs a response
                    should_run_agent = True
                    logger.info(
                        f"Last message is from user - will run agent for thread {thread_id} (run_id={run_id})"
                    )
                elif last_role in ("assistant", "tool"):
                    # Last message is from assistant or tool result - already has response
                    logger.info(
                        f"Last message is from {last_role} - skipping agent run for thread {thread_id}"
                    )
                else:
                    # Unknown role, skip to be safe
                    logger.info(
                        f"Last message has unknown role '{last_role}' - skipping agent run for thread {thread_id}"
                    )
            else:
                # No real messages (only system), don't run
                logger.info(
                    f"No user/assistant messages in request for thread {thread_id} - returning empty run"
                )

        if not should_run_agent:
            # Return minimal response without running agent or saving thread
            return StreamingResponse(
                self._generate_empty_run_events(thread_id),
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "Connection": "keep-alive",
                    "X-Accel-Buffering": "no",
                },
            )

        # Sanitize tool_call IDs to meet Azure AI Foundry's 40-char limit.
        # The agent framework can inject synthetic IDs like
        # "coagent-state-render-yt-summarizer-pending:<UUID>" (79+ chars) which
        # cause a 400 from the model endpoint.
        if "messages" in agent_data:
            agent_data["messages"] = _sanitize_messages_tool_call_ids(agent_data["messages"])

        # Stream the agent response with thread persistence
        return StreamingResponse(
            self._generate_events(agent_data, thread_id, run_id),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "X-Accel-Buffering": "no",
            },
        )

    async def _generate_empty_run_events(self, thread_id: str | None = None):
        """Generate minimal SSE events for an empty run (no user messages).

        This is used when CopilotKit sends connection/heartbeat requests
        without any user messages. We return minimal events to acknowledge
        the connection without running the agent or making LLM calls.

        Args:
            thread_id: The thread ID for the events.

        Yields:
            Minimal SSE event strings for RUN_STARTED and RUN_FINISHED.
        """
        # Generate a unique run ID
        run_id = str(uuid.uuid4())

        # Emit RUN_STARTED event with threadId as required by AG-UI protocol
        start_event = {
            "type": "RUN_STARTED",
            "threadId": thread_id,
            "runId": run_id,
        }
        yield f"data: {json.dumps(start_event)}\n\n"

        # Emit RUN_FINISHED event with threadId as required by AG-UI protocol
        finish_event = {
            "type": "RUN_FINISHED",
            "threadId": thread_id,
            "runId": run_id,
        }
        yield f"data: {json.dumps(finish_event)}\n\n"

        logger.debug(f"Generated empty run events for thread_id={thread_id}, run_id={run_id}")

    async def _generate_events(
        self, input_data: dict[str, Any], thread_id: str | None = None, run_id: str | None = None
    ):
        """Generate SSE events from the agent execution.

        Args:
            input_data: The agent request data including messages.
            thread_id: Optional thread ID for persistence.
            run_id: The run ID for this agent execution (for tracking).

        Yields:
            Encoded SSE event strings.
        """
        event_count = 0
        event_types = []
        collected_messages = list(input_data.get("messages", []))  # Start with input messages
        assistant_content_parts = []  # Collect streaming text content
        current_assistant_message_id = None  # Track current assistant message ID

        # Track tool calls to build proper assistant messages with toolCalls array
        # Format: {tool_call_id: {name, arguments_parts: []}}
        pending_tool_calls: dict[str, dict[str, Any]] = {}

        # Track tool results to create tool messages
        # Format: {tool_call_id: {message_id, content}}
        tool_results: dict[str, dict[str, Any]] = {}

        try:
            logger.info(f"Starting agent execution with input: {list(input_data.keys())}")
            logger.info(f"Messages count: {len(input_data.get('messages', []))}")

            async for event in self._wrapped_agent.run_agent(input_data):
                event_count += 1
                event_type_raw = getattr(event, "type", type(event).__name__)
                # Handle both enum values and strings for event type comparison
                event_type = (
                    event_type_raw.value
                    if hasattr(event_type_raw, "value")
                    else str(event_type_raw)
                )
                event_types.append(event_type_raw)
                logger.debug(f"Event {event_count}: {event_type} - {event}")

                # Handle text message events
                if event_type == "TEXT_MESSAGE_START":
                    current_assistant_message_id = getattr(event, "message_id", None)
                elif event_type == "TEXT_MESSAGE_CONTENT":
                    delta = getattr(event, "delta", None)
                    if delta:
                        assistant_content_parts.append(delta)
                elif event_type == "TEXT_MESSAGE_END":
                    pass  # Just let it stream through

                # Handle tool call events
                # Note: AG-UI uses snake_case for attributes (tool_call_id, tool_call_name)
                elif event_type == "TOOL_CALL_START":
                    tool_call_id = getattr(event, "tool_call_id", None)
                    tool_call_name = getattr(event, "tool_call_name", None)
                    if tool_call_id:
                        pending_tool_calls[tool_call_id] = {
                            "name": tool_call_name,
                            "arguments_parts": [],
                        }
                        logger.info(
                            f"Started tracking tool call: {tool_call_id} ({tool_call_name})"
                        )

                elif event_type == "TOOL_CALL_ARGS":
                    tool_call_id = getattr(event, "tool_call_id", None)
                    delta = getattr(event, "delta", None)
                    if tool_call_id and tool_call_id in pending_tool_calls and delta:
                        pending_tool_calls[tool_call_id]["arguments_parts"].append(delta)

                elif event_type == "TOOL_CALL_END":
                    tool_call_id = getattr(event, "tool_call_id", None)
                    if tool_call_id and tool_call_id in pending_tool_calls:
                        # Mark tool call as complete (arguments are fully received)
                        pending_tool_calls[tool_call_id]["complete"] = True
                        logger.info(f"Completed tool call: {tool_call_id}")

                # Handle tool result events
                elif event_type == "TOOL_CALL_RESULT":
                    tool_call_id = getattr(event, "tool_call_id", None)
                    message_id = getattr(event, "message_id", None)
                    content = getattr(event, "content", None)
                    if tool_call_id:
                        tool_results[tool_call_id] = {
                            "message_id": message_id or f"tool-result-{tool_call_id}",
                            "content": content or "",
                        }
                        logger.info(f"Captured tool result for: {tool_call_id}")

                # Fix MESSAGES_SNAPSHOT: remap snake_case "tool_calls" to camelCase
                # "toolCalls" so CopilotKit's useLazyToolRenderer can find tool calls
                # after the snapshot overwrites the in-memory messages state.
                elif event_type == "MESSAGES_SNAPSHOT":
                    encoded_str = self._event_encoder.encode(event)
                    try:
                        # Parse the already-serialized JSON event
                        json_str = encoded_str.removeprefix("data: ").rstrip("\n")
                        event_data = json.loads(json_str)
                        # Remap tool_calls -> toolCalls in all messages
                        if "messages" in event_data:
                            fixed = []
                            for msg in event_data["messages"]:
                                if isinstance(msg, dict) and "tool_calls" in msg:
                                    msg = {
                                        **{k: v for k, v in msg.items() if k != "tool_calls"},
                                        "toolCalls": msg["tool_calls"],
                                    }
                                fixed.append(msg)
                            event_data["messages"] = fixed
                        yield f"data: {json.dumps(event_data)}\n\n"
                    except Exception as fix_err:
                        logger.warning(
                            f"MESSAGES_SNAPSHOT fix failed: {fix_err}, yielding original"
                        )
                        yield encoded_str
                    continue

                encoded = self._event_encoder.encode(event)
                yield encoded

        except Exception as e:
            logger.error(f"Error during agent execution: {e}", exc_info=True)
            # Yield an error event per AG-UI spec (requires 'message' field)
            error_event = {
                "type": "RUN_ERROR",
                "message": str(e),
                "code": "AGENT_EXECUTION_ERROR",
            }
            yield f"data: {json.dumps(error_event)}\n\n"

        logger.info(f"Agent execution completed - {event_count} events streamed: {event_types}")
        logger.info(
            f"Collected {len(pending_tool_calls)} pending tool calls, {len(tool_results)} tool results"
        )

        # Save thread after execution completes
        if thread_id and get_db is not None:
            try:
                # Build assistant message with tool calls if any
                if pending_tool_calls:
                    # Create the toolCalls array for the assistant message
                    tool_calls_array = []
                    for tc_id, tc_data in pending_tool_calls.items():
                        arguments = "".join(tc_data.get("arguments_parts", []))
                        tool_calls_array.append(
                            {
                                "id": tc_id,
                                "type": "function",
                                "function": {
                                    "name": tc_data.get("name", "unknown"),
                                    "arguments": arguments,
                                },
                            }
                        )

                    # Create assistant message with tool calls
                    assistant_message = {
                        "id": current_assistant_message_id
                        or f"assistant-{thread_id}-{len(collected_messages)}",
                        "role": "assistant",
                        "toolCalls": tool_calls_array,
                    }
                    # Include content if there was any text alongside tool calls
                    if assistant_content_parts:
                        assistant_message["content"] = "".join(assistant_content_parts)

                    collected_messages.append(assistant_message)
                    logger.info(f"Built assistant message with {len(tool_calls_array)} tool calls")

                    # Create tool result messages
                    for tc_id, result_data in tool_results.items():
                        tool_message = {
                            "id": result_data["message_id"],
                            "role": "tool",
                            "toolCallId": tc_id,
                            "content": result_data["content"],
                        }
                        collected_messages.append(tool_message)
                        logger.info(f"Added tool result message for {tc_id}")

                elif assistant_content_parts:
                    # Plain text assistant message (no tool calls)
                    assistant_message = {
                        "id": current_assistant_message_id
                        or f"assistant-{thread_id}-{len(collected_messages)}",
                        "role": "assistant",
                        "content": "".join(assistant_content_parts),
                    }
                    collected_messages.append(assistant_message)

                # Filter out context-injection messages (they're regenerated each request)
                messages_to_save = [
                    m for m in collected_messages if m.get("id") != "context-injection"
                ]

                db = get_db()
                async with db.session() as session:
                    thread_service = ThreadService(session)
                    await thread_service.save_thread(
                        thread_id=thread_id,
                        messages=messages_to_save,
                        agent_name=self.agent_name,
                        last_run_id=run_id,  # Track the run_id to prevent re-runs
                    )
                    logger.info(
                        f"Saved thread {thread_id} with {len(messages_to_save)} messages (run_id={run_id})"
                    )
            except Exception as e:
                logger.warning(f"Failed to save thread {thread_id}: {e}", exc_info=True)
                # Don't fail the request if saving fails

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
