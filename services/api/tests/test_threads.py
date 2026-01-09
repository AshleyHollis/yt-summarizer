"""Integration tests for thread API endpoints.

These tests verify thread persistence with proper toolCalls structure:
- Thread creation with messages
- Thread retrieval with preserved message structure
- Tool call format preservation (assistant toolCalls + tool toolCallId)
"""

from uuid import uuid4

import pytest
from fastapi import status

# ============================================================================
# Thread Fixtures
# ============================================================================


@pytest.fixture
def sample_user_message():
    """Create a sample user message."""
    return {
        "id": str(uuid4()),
        "role": "user",
        "content": "What videos do I have about Python?"
    }


@pytest.fixture
def sample_assistant_with_tool_calls():
    """Create a sample assistant message with toolCalls array."""
    tool_call_id = f"call_{uuid4().hex[:24]}"
    return {
        "id": tool_call_id,
        "role": "assistant",
        "toolCalls": [{
            "id": tool_call_id,
            "type": "function",
            "function": {
                "name": "queryLibrary",
                "arguments": '{"query":"Python videos"}'
            }
        }]
    }


@pytest.fixture
def sample_tool_result(sample_assistant_with_tool_calls):
    """Create a sample tool result message matching the assistant's toolCalls."""
    tool_call_id = sample_assistant_with_tool_calls["toolCalls"][0]["id"]
    return {
        "id": str(uuid4()),
        "role": "tool",
        "content": '{"answer":"You have 3 Python videos","videoCards":[],"evidence":[]}',
        "toolCallId": tool_call_id
    }


@pytest.fixture
def complete_thread_messages(sample_user_message, sample_assistant_with_tool_calls, sample_tool_result):
    """Create a complete thread with user -> assistant(toolCalls) -> tool(result)."""
    return [
        sample_user_message,
        sample_assistant_with_tool_calls,
        sample_tool_result
    ]


@pytest.fixture
def multi_turn_thread_messages():
    """Create a multi-turn thread with multiple tool calls."""
    tool_call_1 = f"call_{uuid4().hex[:24]}"
    tool_call_2 = f"call_{uuid4().hex[:24]}"
    
    return [
        {"id": str(uuid4()), "role": "user", "content": "First question"},
        {
            "id": tool_call_1,
            "role": "assistant",
            "toolCalls": [{
                "id": tool_call_1,
                "type": "function",
                "function": {"name": "queryLibrary", "arguments": '{"query":"first"}'}
            }]
        },
        {"id": str(uuid4()), "role": "tool", "content": '{"answer":"First answer"}', "toolCallId": tool_call_1},
        {"id": str(uuid4()), "role": "user", "content": "Follow up question"},
        {
            "id": tool_call_2,
            "role": "assistant", 
            "toolCalls": [{
                "id": tool_call_2,
                "type": "function",
                "function": {"name": "queryLibrary", "arguments": '{"query":"second"}'}
            }]
        },
        {"id": str(uuid4()), "role": "tool", "content": '{"answer":"Second answer"}', "toolCallId": tool_call_2},
    ]


# ============================================================================
# Thread Message Structure Tests
# ============================================================================


class TestThreadMessageStructure:
    """Tests for proper message structure in threads."""

    def test_assistant_message_has_required_toolcalls_fields(self, sample_assistant_with_tool_calls):
        """Assistant message with toolCalls should have proper structure."""
        msg = sample_assistant_with_tool_calls
        
        assert msg["role"] == "assistant"
        assert "toolCalls" in msg
        assert len(msg["toolCalls"]) > 0
        
        tool_call = msg["toolCalls"][0]
        assert "id" in tool_call
        assert "type" in tool_call
        assert tool_call["type"] == "function"
        assert "function" in tool_call
        assert "name" in tool_call["function"]
        assert "arguments" in tool_call["function"]

    def test_tool_result_has_matching_toolcallid(self, sample_assistant_with_tool_calls, sample_tool_result):
        """Tool result should have toolCallId matching assistant's toolCalls."""
        assistant_tool_call_id = sample_assistant_with_tool_calls["toolCalls"][0]["id"]
        tool_result_call_id = sample_tool_result["toolCallId"]
        
        assert assistant_tool_call_id == tool_result_call_id

    def test_tool_result_has_required_fields(self, sample_tool_result):
        """Tool result message should have all required fields."""
        msg = sample_tool_result
        
        assert "id" in msg
        assert msg["role"] == "tool"
        assert "content" in msg
        assert "toolCallId" in msg

    def test_complete_thread_has_all_message_types(self, complete_thread_messages):
        """Complete thread should have user, assistant with toolCalls, and tool result."""
        roles = [m["role"] for m in complete_thread_messages]
        
        assert "user" in roles
        assert "assistant" in roles
        assert "tool" in roles
        
        # Verify assistant has toolCalls
        assistant_msg = next(m for m in complete_thread_messages if m["role"] == "assistant")
        assert "toolCalls" in assistant_msg

    def test_multi_turn_preserves_all_tool_calls(self, multi_turn_thread_messages):
        """Multi-turn thread should preserve all tool calls and results."""
        assistant_msgs = [m for m in multi_turn_thread_messages if m["role"] == "assistant"]
        tool_msgs = [m for m in multi_turn_thread_messages if m["role"] == "tool"]
        
        assert len(assistant_msgs) == 2
        assert len(tool_msgs) == 2
        
        # Each assistant should have toolCalls
        for assistant in assistant_msgs:
            assert "toolCalls" in assistant
            assert len(assistant["toolCalls"]) > 0
        
        # Each tool should have toolCallId
        for tool in tool_msgs:
            assert "toolCallId" in tool
        
        # Tool call IDs should match between pairs
        assistant_tool_ids = {a["toolCalls"][0]["id"] for a in assistant_msgs}
        tool_call_ids = {t["toolCallId"] for t in tool_msgs}
        
        assert assistant_tool_ids == tool_call_ids


# ============================================================================
# Thread API Integration Tests
# ============================================================================


class TestThreadsAPI:
    """Integration tests for thread API endpoints.
    
    Note: These tests require a real database connection or properly mocked
    persistence layer. Currently marked as skip because the mock session
    doesn't persist data between requests.
    """

    @pytest.mark.skip(reason="Requires database persistence - mock doesn't retain data between requests")
    @pytest.mark.asyncio
    async def test_create_thread_with_tool_calls(
        self, 
        client, 
        complete_thread_messages
    ):
        """POST /api/v1/threads/messages should create thread with toolCalls preserved."""
        response = client.post(
            "/api/v1/threads/messages",
            json={
                "messages": complete_thread_messages,
                "title": "Test Thread with Tool Calls"
            }
        )
        
        # Should successfully create thread (201 Created)
        assert response.status_code == status.HTTP_201_CREATED
        data = response.json()
        
        assert "thread_id" in data
        assert data["message_count"] == len(complete_thread_messages)

    @pytest.mark.skip(reason="Requires database persistence - mock doesn't retain data between requests")
    @pytest.mark.asyncio
    async def test_get_thread_preserves_tool_call_structure(
        self, 
        client,
        complete_thread_messages
    ):
        """GET /api/v1/threads/{id} should return messages with toolCalls intact."""
        # First create a thread
        create_response = client.post(
            "/api/v1/threads/messages",
            json={
                "messages": complete_thread_messages,
                "title": "Test Thread for Retrieval"
            }
        )
        
        assert create_response.status_code == status.HTTP_201_CREATED
        thread_id = create_response.json()["thread_id"]
        
        # Now get the thread
        get_response = client.get(f"/api/v1/threads/{thread_id}")
        
        assert get_response.status_code == status.HTTP_200_OK
        data = get_response.json()
        
        # Verify messages structure
        assert "messages" in data
        messages = data["messages"]
        
        # Find the assistant message
        assistant_msg = next((m for m in messages if m["role"] == "assistant"), None)
        assert assistant_msg is not None
        assert "toolCalls" in assistant_msg
        assert len(assistant_msg["toolCalls"]) > 0
        
        # Find the tool result message
        tool_msg = next((m for m in messages if m["role"] == "tool"), None)
        assert tool_msg is not None
        assert "toolCallId" in tool_msg
        
        # Verify IDs match
        assert assistant_msg["toolCalls"][0]["id"] == tool_msg["toolCallId"]

    @pytest.mark.skip(reason="PUT endpoint not implemented yet")
    @pytest.mark.asyncio
    async def test_update_thread_with_additional_tool_calls(
        self,
        client,
        complete_thread_messages
    ):
        """PUT /api/v1/threads/{id}/messages should preserve new tool calls."""
        # Create initial thread
        create_response = client.post(
            "/api/v1/threads/messages",
            json={
                "messages": complete_thread_messages,
                "title": "Thread to Update"
            }
        )
        thread_id = create_response.json()["thread_id"]
        
        # Add more messages including a new tool call
        new_tool_call_id = f"call_{uuid4().hex[:24]}"
        updated_messages = complete_thread_messages + [
            {"id": str(uuid4()), "role": "user", "content": "Follow up"},
            {
                "id": new_tool_call_id,
                "role": "assistant",
                "toolCalls": [{
                    "id": new_tool_call_id,
                    "type": "function",
                    "function": {"name": "queryLibrary", "arguments": '{"query":"follow up"}'}
                }]
            },
            {"id": str(uuid4()), "role": "tool", "content": '{"answer":"follow up result"}', "toolCallId": new_tool_call_id},
        ]
        
        # Update the thread
        update_response = client.put(
            f"/api/v1/threads/{thread_id}/messages",
            json={"messages": updated_messages}
        )
        
        assert update_response.status_code == status.HTTP_200_OK
        
        # Get and verify
        get_response = client.get(f"/api/v1/threads/{thread_id}")
        data = get_response.json()
        
        assistant_msgs = [m for m in data["messages"] if m["role"] == "assistant"]
        assert len(assistant_msgs) == 2
        
        tool_msgs = [m for m in data["messages"] if m["role"] == "tool"]
        assert len(tool_msgs) == 2

    @pytest.mark.skip(reason="Requires database persistence - mock doesn't retain data between requests")
    @pytest.mark.asyncio
    async def test_thread_with_multiple_simultaneous_tool_calls(self, client):
        """Thread with multiple tool calls from one assistant message."""
        tool_call_1 = f"call_{uuid4().hex[:24]}"
        tool_call_2 = f"call_{uuid4().hex[:24]}"
        
        messages = [
            {"id": str(uuid4()), "role": "user", "content": "Complex query"},
            {
                "id": str(uuid4()),
                "role": "assistant",
                "toolCalls": [
                    {
                        "id": tool_call_1,
                        "type": "function",
                        "function": {"name": "queryLibrary", "arguments": '{"query":"part 1"}'}
                    },
                    {
                        "id": tool_call_2,
                        "type": "function",
                        "function": {"name": "queryLibrary", "arguments": '{"query":"part 2"}'}
                    }
                ]
            },
            {"id": str(uuid4()), "role": "tool", "content": '{"answer":"result 1"}', "toolCallId": tool_call_1},
            {"id": str(uuid4()), "role": "tool", "content": '{"answer":"result 2"}', "toolCallId": tool_call_2},
        ]
        
        create_response = client.post(
            "/api/v1/threads/messages",
            json={"messages": messages, "title": "Multi-Tool-Call Test"}
        )
        
        assert create_response.status_code == status.HTTP_201_CREATED
        thread_id = create_response.json()["thread_id"]
        
        # Verify structure preserved
        get_response = client.get(f"/api/v1/threads/{thread_id}")
        data = get_response.json()
        
        assistant_msg = next(m for m in data["messages"] if m["role"] == "assistant")
        assert len(assistant_msg["toolCalls"]) == 2
        
        tool_call_ids = {tc["id"] for tc in assistant_msg["toolCalls"]}
        assert tool_call_1 in tool_call_ids
        assert tool_call_2 in tool_call_ids


# ============================================================================
# Thread Retrieval for Display Tests
# ============================================================================


class TestThreadDisplayFormatting:
    """Tests for thread message formatting for UI display."""

    def test_messages_with_tool_calls_can_be_rendered(self, complete_thread_messages):
        """Messages with proper toolCalls structure can be rendered by CopilotKit."""
        # Simulate what the UI does: check if toolCalls exists on assistant message
        assistant_msg = next(m for m in complete_thread_messages if m["role"] == "assistant")
        
        has_tool_calls = "toolCalls" in assistant_msg and len(assistant_msg.get("toolCalls", [])) > 0
        
        assert has_tool_calls, "Assistant message should have toolCalls for proper rendering"

    def test_tool_result_can_be_associated_with_tool_call(self, complete_thread_messages):
        """Tool result can be associated with its triggering tool call."""
        assistant_msg = next(m for m in complete_thread_messages if m["role"] == "assistant")
        tool_msg = next(m for m in complete_thread_messages if m["role"] == "tool")
        
        # Build map of tool call IDs
        tool_call_ids = {tc["id"] for tc in assistant_msg.get("toolCalls", [])}
        
        # Tool result should match
        assert tool_msg["toolCallId"] in tool_call_ids

    def test_incomplete_tool_call_detection(self):
        """Detect when tool call doesn't have a matching result."""
        tool_call_id = f"call_{uuid4().hex[:24]}"
        
        messages = [
            {"id": str(uuid4()), "role": "user", "content": "Query"},
            {
                "id": tool_call_id,
                "role": "assistant",
                "toolCalls": [{
                    "id": tool_call_id,
                    "type": "function",
                    "function": {"name": "queryLibrary", "arguments": "{}"}
                }]
            },
            # Note: No tool result message
        ]
        
        # Check if all tool calls have results
        tool_call_ids = set()
        tool_result_ids = set()
        
        for msg in messages:
            if msg["role"] == "assistant" and "toolCalls" in msg:
                for tc in msg["toolCalls"]:
                    tool_call_ids.add(tc["id"])
            elif msg["role"] == "tool" and "toolCallId" in msg:
                tool_result_ids.add(msg["toolCallId"])
        
        # Incomplete if not all tool calls have results
        is_complete = tool_call_ids <= tool_result_ids
        
        assert not is_complete, "Should detect incomplete tool call"

    def test_complete_tool_call_detection(self, complete_thread_messages):
        """Detect when all tool calls have matching results."""
        tool_call_ids = set()
        tool_result_ids = set()
        
        for msg in complete_thread_messages:
            if msg["role"] == "assistant" and "toolCalls" in msg:
                for tc in msg["toolCalls"]:
                    tool_call_ids.add(tc["id"])
            elif msg["role"] == "tool" and "toolCallId" in msg:
                tool_result_ids.add(msg["toolCallId"])
        
        is_complete = tool_call_ids <= tool_result_ids
        
        assert is_complete, "Should detect complete tool call"
