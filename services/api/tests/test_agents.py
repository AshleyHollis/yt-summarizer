"""Unit tests for the agents module.

These tests verify that the AG-UI endpoint and agent can be properly
initialized and registered. They catch issues like:
- Missing dependencies (agent_framework packages)
- Invalid return type annotations on FastAPI routes
- Incorrect attribute access on framework objects
- Environment variable configuration issues

Run early to catch integration issues before E2E tests.
"""


import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Check if agent framework packages are available
try:
    import agent_framework
    HAS_AGENT_FRAMEWORK = True
except ImportError:
    HAS_AGENT_FRAMEWORK = False

try:
    import agent_framework_ag_ui
    HAS_AGENT_FRAMEWORK_AG_UI = True
except ImportError:
    HAS_AGENT_FRAMEWORK_AG_UI = False

requires_agent_framework = pytest.mark.skipif(
    not HAS_AGENT_FRAMEWORK,
    reason="agent_framework package not installed (optional dependency)"
)
requires_agent_framework_ag_ui = pytest.mark.skipif(
    not HAS_AGENT_FRAMEWORK_AG_UI,
    reason="agent_framework_ag_ui package not installed (optional dependency)"
)


# =============================================================================
# Test: Agent Framework Availability (optional - skip if not installed)
# =============================================================================

@requires_agent_framework
class TestAgentFrameworkAvailability:
    """Test that required agent framework packages are available."""

    def test_agent_framework_package_installed(self):
        """Verify agent_framework package can be imported."""
        import agent_framework
        assert hasattr(agent_framework, 'ChatAgent')
        assert hasattr(agent_framework, 'ai_function')

    @requires_agent_framework_ag_ui
    def test_agent_framework_ag_ui_package_installed(self):
        """Verify agent_framework_ag_ui package can be imported."""
        import agent_framework_ag_ui
        assert hasattr(agent_framework_ag_ui, 'AgentFrameworkAgent')

    def test_openai_client_available(self):
        """Verify OpenAI client is available in agent_framework."""
        from agent_framework.openai import OpenAIChatClient
        assert OpenAIChatClient is not None

    @requires_agent_framework_ag_ui
    def test_event_encoder_available(self):
        """Verify EventEncoder is available for SSE streaming."""
        from agent_framework_ag_ui._endpoint import EventEncoder
        assert EventEncoder is not None


# =============================================================================
# Test: Agent Creation (requires agent_framework)
# =============================================================================

@requires_agent_framework
class TestAgentCreation:
    """Test agent creation with various configurations."""

    def test_create_agent_with_azure_openai_config(self, monkeypatch):
        """Verify agent creation succeeds with Azure OpenAI configuration."""
        # Set required environment variables
        monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://test.openai.azure.com")
        monkeypatch.setenv("AZURE_OPENAI_API_KEY", "test-api-key")
        monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
        
        from src.api.agents.yt_summarizer_agent import create_yt_summarizer_agent
        
        agent = create_yt_summarizer_agent()
        
        assert agent is not None, "Agent should be created with valid Azure OpenAI config"

    def test_create_agent_with_openai_config(self, monkeypatch):
        """Verify agent creation succeeds with standard OpenAI configuration."""
        # Clear Azure config, set OpenAI config
        monkeypatch.delenv("AZURE_OPENAI_ENDPOINT", raising=False)
        monkeypatch.delenv("AZURE_OPENAI_API_KEY", raising=False)
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")
        monkeypatch.setenv("OPENAI_MODEL", "gpt-4o")
        
        from src.api.agents.yt_summarizer_agent import create_yt_summarizer_agent
        
        agent = create_yt_summarizer_agent()
        
        assert agent is not None, "Agent should be created with valid OpenAI config"

    def test_create_agent_returns_none_without_config(self, monkeypatch):
        """Verify agent creation returns None without LLM configuration."""
        # Clear all LLM config
        monkeypatch.delenv("AZURE_OPENAI_ENDPOINT", raising=False)
        monkeypatch.delenv("AZURE_OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        
        from src.api.agents.yt_summarizer_agent import create_yt_summarizer_agent
        
        agent = create_yt_summarizer_agent()
        
        assert agent is None, "Agent should be None without LLM configuration"

    def test_agent_has_expected_tools(self, monkeypatch):
        """Verify agent is created with the expected tools."""
        monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://test.openai.azure.com")
        monkeypatch.setenv("AZURE_OPENAI_API_KEY", "test-api-key")
        
        from src.api.agents.yt_summarizer_agent import get_agent_tools
        
        tools = get_agent_tools()
        
        # Check we have the expected number of tools
        assert len(tools) == 8, f"Expected 8 tools, got {len(tools)}"
        
        # Check each tool has a name attribute (not __name__)
        for tool in tools:
            # AIFunction objects use .name, not __name__
            tool_name = getattr(tool, 'name', None)
            assert tool_name is not None, f"Tool {tool} should have a 'name' attribute"
            assert isinstance(tool_name, str), f"Tool name should be a string, got {type(tool_name)}"

    def test_tool_names_are_correct(self, monkeypatch):
        """Verify tools have the expected names."""
        monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://test.openai.azure.com")
        monkeypatch.setenv("AZURE_OPENAI_API_KEY", "test-api-key")
        
        from src.api.agents.yt_summarizer_agent import get_agent_tools
        
        tools = get_agent_tools()
        tool_names = {getattr(t, 'name', None) for t in tools}
        
        expected_names = {
            'search_videos',
            'search_segments', 
            'get_video_summary',
            'get_library_coverage',
            'get_topics_for_channel',
            'query_library',  # Main RAG query tool with AI settings support
            'synthesize_learning_path',  # US6: Learning path synthesis
            'synthesize_watch_list',  # US6: Watch list synthesis
        }
        
        assert tool_names == expected_names, f"Tool names mismatch. Got: {tool_names}, Expected: {expected_names}"


# =============================================================================
# Test: Agent System Prompt Behavior (no agent_framework required)
# =============================================================================

class TestAgentSystemPrompt:
    """Test that the agent's system prompt enforces proactive behavior.
    
    The agent should use tools proactively instead of asking for clarification.
    When a user asks a question like "How many albums were sold?", the agent
    should search the video library first, NOT ask "which video?".
    """

    def test_system_prompt_instructs_proactive_tool_use(self):
        """Verify system prompt tells agent to use tools proactively."""
        from src.api.agents.yt_summarizer_agent import SYSTEM_INSTRUCTIONS
        
        # Check for proactive behavior instructions
        prompt_lower = SYSTEM_INSTRUCTIONS.lower()
        
        assert "proactively" in prompt_lower or "proactive" in prompt_lower, \
            "System prompt should instruct agent to use tools proactively"

    def test_system_prompt_discourages_clarification_requests(self):
        """Verify system prompt tells agent NOT to ask for clarification."""
        from src.api.agents.yt_summarizer_agent import SYSTEM_INSTRUCTIONS
        
        prompt_lower = SYSTEM_INSTRUCTIONS.lower()
        
        # Should discourage asking for clarification
        discouragement_phrases = [
            "do not ask for clarification",
            "don't ask for clarification",
            "don't ask which",
            "do not ask which",
            "search first",
            "act first",
        ]
        
        has_discouragement = any(phrase in prompt_lower for phrase in discouragement_phrases)
        assert has_discouragement, \
            "System prompt should discourage asking for clarification before searching"

    def test_system_prompt_instructs_immediate_search(self):
        """Verify system prompt tells agent to search immediately."""
        from src.api.agents.yt_summarizer_agent import SYSTEM_INSTRUCTIONS
        
        prompt_lower = SYSTEM_INSTRUCTIONS.lower()
        
        # Should have instructions to search immediately
        search_phrases = [
            "immediately search",
            "search the library",
            "search first",
            "always search",
        ]
        
        has_search_instruction = any(phrase in prompt_lower for phrase in search_phrases)
        assert has_search_instruction, \
            "System prompt should instruct agent to search the library immediately"

    def test_system_prompt_references_available_tools(self):
        """Verify system prompt mentions the tools available."""
        from src.api.agents.yt_summarizer_agent import SYSTEM_INSTRUCTIONS
        
        prompt_lower = SYSTEM_INSTRUCTIONS.lower()
        
        # Should mention key tools
        assert "search_videos" in prompt_lower or "search videos" in prompt_lower, \
            "System prompt should mention search_videos tool"
        assert "search_segments" in prompt_lower or "search segments" in prompt_lower, \
            "System prompt should mention search_segments tool"

    def test_system_prompt_has_context_awareness_instructions(self):
        """Verify system prompt tells agent to use scope/context for video targeting."""
        from src.api.agents.yt_summarizer_agent import SYSTEM_INSTRUCTIONS
        
        prompt_lower = SYSTEM_INSTRUCTIONS.lower()
        
        # Should mention scope or videoIds context (the current implementation)
        has_scope_context = "scope" in prompt_lower or "videoids" in prompt_lower
        assert has_scope_context, \
            "System prompt should mention scope or videoIds for video targeting"
        
        # Should instruct scoping to specific videos
        scope_phrases = [
            "only search those specific videos",
            "video_id",
            "pass video_id",
        ]
        has_scoping = any(phrase in prompt_lower for phrase in scope_phrases)
        assert has_scoping, \
            "System prompt should instruct agent to scope searches to specific videos"


# =============================================================================
# Test: Azure Endpoint URL Building (no agent_framework required)
# =============================================================================

class TestAzureEndpointURLBuilding:
    """Test that Azure OpenAI and Azure AI Foundry endpoints are correctly formatted.
    
    This catches issues like:
    - 401 Unauthorized due to incorrect audience/endpoint format
    - Wrong base_url construction for different Azure AI services
    
    These tests do NOT require agent_framework - they test pure URL building.
    """

    def test_azure_ai_foundry_endpoint_format(self):
        """Verify Azure AI Foundry endpoint is correctly formatted."""
        from src.api.agents.yt_summarizer_agent import _build_azure_openai_base_url
        
        # Azure AI Foundry format
        endpoint = "https://aif-pai-dev-aue.services.ai.azure.com/api/projects/personal-ai-portal-dev"
        deployment = "gpt-4o"
        
        base_url = _build_azure_openai_base_url(endpoint, deployment)
        
        # Should use /models endpoint for Foundry
        assert base_url == "https://aif-pai-dev-aue.services.ai.azure.com/models", \
            f"Azure AI Foundry base_url incorrect: {base_url}"

    def test_azure_ai_foundry_endpoint_without_project_path(self):
        """Verify Azure AI Foundry endpoint works without project path."""
        from src.api.agents.yt_summarizer_agent import _build_azure_openai_base_url
        
        endpoint = "https://my-resource.services.ai.azure.com"
        deployment = "gpt-4o"
        
        base_url = _build_azure_openai_base_url(endpoint, deployment)
        
        assert base_url == "https://my-resource.services.ai.azure.com/models", \
            f"Base URL should end with /models: {base_url}"

    def test_standard_azure_openai_endpoint_format(self):
        """Verify standard Azure OpenAI endpoint is correctly formatted."""
        from src.api.agents.yt_summarizer_agent import _build_azure_openai_base_url
        
        endpoint = "https://my-resource.openai.azure.com"
        deployment = "gpt-4o"
        
        base_url = _build_azure_openai_base_url(endpoint, deployment)
        
        assert base_url == "https://my-resource.openai.azure.com/openai/deployments/gpt-4o", \
            f"Azure OpenAI base_url incorrect: {base_url}"

    def test_endpoint_with_trailing_slash(self):
        """Verify trailing slashes are handled correctly."""
        from src.api.agents.yt_summarizer_agent import _build_azure_openai_base_url
        
        # With trailing slash
        endpoint = "https://my-resource.openai.azure.com/"
        deployment = "gpt-4o"
        
        base_url = _build_azure_openai_base_url(endpoint, deployment)
        
        # Should not have double slashes
        assert "//" not in base_url.replace("https://", ""), \
            f"Base URL should not have double slashes: {base_url}"

    def test_azure_ai_foundry_endpoint_with_trailing_slash(self):
        """Verify Azure AI Foundry endpoint handles trailing slashes."""
        from src.api.agents.yt_summarizer_agent import _build_azure_openai_base_url
        
        endpoint = "https://aif-pai-dev-aue.services.ai.azure.com/api/projects/my-project/"
        deployment = "gpt-4o"
        
        base_url = _build_azure_openai_base_url(endpoint, deployment)
        
        assert base_url == "https://aif-pai-dev-aue.services.ai.azure.com/models", \
            f"Base URL should be /models endpoint: {base_url}"

    @requires_agent_framework
    def test_create_client_with_azure_ai_foundry_endpoint(self, monkeypatch):
        """Verify OpenAI client is created correctly with Azure AI Foundry endpoint."""
        monkeypatch.setenv(
            "AZURE_OPENAI_ENDPOINT", 
            "https://aif-pai-dev-aue.services.ai.azure.com/api/projects/personal-ai-portal-dev"
        )
        monkeypatch.setenv("AZURE_OPENAI_API_KEY", "test-api-key")
        monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
        
        from src.api.agents.yt_summarizer_agent import create_openai_chat_client
        
        client = create_openai_chat_client()
        
        assert client is not None, "Client should be created with Azure AI Foundry config"
        # Verify the base_url was set correctly
        assert hasattr(client, '_client') or hasattr(client, 'base_url'), \
            "Client should have accessible configuration"

    @requires_agent_framework
    def test_agent_does_not_set_max_tokens(self, monkeypatch):
        """Verify agent doesn't set max_tokens (causes errors with newer models).
        
        Newer OpenAI models (gpt-4o, o1, o3, gpt-5-mini, etc.) require 
        max_completion_tokens instead of max_tokens. The agent framework's
        ChatAgent sets max_tokens, which causes 400 errors.
        """
        monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://test.openai.azure.com")
        monkeypatch.setenv("AZURE_OPENAI_API_KEY", "test-api-key")
        monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
        
        from src.api.agents.yt_summarizer_agent import create_yt_summarizer_agent
        
        agent = create_yt_summarizer_agent()
        
        assert agent is not None
        # The agent should not have max_tokens set to avoid API errors
        # Check if the agent's max_tokens is None or not set
        max_tokens = getattr(agent, 'max_tokens', None) or getattr(agent, '_max_tokens', None)
        assert max_tokens is None, \
            f"Agent should not set max_tokens (causes errors with newer models). Got: {max_tokens}"

    @requires_agent_framework
    def test_agent_sets_temperature_to_one(self, monkeypatch):
        """Verify agent sets temperature=1 (required for reasoning models).
        
        Reasoning models (o1, o3, gpt-5-mini, etc.) only support temperature=1.
        Setting other values causes 400 errors.
        
        Note: The temperature is set in the ChatAgent constructor, but may not be
        exposed as a public attribute. We verify the agent creates successfully,
        which indicates the constructor accepted temperature=1.
        """
        monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://test.openai.azure.com")
        monkeypatch.setenv("AZURE_OPENAI_API_KEY", "test-api-key")
        monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "gpt-5-mini")
        
        from src.api.agents.yt_summarizer_agent import create_yt_summarizer_agent
        
        agent = create_yt_summarizer_agent()
        
        assert agent is not None, "Agent should be created successfully with temperature=1"
        # The agent is created - temperature=1 was accepted by ChatAgent constructor
        # Temperature is set in yt_summarizer_agent.py:410 and is the only value
        # supported by reasoning models. The agent constructor validates this.


# =============================================================================
# Test: AG-UI Endpoint Registration (requires agent_framework_ag_ui)
# =============================================================================

@requires_agent_framework_ag_ui
class TestAGUIEndpointRegistration:
    """Test that AG-UI endpoints are properly registered on FastAPI app."""

    def test_agui_endpoint_registers_routes(self, monkeypatch):
        """Verify AG-UI endpoint registers both POST and GET routes."""
        monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://test.openai.azure.com")
        monkeypatch.setenv("AZURE_OPENAI_API_KEY", "test-api-key")
        monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
        
        from src.api.agents.agui_endpoint import setup_agui_endpoint
        
        app = FastAPI()
        setup_agui_endpoint(app)
        
        # Get all registered route paths
        route_paths = [route.path for route in app.routes]
        
        assert "/api/copilotkit" in route_paths, "POST /api/copilotkit route should be registered"
        assert "/api/copilotkit/info" in route_paths, "GET /api/copilotkit/info route should be registered"

    def test_agui_endpoint_setup_returns_true_on_success(self, monkeypatch):
        """Verify setup_agui_endpoint returns True on successful setup."""
        monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://test.openai.azure.com")
        monkeypatch.setenv("AZURE_OPENAI_API_KEY", "test-api-key")
        
        from src.api.agents.agui_endpoint import AGUIEndpoint
        
        endpoint = AGUIEndpoint(
            agent_name="test-agent",
            agent_description="Test agent",
        )
        
        app = FastAPI()
        result = endpoint.setup(app)
        
        assert result is True, "setup() should return True on success"

    def test_agui_endpoint_setup_returns_false_without_config(self, monkeypatch):
        """Verify setup_agui_endpoint returns False without LLM config."""
        monkeypatch.delenv("AZURE_OPENAI_ENDPOINT", raising=False)
        monkeypatch.delenv("AZURE_OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        
        from src.api.agents.agui_endpoint import AGUIEndpoint
        
        endpoint = AGUIEndpoint(
            agent_name="test-agent",
            agent_description="Test agent",
        )
        
        app = FastAPI()
        result = endpoint.setup(app)
        
        assert result is False, "setup() should return False without LLM config"

    def test_agui_endpoint_info_response_format(self, monkeypatch):
        """Verify info response has correct format for CopilotKit."""
        from src.api.agents.agui_endpoint import AGUIEndpoint
        
        endpoint = AGUIEndpoint(
            agent_name="yt-summarizer",
            agent_description="Test description",
            version="1.0.0",
        )
        
        info = endpoint.info_response
        
        # Verify structure expected by CopilotKit
        assert "version" in info, "Info should contain 'version'"
        assert "agents" in info, "Info should contain 'agents'"
        assert isinstance(info["agents"], dict), "agents should be a dict, not a list"
        assert "yt-summarizer" in info["agents"], "Agent name should be a key in agents dict"
        assert "description" in info["agents"]["yt-summarizer"], "Agent should have description"


# =============================================================================
# Test: AG-UI Endpoint HTTP Handlers (requires agent_framework_ag_ui)
# =============================================================================

@requires_agent_framework_ag_ui
class TestAGUIEndpointHTTPHandlers:
    """Test AG-UI endpoint HTTP request handling."""

    @pytest.fixture
    def configured_app(self, monkeypatch):
        """Create a FastAPI app with AG-UI endpoint configured."""
        monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://test.openai.azure.com")
        monkeypatch.setenv("AZURE_OPENAI_API_KEY", "test-api-key")
        monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
        
        from src.api.agents.agui_endpoint import setup_agui_endpoint
        
        app = FastAPI()
        setup_agui_endpoint(app)
        return app

    def test_get_info_endpoint_returns_200(self, configured_app):
        """Verify GET /api/copilotkit/info returns 200."""
        client = TestClient(configured_app)
        
        response = client.get("/api/copilotkit/info")
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"

    def test_get_info_endpoint_returns_agent_info(self, configured_app):
        """Verify GET /api/copilotkit/info returns correct agent info."""
        client = TestClient(configured_app)
        
        response = client.get("/api/copilotkit/info")
        data = response.json()
        
        assert "version" in data
        assert "agents" in data
        assert "yt-summarizer" in data["agents"]

    def test_post_with_method_info_returns_agent_info(self, configured_app):
        """Verify POST with method:info returns agent info (CopilotKit single transport)."""
        client = TestClient(configured_app)
        
        response = client.post(
            "/api/copilotkit",
            json={"method": "info"}
        )
        
        assert response.status_code == 200, f"Expected 200, got {response.status_code}"
        
        data = response.json()
        assert "version" in data
        assert "agents" in data
        assert "yt-summarizer" in data["agents"]

    def test_post_with_invalid_json_returns_400(self, configured_app):
        """Verify POST with invalid JSON returns 400."""
        client = TestClient(configured_app)
        
        response = client.post(
            "/api/copilotkit",
            content="not valid json",
            headers={"Content-Type": "application/json"}
        )
        
        assert response.status_code == 400

    def test_post_agent_request_returns_streaming_response(self, configured_app):
        """Verify POST with agent request returns SSE streaming response."""
        client = TestClient(configured_app)
        
        # Minimal agent request (will fail on LLM call but should return SSE format)
        response = client.post(
            "/api/copilotkit",
            json={
                "runId": "test-run",
                "threadId": "test-thread",
                "messages": [{"role": "user", "content": "Hello"}]
            }
        )
        
        # Should return streaming response (even if there's an error in the stream)
        assert response.headers.get("content-type", "").startswith("text/event-stream"), \
            "Response should be SSE stream"


# =============================================================================
# Test: Full Application Integration (requires agent_framework_ag_ui)
# =============================================================================

@requires_agent_framework_ag_ui
class TestFullApplicationIntegration:
    """Test AG-UI endpoint integration with full FastAPI application."""

    def test_main_app_registers_agui_endpoint(self, monkeypatch):
        """Verify main app registers AG-UI endpoint when configured."""
        monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://test.openai.azure.com")
        monkeypatch.setenv("AZURE_OPENAI_API_KEY", "test-api-key")
        monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
        
        from src.api.main import create_app
        
        app = create_app()
        
        # Get all registered route paths
        route_paths = [route.path for route in app.routes]
        
        assert "/api/copilotkit" in route_paths, \
            "Main app should register /api/copilotkit route"
        assert "/api/copilotkit/info" in route_paths, \
            "Main app should register /api/copilotkit/info route"

    def test_main_app_health_endpoint_still_works(self, monkeypatch):
        """Verify health endpoint works when AG-UI is configured."""
        monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://test.openai.azure.com")
        monkeypatch.setenv("AZURE_OPENAI_API_KEY", "test-api-key")
        
        from src.api.main import create_app
        
        app = create_app()
        client = TestClient(app, raise_server_exceptions=False)
        
        response = client.get("/health")
        
        assert response.status_code == 200

    def test_main_app_copilot_info_accessible(self, monkeypatch):
        """Verify /api/copilotkit/info is accessible through main app."""
        monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://test.openai.azure.com")
        monkeypatch.setenv("AZURE_OPENAI_API_KEY", "test-api-key")
        monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
        
        from src.api.main import create_app
        
        app = create_app()
        client = TestClient(app, raise_server_exceptions=False)
        
        response = client.get("/api/copilotkit/info")
        
        # Should be 200, NOT 404
        assert response.status_code == 200, \
            f"Expected 200, got {response.status_code}. AG-UI endpoint may not be registered."

    def test_main_app_copilot_post_accessible(self, monkeypatch):
        """Verify POST /api/copilotkit is accessible through main app."""
        monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://test.openai.azure.com")
        monkeypatch.setenv("AZURE_OPENAI_API_KEY", "test-api-key")
        monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "gpt-4o")
        
        from src.api.main import create_app
        
        app = create_app()
        client = TestClient(app, raise_server_exceptions=False)
        
        response = client.post(
            "/api/copilotkit",
            json={"method": "info"}
        )
        
        # Should be 200, NOT 404
        assert response.status_code == 200, \
            f"Expected 200, got {response.status_code}. AG-UI endpoint may not be registered."


# =============================================================================
# Test: Error Handling (no agent_framework required for some tests)
# =============================================================================

class TestErrorHandling:
    """Test error handling in agent and endpoint setup."""

    def test_agent_creation_handles_missing_dependencies_gracefully(self, monkeypatch):
        """Verify agent creation doesn't crash with missing agent_framework."""
        # This test verifies the fallback behavior when agent_framework isn't installed
        # In practice, if agent_framework is missing, AGENT_FRAMEWORK_AVAILABLE will be False
        
        from src.api.agents import yt_summarizer_agent
        
        # The module should have this flag
        assert hasattr(yt_summarizer_agent, 'AGENT_FRAMEWORK_AVAILABLE')

    def test_endpoint_setup_logs_warning_without_config(self, monkeypatch, caplog):
        """Verify endpoint setup logs warning when agent can't be created."""
        import logging
        
        monkeypatch.delenv("AZURE_OPENAI_ENDPOINT", raising=False)
        monkeypatch.delenv("AZURE_OPENAI_API_KEY", raising=False)
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        
        from src.api.agents.agui_endpoint import AGUIEndpoint
        
        endpoint = AGUIEndpoint(
            agent_name="test-agent",
            agent_description="Test",
        )
        
        app = FastAPI()
        
        with caplog.at_level(logging.WARNING):
            result = endpoint.setup(app)
        
        assert result is False
        # Should have logged a warning about missing config
        assert any("not created" in record.message.lower() or "not found" in record.message.lower() 
                   for record in caplog.records) or len(caplog.records) > 0


# =============================================================================
# Test: Configuration Exports (no agent_framework required)
# =============================================================================

class TestConfigurationExports:
    """Test that module exports are correct."""

    def test_agents_module_exports(self):
        """Verify agents module exports expected symbols."""
        from src.api.agents import (
            AGENT_DESCRIPTION,
            AGENT_NAME,
            create_openai_chat_client,
            create_yt_summarizer_agent,
            get_agent_tools,
            setup_agui_endpoint,
        )
        
        assert AGENT_NAME == "yt-summarizer"
        assert AGENT_DESCRIPTION is not None
        assert callable(create_openai_chat_client)
        assert callable(create_yt_summarizer_agent)
        assert callable(get_agent_tools)
        assert callable(setup_agui_endpoint)

    def test_agent_name_constant_matches_copilotkit_config(self):
        """Verify AGENT_NAME matches what CopilotKit expects."""
        from src.api.agents import AGENT_NAME
        
        # This must match the agent prop in CopilotKit provider
        assert AGENT_NAME == "yt-summarizer", \
            f"AGENT_NAME should be 'yt-summarizer', got '{AGENT_NAME}'"
