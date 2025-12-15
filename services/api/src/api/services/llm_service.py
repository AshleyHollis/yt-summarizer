"""LLM service for Azure OpenAI chat completions.

Provides a wrapper around Azure OpenAI for copilot query processing.
"""

import json
from typing import Any

from openai import AsyncAzureOpenAI, AsyncOpenAI

# Import shared modules
try:
    from shared.config import get_settings
    from shared.logging.config import get_logger
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


logger = get_logger(__name__)


COPILOT_SYSTEM_PROMPT = """You are a helpful assistant that answers questions about YouTube video content.

You have access to a library of transcribed and summarized YouTube videos. Your role is to:
1. Answer questions based ONLY on the provided evidence from video transcripts
2. Always cite your sources with video titles and timestamps
3. If you don't have enough information to answer, say so clearly
4. Never make claims that aren't supported by the evidence
5. Be concise but thorough

When providing answers:
- Reference specific videos and timestamps
- Quote relevant segments when helpful
- Suggest follow-up questions the user might want to ask
- Indicate your confidence level if the evidence is limited

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
    endpoint = endpoint.rstrip('/')
    
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
            # Check for Azure OpenAI configuration
            azure_endpoint = self.settings.openai.azure_endpoint
            
            if azure_endpoint:
                # Use Azure OpenAI with corrected endpoint for AI Foundry
                base_url = _build_azure_openai_base_url(azure_endpoint)
                logger.debug(f"Using Azure OpenAI with base_url: {base_url}")
                self._client = AsyncAzureOpenAI(
                    api_key=self.settings.openai.effective_api_key,
                    azure_endpoint=base_url,
                    api_version=self.settings.openai.azure_api_version,
                )
            else:
                # Use OpenAI directly
                self._client = AsyncOpenAI(
                    api_key=self.settings.openai.effective_api_key,
                )
        
        return self._client
    
    async def get_embedding(self, text: str) -> list[float]:
        """Get embedding vector for text.
        
        Args:
            text: The text to embed.
            
        Returns:
            Embedding vector (1536 dimensions for text-embedding-3-small).
        """
        try:
            response = await self.client.embeddings.create(
                model=self.settings.openai.embedding_model,
                input=text,
            )
            return response.data[0].embedding
        except Exception as e:
            logger.error(f"Failed to get embedding: {e}")
            raise
    
    async def generate_answer(
        self,
        query: str,
        evidence: list[dict[str, Any]],
        video_context: list[dict[str, Any]] | None = None,
        conversation_history: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        """Generate an answer based on the query and evidence.
        
        Args:
            query: The user's question.
            evidence: List of evidence segments with text, video info, timestamps.
            video_context: Optional list of relevant videos with summaries.
            conversation_history: Optional previous messages in the conversation.
            
        Returns:
            Dict with answer, citations, follow-ups, and uncertainty.
        """
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
        
        # Build the user message with evidence
        user_message = f"""Based on the following evidence from the video library, please answer this question:

QUESTION: {query}

EVIDENCE FROM VIDEO TRANSCRIPTS:
{evidence_text}

{f"VIDEO SUMMARIES:{chr(10)}{video_context_text}" if video_context_text else ""}

Please provide:
1. A clear, concise answer citing specific videos and timestamps
2. Your confidence level (high/medium/low) based on the evidence quality
3. 2-3 suggested follow-up questions

If the evidence is insufficient to answer the question, explain what information is missing.

Respond in JSON format:
{{
    "answer": "your answer with inline citations like [Video Title, 2:30]",
    "confidence": "high|medium|low",
    "cited_videos": ["video_id1", "video_id2"],
    "follow_ups": ["follow-up question 1", "follow-up question 2"],
    "uncertainty": "null or explanation of what's missing"
}}"""
        
        messages.append({"role": "user", "content": user_message})
        
        try:
            response = await self.client.chat.completions.create(
                model=self.settings.openai.model,
                messages=messages,
                max_tokens=self.settings.openai.max_tokens,
                temperature=self.settings.openai.temperature,
                response_format={"type": "json_object"},
            )
            
            content = response.choices[0].message.content
            result = json.loads(content)
            
            return {
                "answer": result.get("answer", "I couldn't generate an answer."),
                "confidence": result.get("confidence", "low"),
                "cited_videos": result.get("cited_videos", []),
                "follow_ups": result.get("follow_ups", []),
                "uncertainty": result.get("uncertainty"),
            }
        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse LLM response as JSON: {e}")
            # Return the raw content as answer
            return {
                "answer": response.choices[0].message.content if response else "Failed to generate answer",
                "confidence": "low",
                "cited_videos": [],
                "follow_ups": [],
                "uncertainty": "Response format was unexpected",
            }
        except Exception as e:
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
        topics_context = ""
        if available_topics:
            topics_context = f"\nAvailable topics in the library: {', '.join(available_topics[:20])}"
        
        prompt = f"""Given this Q&A exchange, suggest 3 natural follow-up questions the user might want to ask.
{topics_context}

Original Question: {query}
Answer: {answer}

Return a JSON array of 3 follow-up questions:
["question 1", "question 2", "question 3"]"""
        
        try:
            response = await self.client.chat.completions.create(
                model=self.settings.openai.model,
                messages=[
                    {"role": "system", "content": "You suggest helpful follow-up questions."},
                    {"role": "user", "content": prompt},
                ],
                max_tokens=256,
                temperature=0.7,
                response_format={"type": "json_object"},
            )
            
            content = response.choices[0].message.content
            # Parse JSON - might be wrapped in an object
            parsed = json.loads(content)
            
            if isinstance(parsed, list):
                return parsed[:3]
            elif isinstance(parsed, dict):
                # Look for an array in the response
                for key, value in parsed.items():
                    if isinstance(value, list):
                        return value[:3]
            
            return []
        except Exception as e:
            logger.warning(f"Failed to generate follow-ups: {e}")
            return []
    
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
            
            formatted.append(f"[{i}] {video_title} at {timestamp}:\n\"{text}\"")
        
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
