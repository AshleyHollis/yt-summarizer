"""Summarize worker for generating AI-powered video summaries."""

import os
from dataclasses import dataclass
from typing import Any

# Fix SSL certificate verification on Windows by using certifi's CA bundle
try:
    import certifi
    os.environ.setdefault("SSL_CERT_FILE", certifi.where())
except ImportError:
    pass  # certifi not installed, use system defaults

from shared.blob.client import (
    SUMMARIES_CONTAINER,
    TRANSCRIPTS_CONTAINER,
    compute_content_hash,
    get_blob_client,
    get_summary_blob_path,
    get_transcript_blob_path,
)
from shared.config import get_settings
from shared.db.connection import get_db
from shared.db.job_service import mark_job_completed, mark_job_failed, mark_job_running
from shared.db.models import Artifact, Job, Video
from shared.logging.config import get_logger
from shared.queue.client import EMBED_QUEUE, SUMMARIZE_QUEUE, get_queue_client
from shared.telemetry.config import inject_trace_context
from shared.worker.base_worker import BaseWorker, WorkerResult, run_worker

logger = get_logger(__name__)

# Summarization prompt template
SUMMARIZE_PROMPT = """Analyze and summarize this YouTube video transcript. First, identify the content type, then create a structured summary tailored to that type.

## Content Type
Identify ONE primary type: News, Tutorial, Product Review, Educational, Entertainment, Music, Documentary, Interview, Vlog, Gaming, or Other.

## Main Topic
One sentence describing what the video covers.

## Key Points
1. First key point (most important information or insight)
2. Second key point
3. Third key point
(Include up to 5 key points for longer/denser content)

## Notable Quotes
Include 1-3 memorable or important quotes from the transcript. Use "quote" format.

## Watch This If...
One sentence describing who would benefit from this video (e.g., "Watch this if you want to understand X" or "Skip if you already know Y").

## Key Takeaways
(ONLY include this section if the content has actionable advice, lessons, or recommendations. Skip entirely for news reports, music videos, entertainment, or purely informational content.)
1. First actionable takeaway the viewer can apply
2. Second actionable takeaway
3. Third actionable takeaway

## Summary
Two to three paragraphs providing a narrative overview. Focus on:
- The main argument or story arc
- Important context not captured in key points
- How the content concludes or what it leads to

FORMATTING RULES:
- Start each section with ## followed by the exact header name
- Use numbered lists (1. 2. 3.) for Key Points and Key Takeaways
- Write prose paragraphs for Summary section
- Do NOT use ** for headers or section titles
- Do NOT use bullet points (-) anywhere except in the Summary section if needed for clarity
- For Notable Quotes, use quotation marks around the text

CONTENT TYPE GUIDELINES:
- News: Focus on who, what, when, where, why. Skip Key Takeaways unless there are clear lessons.
- Tutorial/How-To: Emphasize steps, prerequisites, and Key Takeaways with actionable items.
- Product Review: Highlight pros/cons, comparisons, and specific recommendations.
- Educational: Include Key Takeaways with learning outcomes and concepts to remember.
- Music: Focus on themes, lyrics interpretation, musical elements. Skip Key Takeaways.
- Entertainment: Describe the content, style, and appeal. Key Takeaways optional.

Transcript:
{transcript}

Your markdown summary:"""


@dataclass
class SummarizeMessage:
    """Message payload for summarize jobs."""

    job_id: str
    video_id: str
    youtube_video_id: str
    channel_name: str
    correlation_id: str
    batch_id: str | None = None
    retry_count: int = 0


class SummarizeWorker(BaseWorker[SummarizeMessage]):
    """Worker for generating AI-powered video summaries."""

    @property
    def queue_name(self) -> str:
        """Return the queue name."""
        return SUMMARIZE_QUEUE

    def get_additional_connectivity_checks(self) -> dict[str, Any]:
        """Add OpenAI connectivity check since this worker requires it for summarization."""
        return {"openai": self._check_openai_connectivity}

    def parse_message(self, raw_message: dict[str, Any]) -> SummarizeMessage:
        """Parse raw message to SummarizeMessage."""
        return SummarizeMessage(
            job_id=raw_message["job_id"],
            video_id=raw_message["video_id"],
            youtube_video_id=raw_message["youtube_video_id"],
            channel_name=raw_message.get("channel_name", "unknown-channel"),
            correlation_id=raw_message.get("correlation_id", "unknown"),
            batch_id=raw_message.get("batch_id"),
            retry_count=raw_message.get("retry_count", 0),
        )

    async def process_message(
        self,
        message: SummarizeMessage,
        correlation_id: str,
    ) -> WorkerResult:
        """Process a summarize job.

        1. Fetch transcript from blob storage
        2. Call OpenAI API to generate summary
        3. Store summary in blob storage
        4. Create artifact record
        5. Update job status
        6. Queue next job (embed)
        """
        logger.info(
            "Processing summarize job",
            job_id=message.job_id,
            video_id=message.video_id,
        )

        try:
            # Mark job as running
            await mark_job_running(message.job_id, "summarizing")

            # Fetch transcript (using channel-based blob path)
            transcript = await self._fetch_transcript(
                message.channel_name,
                message.youtube_video_id,
            )

            if not transcript:
                await mark_job_failed(message.job_id, "Could not find transcript in blob storage")
                return WorkerResult.failed(
                    Exception("Transcript not found"),
                    "Could not find transcript in blob storage",
                )

            # Generate summary
            summary, error = await self._generate_summary(transcript)

            if not summary:
                error_msg = error or "OpenAI API failed to generate summary"
                # Truncate error message for database (max 4000 chars for SQL Server nvarchar)
                if len(error_msg) > 4000:
                    error_msg = error_msg[:3997] + "..."
                await mark_job_failed(message.job_id, error_msg)
                return WorkerResult.failed(
                    Exception("Summary generation failed"),
                    error_msg,
                )

            # Store summary (using channel-based blob path)
            blob_uri = await self._store_summary(
                message.channel_name,
                message.youtube_video_id,
                summary,
            )

            # Create artifact record
            await self._create_artifact(
                message.video_id,
                blob_uri,
                summary,
            )

            # Mark job as completed
            await mark_job_completed(message.job_id)

            # Queue next job (embed)
            await self._queue_next_job(message, correlation_id)

            logger.info(
                "Summarize job completed",
                job_id=message.job_id,
                summary_length=len(summary),
            )

            return WorkerResult.success(
                message="Summary generated successfully",
                data={"summary_length": len(summary), "blob_uri": blob_uri},
            )

        except Exception as e:
            logger.exception("Summarize job failed", job_id=message.job_id)
            await mark_job_failed(message.job_id, str(e))
            return WorkerResult.failed(e)

    async def _fetch_transcript(
        self,
        channel_name: str,
        youtube_video_id: str,
    ) -> str | None:
        """Fetch transcript from blob storage.
        
        Uses channel-based blob path organization:
        {sanitized_channel_name}/{youtube_video_id}/transcript.txt
        """
        try:
            blob_client = get_blob_client()
            blob_name = get_transcript_blob_path(channel_name, youtube_video_id)
            content = blob_client.download_blob(TRANSCRIPTS_CONTAINER, blob_name)
            return content.decode("utf-8")
        except Exception as e:
            logger.error(
                "Failed to fetch transcript",
                error=str(e),
                channel_name=channel_name,
                youtube_video_id=youtube_video_id,
                blob_name=get_transcript_blob_path(channel_name, youtube_video_id),
            )
            return None

    async def _generate_summary(self, transcript: str) -> tuple[str | None, str | None]:
        """Generate summary using OpenAI API.
        
        Returns:
            Tuple of (summary, error_message). If successful, summary is set and error is None.
            If failed, summary is None and error_message contains the failure reason.
        """
        settings = get_settings()
        
        # DEBUG: Log the API key check
        logger.info(
            "DEBUG: _generate_summary API key check",
            api_key_repr=repr(settings.openai.api_key),
            is_azure_configured=settings.openai.is_azure_configured,
            is_azure_ai_foundry=settings.openai.is_azure_ai_foundry,
            azure_openai_base_url=settings.openai.azure_openai_base_url,
            effective_api_key_set=bool(settings.openai.effective_api_key),
        )
        
        # Check if any OpenAI configuration is available (Azure or standard)
        has_valid_config = (
            settings.openai.is_azure_configured or 
            (settings.openai.api_key and settings.openai.api_key != "not-configured")
        )
        
        if not has_valid_config:
            logger.warning("OpenAI API key not configured - generating mock summary for testing")
            # Provide a mock summary for testing without API key
            preview = transcript[:500] + "..." if len(transcript) > 500 else transcript
            return (f"""# Video Summary (Mock)

**Note**: This is a mock summary generated because no OpenAI API key is configured.

## Main Topic
This video discusses topics covered in the transcript.

## Key Points
- The transcript contains {len(transcript)} characters of content
- Full AI summarization requires an OpenAI API key
- Set the OPENAI_API_KEY environment variable to enable real summaries

## Transcript Preview
{preview}

## Summary
This is a placeholder summary for testing purposes. Configure an OpenAI API key to generate real AI-powered summaries.
""", None)
        
        try:
            # Use Azure OpenAI if configured, otherwise use standard OpenAI
            if settings.openai.is_azure_configured:
                base_url = settings.openai.azure_openai_base_url
                model = settings.openai.azure_deployment or "gpt-4o-mini"
                
                # Azure AI Foundry uses OpenAI-compatible API with /models endpoint
                if settings.openai.is_azure_ai_foundry:
                    from openai import AsyncOpenAI
                    
                    client = AsyncOpenAI(
                        api_key=settings.openai.effective_api_key,
                        base_url=base_url,
                        default_headers={"api-key": settings.openai.effective_api_key},
                    )
                    logger.info(
                        "Using Azure AI Foundry for summarization",
                        original_endpoint=settings.openai.azure_endpoint,
                        base_url=base_url,
                        model=model,
                    )
                else:
                    # Standard Azure OpenAI
                    from openai import AsyncAzureOpenAI
                    
                    client = AsyncAzureOpenAI(
                        api_key=settings.openai.effective_api_key,
                        azure_endpoint=base_url,
                        api_version=settings.openai.azure_api_version,
                    )
                    logger.info(
                        "Using Azure OpenAI for summarization",
                        original_endpoint=settings.openai.azure_endpoint,
                        base_url=base_url,
                        deployment=model,
                    )
            else:
                from openai import AsyncOpenAI
                
                client = AsyncOpenAI(api_key=settings.openai.api_key)
                model = settings.openai.model

            # Truncate transcript if too long (GPT-4o-mini has 128k context)
            # Use tiktoken for accurate token counting instead of character count
            max_tokens = 100000  # Leave room for system prompt and response
            try:
                import tiktoken
                encoding = tiktoken.encoding_for_model(model)
                tokens = encoding.encode(transcript)
                if len(tokens) > max_tokens:
                    original_token_count = len(tokens)
                    tokens = tokens[:max_tokens]
                    transcript = encoding.decode(tokens) + "..."
                    logger.warning(
                        "Transcript truncated",
                        original_tokens=original_token_count,
                        max_tokens=max_tokens,
                    )
            except Exception as e:
                # Fallback to conservative character-based truncation if tiktoken fails
                # Assume ~4 characters per token as a conservative estimate
                max_chars = max_tokens * 4
                if len(transcript) > max_chars:
                    logger.warning(
                        "Transcript truncated (fallback char-based, tiktoken error: %s)",
                        str(e),
                        original_length=len(transcript),
                        max_chars=max_chars,
                    )
                    transcript = transcript[:max_chars] + "..."

            # Build request parameters - newer models use max_completion_tokens instead of max_tokens
            request_params = {
                "model": model,
                "messages": [
                    {
                        "role": "system",
                        "content": "You are an expert at summarizing video content.",
                    },
                    {
                        "role": "user",
                        "content": SUMMARIZE_PROMPT.format(transcript=transcript),
                    },
                ],
            }
            
            # Azure AI Foundry models (like gpt-5) use max_completion_tokens
            # Standard models use max_tokens
            if settings.openai.is_azure_ai_foundry:
                request_params["max_completion_tokens"] = 4096
            else:
                request_params["max_tokens"] = 4096
                request_params["temperature"] = 0.7

            response = await client.chat.completions.create(**request_params)

            summary = response.choices[0].message.content
            return (summary, None)

        except Exception as e:
            import traceback
            error_details = f"{type(e).__name__}: {str(e)}"
            full_traceback = traceback.format_exc()
            logger.error(
                "OpenAI API call failed",
                error=str(e),
                error_type=type(e).__name__,
                traceback=full_traceback,
            )
            return (None, f"{error_details}\n\nTraceback:\n{full_traceback}")

    async def _store_summary(
        self,
        channel_name: str,
        youtube_video_id: str,
        summary: str,
    ) -> str:
        """Store summary in blob storage.
        
        Uses channel-based blob path organization:
        {sanitized_channel_name}/{youtube_video_id}/summary.md
        """
        blob_client = get_blob_client()
        blob_name = get_summary_blob_path(channel_name, youtube_video_id)

        uri = blob_client.upload_blob(
            SUMMARIES_CONTAINER,
            blob_name,
            summary.encode("utf-8"),
            content_type="text/markdown",
        )

        return uri

    async def _create_artifact(
        self,
        video_id: str,
        blob_uri: str,
        summary: str,
    ) -> None:
        """Create artifact record in database."""
        from uuid import UUID

        db = get_db()
        async with db.session() as session:
            from sqlalchemy import select

            # Check if artifact already exists
            result = await session.execute(
                select(Artifact).where(
                    Artifact.video_id == UUID(video_id),
                    Artifact.artifact_type == "summary",
                )
            )
            existing = result.scalar_one_or_none()

            if existing:
                # Update existing artifact
                existing.blob_uri = blob_uri
                existing.content_length = len(summary)
                existing.content_hash = compute_content_hash(summary.encode("utf-8"))
            else:
                # Create new artifact
                artifact = Artifact(
                    video_id=UUID(video_id),
                    artifact_type="summary",
                    blob_uri=blob_uri,
                    content_length=len(summary),
                    content_hash=compute_content_hash(summary.encode("utf-8")),
                )
                session.add(artifact)

    async def _queue_next_job(
        self,
        message: SummarizeMessage,
        correlation_id: str,
    ) -> None:
        """Queue the next job (embed)."""
        from uuid import UUID

        db = get_db()
        async with db.session() as session:
            # Create embed job
            job = Job(
                video_id=UUID(message.video_id),
                batch_id=UUID(message.batch_id) if message.batch_id else None,
                job_type="embed",
                stage="queued",
                status="pending",
                correlation_id=correlation_id,
            )
            session.add(job)
            await session.flush()

            # Queue the job
            queue_client = get_queue_client()
            queue_message = inject_trace_context({
                "job_id": str(job.job_id),
                "video_id": message.video_id,
                "youtube_video_id": message.youtube_video_id,
                "channel_name": message.channel_name,
                "correlation_id": correlation_id,
            })
            if message.batch_id:
                queue_message["batch_id"] = message.batch_id
            
            queue_client.send_message(EMBED_QUEUE, queue_message)

            logger.info("Queued embed job", job_id=str(job.job_id))


def main():
    """Run the summarize worker."""
    worker = SummarizeWorker()
    run_worker(worker)


if __name__ == "__main__":
    main()
