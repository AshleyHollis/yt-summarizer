# Product Specification: YT Summarizer

**Feature Branch**: `001-product-spec`  
**Created**: 2025-12-13  
**Status**: Draft  
**Input**: Product specification for YT Summarizer — transcribe, summarize, and explore YouTube videos

---

## Overview

YT Summarizer transforms selected YouTube videos and channels into a personal, searchable knowledge library. Users can ask questions that span single videos or entire channels, receive answers grounded in timestamped evidence, and discover connections between content.

**One-line description**: Ask questions, extract insights, and discover connections across your YouTube library.

---

## Personas

### Primary User: Power User (Solo)

A single user who curates a personal library of YouTube content for learning, reference, or research. Values:

- **Accurate citations**: Needs to trust answers with timestamped evidence
- **Cross-content discovery**: Wants to find themes across videos/channels
- **Control over ingestion**: Decides what enters the library
- **Transparency**: Understands what the system knows and doesn't know

### Secondary: Shared Access (Future)

Potential to share the library read-only with a handful of friends. Not in initial scope.

---

## Scope & Non-Goals

### In Scope

- Ingest individual videos or batch-ingest from channels
- Transcribe, summarize, chunk, embed, and extract relationships
- Browse library with filters (channel, time, tags/facets)
- Query via copilot with scope controls and citation-backed answers
- Transparency features ("why this recommendation?")
- Domain-agnostic design (supports any topic, not workout-specific)

### Explicit Non-Goals

- **Copilot writes nothing**: The in-app copilot is strictly read-only. It MUST NOT create batches, trigger processing, write to the database, or modify graph/vector data.
- **Web search is optional**: Web search is available as a knowledge source toggle but disabled by default. Users can enable it when they want current information from the internet.
- **No massive scale optimization**: Design for ~1,500 videos and ~15,000 segments. Keep hobby-appropriate.
- **No multi-tenant architecture**: Single-user system (with potential future read-sharing).

### Constraints (acknowledged, not specified as implementation)

- Frontend: Next.js on Azure Static Web Apps
- Backend: Azure Container Apps with .NET Aspire orchestration; Python (API + Workers)
- Data: Single Azure SQL Database (serverless) for operational data, vectors, and relationships
- Blob storage for large artifacts; queue for background processing
- Identity: Azure Entra ID with Managed Identity
- Security: No API authentication enforced; trust network boundary only (container-to-container communication within Azure Container Apps environment)
- LLM: Azure OpenAI — GPT-4o for chat/summarization, text-embedding-3-small for embeddings

---

## User Scenarios & Testing

### User Story 1 — Ingest a Single Video (Priority: P1)

User submits a YouTube URL and watches it progress through transcription, summarization, embedding, and relationship extraction. When complete, the video appears in the library with viewable summary, transcript, and key segments.

**Why this priority**: Core value. Without ingestion, there's nothing to query.

**Independent Test**: Submit one URL, wait for completion, view the video detail page with summary and transcript.

**Acceptance Scenarios**:

1. **Given** an empty library, **When** user submits a valid YouTube URL, **Then** the system queues the video, shows progress stages (transcribe → summarize → embed → build relationships), and marks it complete when done.

2. **Given** a video in progress, **When** user views the jobs page, **Then** they see current stage, elapsed time, and estimated remaining time (if available).

3. **Given** a completed video, **When** user opens the video detail page, **Then** they see: title, thumbnail, duration, summary, full transcript, and key segments with timestamps.

4. **Given** a failed ingestion, **When** user views the video in the library, **Then** they see a clear error message and a "Retry" button (not via chat).

5. **Given** a video URL that's already ingested, **When** user submits it again, **Then** the system either skips (if unchanged) or offers to reprocess (if user chooses).

---

### User Story 2 — Ingest from a Channel (Batch) (Priority: P2)

User provides a channel URL/ID, browses available videos, and either selects specific videos or chooses to ingest the entire channel. They see batch progress and per-video status.

**Why this priority**: Enables building a library at scale, but depends on single-video ingestion working first.

**Independent Test**: Submit a channel, select 5 videos OR choose "Ingest All", start batch, verify all selected/all videos complete.

**Acceptance Scenarios**:

1. **Given** a channel URL/ID, **When** user submits it, **Then** the system fetches the channel's video list and displays them for selection, with an "Ingest All Videos" option.

2. **Given** a list of channel videos, **When** user selects multiple and clicks "Start Batch", **Then** a batch is created and each selected video is queued.

3. **Given** a list of channel videos, **When** user clicks "Ingest All Videos", **Then** a batch is created containing all videos from the channel.

4. **Given** an active batch, **When** user views the batch status page, **Then** they see: total count, completed count, failed count, and per-video status rows.

5. **Given** some videos in the batch fail, **When** user views the batch, **Then** they can retry failed videos individually or all-at-once (not via chat).

6. **Given** a batch completes, **When** user views "Ready to Review" list, **Then** they see all newly-ingested videos with links to detail pages.

7. **Given** a channel previously ingested, **When** user submits it again, **Then** the system shows which videos are new, which are already ingested, and offers to ingest only new videos or reprocess all.

---

### User Story 3 — Browse the Library (Priority: P2)

User filters the library by channel, time range, and generic facets (topic/tags). They can open any video's detail page.

**Why this priority**: Users need to navigate and find content. Parallel priority with batch ingestion.

**Independent Test**: With 10+ ingested videos, filter by channel, verify correct results, open a detail page.

**Acceptance Scenarios**:

1. **Given** a library with videos from multiple channels, **When** user applies a channel filter, **Then** only videos from that channel appear.

2. **Given** a library with videos over time, **When** user applies a date range filter, **Then** only videos published within that range appear.

3. **Given** videos with extracted tags/facets, **When** user clicks a tag chip, **Then** only videos with that tag appear.

4. **Given** filter results, **When** user clicks a video card, **Then** they navigate to the video detail page.

5. **Given** the video detail page, **When** user views it, **Then** they see: summary, transcript, segments with timestamps (clickable to YouTube), and any extracted metadata/tags.

---

### User Story 4 — Query with the Copilot (Priority: P1)

User asks a question scoped to a channel or the whole library. The UI shows scope, the answer includes citations, and the user can adjust scope and re-query.

**Why this priority**: Core value proposition — asking questions is why users ingest content.

**Independent Test**: With 5+ ingested videos, ask a question, receive an answer with citations and video cards.

**Acceptance Scenarios**:

1. **Given** ingested content, **When** user types a question, **Then** the copilot returns: a short answer, recommended videos (as cards), and evidence citations (timestamped snippets).

2. **Given** a query, **When** the answer is displayed, **Then** the UI shows the "Scope" that was searched (channels, time range, content types) as chips.

3. **Given** scope chips, **When** user changes scope (e.g., selects a different channel), **Then** the query re-runs with the new scope and results update.

4. **Given** an answer with citations, **When** user clicks a citation, **Then** they see the segment text and can click through to the video at that timestamp.

5. **Given** insufficient ingested content, **When** user asks a question, **Then** the copilot responds: "I don't have enough information on this topic in your library" and suggests ingesting more via the normal UI (no ingestion from chat).

6. **Given** any answer, **When** user views it, **Then** follow-up suggestion buttons are displayed (e.g., "Show more from this channel", "Find related videos").

7. **Given** a query, **When** user clicks "Topics in Scope", **Then** a panel shows top facets/concepts with counts relevant to current scope.

---

### User Story 5 — "Explain Why" (Transparency) (Priority: P3)

For any recommended video, user can see why it was recommended — similarity basis, relationship basis, and exact evidence segments.

**Why this priority**: Builds trust but depends on query working first.

**Independent Test**: After a query, click "Why this?" on a video card, see explanation with evidence links.

**Acceptance Scenarios**:

1. **Given** a recommended video in query results, **When** user clicks "Why this?", **Then** a panel shows: similarity basis (which summary/segment matched), relationship basis (if any stored), and evidence segment snippets.

2. **Given** the explanation panel, **When** user clicks an evidence segment, **Then** they navigate to that video at the relevant timestamp.

3. **Given** a video with stored relationships to other videos, **When** user views "Why this?", **Then** the panel shows relationship type (e.g., "same series", "related topic") and which segment/metadata established it.

---

### User Story 6 — Synthesize Structured Outputs (Priority: P3)

User asks the copilot to create a structured output (e.g., a learning path, a progression program, a watch list) synthesized from library content.

**Why this priority**: High value but depends on relationships and broad queries working.

**Independent Test**: With 10+ related videos ingested, ask for a "progression" or "learning path", receive a structured list with citations.

**Acceptance Scenarios**:

1. **Given** multiple related videos, **When** user asks "Build a learning path for X from this channel", **Then** the copilot returns an ordered list of videos with rationale for the order.

2. **Given** a synthesized output, **When** user views it, **Then** each item cites the evidence (segments, relationships) that informed its position.

3. **Given** a synthesized output, **When** content is insufficient, **Then** the copilot states what's missing and suggests ingesting more (via UI, not chat).

---

### Edge Cases

- **Duplicate URL submission**: System detects already-ingested videos and offers skip or reprocess options.
- **Video unavailable**: If YouTube returns 404 or private, system marks job as failed with clear message.
- **Partial transcript**: If transcription is incomplete, system marks it and shows what's available.
- **Serverless DB cold start**: API retries with timeout; UI shows "Warming up..." instead of error.
- **Empty query scope**: If user narrows scope to zero videos, system explains and suggests broadening.
- **Very long video**: System handles gracefully (may take longer); shows progress.
- **Rate limiting**: If YouTube or AI provider rate-limits, system queues retries with backoff.

---

## Requirements

### Functional Requirements

#### Ingestion & Processing

- **FR-001**: System MUST accept a YouTube video URL and queue it for processing.
- **FR-002**: System MUST process videos through stages: transcript acquisition → summarization → chunking + embedding → relationship extraction.
- **FR-003**: System MUST expose per-video job status: pending, running (with stage), succeeded, failed (with error).
- **FR-004**: System MUST allow retry of failed jobs from the UI (not via chat).
- **FR-005**: System MUST support batch ingestion from a channel with per-video status tracking. Channel video lists are fetched via yt-dlp extraction (no YouTube API key required). UI displays up to 100 videos initially with "Load More" pagination; "Ingest All" queues all videos via backend cursor.
- **FR-006**: System MUST NOT duplicate segments or embeddings on reprocessing (upsert semantics).

#### Library & Browsing

- **FR-007**: System MUST provide library browse with filters: channel, time range, tags/facets.
- **FR-008**: System MUST display video detail pages with: title, summary, transcript, segments with timestamps, and extracted metadata.
- **FR-009**: System MUST support pagination for library results (hobby-appropriate: optimize for ~1,500 videos).

#### Copilot & Queries

- **FR-010**: Copilot MUST be read-only — it MUST NOT trigger ingestion, modify data, or execute side effects.
- **FR-011**: Copilot MUST provide AI Knowledge Settings to control knowledge sources:
  - **Your Videos** (Video Context): Toggle to search the ingested video library via RAG retrieval.
  - **AI Knowledge** (LLM Knowledge): Toggle to include LLM's general trained knowledge in answers.
  - **Web Search**: Toggle to enable live web search for current information (disabled by default).
- **FR-011a**: When "Your Videos" is disabled but "AI Knowledge" is enabled, copilot answers using only LLM knowledge with an uncertainty indicator.
- **FR-011b**: When both "Your Videos" and "AI Knowledge" are disabled, copilot returns an error message requesting at least one knowledge source.
- **FR-012**: All copilot answers MUST include citations with video + timestamp references (when using video context).
- **FR-013**: Copilot MUST display query scope (channels, time range, content types) visibly in the UI.
- **FR-014**: Copilot MUST allow scope adjustment via chips and re-run queries.
- **FR-015**: Copilot MUST state uncertainty when content is insufficient and suggest ingesting more (via UI).
- **FR-016**: Copilot MAY generate structured outputs (learning paths, watch lists) from library content.

#### Transparency & Provenance

- **FR-017**: System MUST provide "Why this?" explanation for recommended videos showing similarity basis and evidence segments.
- **FR-018**: System MUST store relationships between videos with: type, confidence, rationale, evidence pointer.
- **FR-019**: Derived artifacts (summaries, embeddings) SHOULD store traceability metadata (timestamp, model, parameters) for debugging.

#### Error Handling & Resilience

- **FR-020**: System MUST handle Azure SQL serverless wake-up latency with retries and user-friendly "Warming up" messaging.
- **FR-021**: System MUST implement retry with exponential backoff for transient failures.
- **FR-022**: System MUST dead-letter failed jobs after max retries with diagnostic context.

#### Observability

- **FR-023**: System MUST propagate correlation IDs from UI → API → workers.
- **FR-024**: System MUST expose job timelines and processing history in the UI.
- **FR-025**: System MUST emit structured logs (JSON) with queryable fields.

---

### Key Entities

- **Channel**: A YouTube channel. Has: channel ID, name, thumbnail, last synced date, video count.

- **Video**: A YouTube video. Has: video ID, channel reference, title, description, duration, publish date, thumbnail, processing status.

- **Batch**: A group of videos queued together. Has: batch ID, channel reference (optional), created date, video count, status counts (pending/running/succeeded/failed).

- **Job**: A processing task for a video. Has: job ID, video reference, batch reference (optional), stage, status, started/completed timestamps, error message, correlation ID.

- **Artifact**: A derived output (transcript, summary). Has: artifact ID, video reference, type (transcript/summary), content reference (inline or blob), created date, traceability metadata (model, parameters).

- **Segment**: A chunk of transcript with embedding. Has: segment ID, video reference, start/end timestamps, text, embedding vector.

- **Relationship**: A connection between videos or concepts. Has: relationship ID, source video, target video (or concept), type (series/progression/related/references), confidence, rationale, evidence segment reference.

- **Facet/Tag**: Generic metadata attached to videos. Has: facet ID, name, type (topic/format/level/language/etc.), video references.

---

## Copilot UX Requirements

### Read-Only Boundary (Hard Rule)

The copilot is a query interface only. It:

- ✅ Queries videos, transcripts, summaries, segments, relationships
- ✅ Returns answers with citations
- ✅ Suggests related videos and viewing sequences
- ✅ Generates structured outputs (learning paths, watch lists) from library content
- ❌ NEVER triggers ingestion or reprocessing
- ❌ NEVER writes to the database
- ❌ NEVER modifies relationships or embeddings
- ❌ NEVER searches live web or YouTube API

### Conversation History

- Chat history MUST persist in browser localStorage (survives page refresh)
- History SHOULD be cleared on explicit logout or browser storage clear
- No server-side chat history storage required

### Scope Visibility

- Current scope MUST be visible as chips in the chat thread (channels, time range, content types)
- User MUST be able to adjust scope and re-run
- A "Topics in Scope" panel MUST show top facets/concepts with counts
- Coverage indicators SHOULD show: indexed video count, segment count, last updated time

### AI Knowledge Settings

The copilot provides three toggleable knowledge sources in the UI header:

- **Search scope selector**: "All Videos" | "This Channel" | "This Video"
  - Contextually shows all options when viewing a video
  - Shows only "All Videos" when on library pages
  
- **Knowledge source toggles** (Include:):
  - **Your Videos**: Search transcripts & summaries from the video library (RAG retrieval). Enabled by default.
  - **AI Knowledge**: Include AI's general trained knowledge in answers. Enabled by default.
  - **Web Search**: Search the web for current information. Disabled by default.

- **Help panel**: Expandable (i) button with clear explanations of each option

Behavior:
- All settings persist in React context (session-scoped)
- Settings are passed to the API with each query request
- When "Your Videos" is disabled, no RAG retrieval is performed
- When "AI Knowledge" is disabled with videos, LLM only synthesizes from evidence
- When both are disabled, an error message is returned

### Citation Format

Every answer MUST include:

- Short response text
- Recommended videos (as cards)
- Evidence citations (segment text + video + timestamp, clickable)
- Optional follow-up suggestion buttons

### Grounding Requirement

- Every factual claim MUST be grounded in stored evidence
- If grounding is not possible, state uncertainty explicitly
- If content is insufficient, say so and suggest ingesting more (via UI, not chat)

---

## Processing Pipeline Requirements

### Stages

1. **Transcript Acquisition**: Fetch or generate transcript. Store as artifact.
2. **Summarization**: Generate summary from transcript. Store as artifact.
3. **Chunking + Embedding**: Split transcript into segments, generate embeddings. Store as segments.
4. **Relationship Extraction**: Identify connections to other videos (series, progression, same-topic). Store as relationships.

### Idempotency & Traceability

- Each video has exactly one summary, one set of embeddings, etc. (one artifact per source).
- Reprocessing MUST upsert (not duplicate) segments and relationships — overwrites previous version.
- Derived artifacts SHOULD store traceability metadata (timestamp, model, parameters) for debugging, not for maintaining multiple versions.

### Retry & Dead-Letter

- Transient failures MUST retry with exponential backoff.
- After max retries, job MUST be dead-lettered with diagnostic context.
- Dead-lettered jobs MUST be visible in UI with error details.

### Job Status Exposure

- Jobs MUST expose: pending, running (with current stage), succeeded, failed (with error).
- Job timelines MUST be visible in UI (started, stage transitions, completed).

---

## Observability & Quality Requirements

### Correlation IDs

- Every user action MUST generate a correlation ID at the frontend.
- Correlation ID MUST propagate through API → workers → database operations.
- Logs MUST include correlation ID for end-to-end tracing.

### Structured Logging

- All components MUST emit JSON-formatted logs.
- Logs MUST include: timestamp, level, correlation ID, component, message, relevant IDs.

### Distributed Traces

- System SHOULD support distributed tracing (OpenTelemetry or similar).
- Traces SHOULD be queryable by correlation ID.

### Metrics (Recommended, Not Required Initially)

- Request counts, latencies, queue depth, error rates.
- Job processing times by stage.

### Performance Bounds (Hobby-Appropriate)

- Library should handle ~1,500 videos and ~15,000 segments responsively.
- All queries MUST be bounded (top-K limits, pagination).
- Sensible defaults: 10 results per page, 50 max per request.

---

## Success Criteria

### Measurable Outcomes

- **SC-001**: User can ingest a video and view its summary within 5 minutes of submission (for typical 10-minute video).
- **SC-002**: User can ask a question and receive a cited answer within 3 seconds (excluding DB cold start).
- **SC-003**: Library browse returns results within 1 second for up to 1,500 videos.
- **SC-004**: 100% of copilot answers include at least one citation when content exists.
- **SC-005**: Failed jobs are visible with clear error messages and retry is available within 1 click.
- **SC-006**: Scope is always visible during copilot interaction — user never wonders "what did it search?".

---

## Out of Scope / Future Ideas

- **Multi-user / sharing**: Read-only sharing with friends (future).
- **Playlists**: User-created playlists or collections beyond ingestion batches.
- **Export**: Export summaries, transcripts, or learning paths to external formats.
- **Notifications**: Alerts when new videos from tracked channels are available.
- **Mobile app**: Native mobile experience.
- **Podcast support**: Extend beyond YouTube to audio podcasts.
- **Live transcription**: Real-time transcription of live streams.
- **User annotations**: Allow user to add notes or highlights to segments.

---

## Assumptions

- YouTube provides accessible transcripts (auto-generated or uploaded) for most videos, or transcription can be generated from audio.
- A single Azure SQL Database can handle operational data, vector storage, and relationship queries at hobby scale.
- Users are comfortable waiting minutes for video processing (not real-time).
- The copilot model (e.g., GPT-4) can ground responses in provided context without hallucination if properly prompted.

---

## Clarifications

### Session 2024-12-14

- Q: How should the system retrieve a YouTube channel's video list for batch ingestion? → A: yt-dlp extraction (scrapes channel page, no API key needed)
- Q: What is the maximum number of videos to fetch for channel selection UI? → A: Fetch up to 100 videos with "Load More" pagination

### Session 2025-12-14

- Q: How should API authentication be enforced? → A: No auth (trust network boundary only)
- Q: Which LLM provider and model should be used? → A: Azure OpenAI (GPT-4o + text-embedding-3-small)
- Q: How should copilot conversation history be persisted? → A: Browser localStorage (survives refresh, cleared on logout)

### Session 2025-12-18

- Q: How should "Why this?" explanation be delivered? → A: Inline in main query response
  - Explanation data is included in the `CopilotQueryResponse`, not via separate API call
  - Each `RecommendedVideo` includes an `explanation` field with human-readable content
  - LLM generates explanation during answer generation (no additional embedding/LLM calls)
  - Format: `{ summary: string, keyMoments: KeyMoment[], relatedTo?: string }`
  - Frontend displays explanation on "Why this?" click (no network request needed)
