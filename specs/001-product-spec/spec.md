# Feature Specification: YT Summarizer — Personal YouTube Knowledge Library

**Feature Branch**: `001-product-spec`
**Created**: 2025-12-13
**Status**: Active — Core pipeline implemented; edge cases and UI refinement ongoing
**Input**: YT Summarizer — transforms YouTube videos into a personal searchable knowledge library

## Overview

YT Summarizer transforms selected YouTube videos and channels into a personal, searchable knowledge library. The owner ingests videos by URL or channel, the system processes them into searchable content with AI-generated summaries and semantic embeddings, and an AI copilot answers questions grounded in timestamped evidence drawn from the library.

**One-line description**: Ask questions, extract insights, and discover connections across your YouTube library.

---

## Actors

### Primary: Library Owner (Solo Power User)

A single user who curates a personal YouTube library for learning, reference, or research. Needs:

- **Accurate citations** — trust answers through timestamped evidence
- **Cross-content discovery** — find themes and connections across videos
- **Ingestion control** — decides what enters the library
- **Transparency** — understand what the system knows and does not know

### Future: Read-Only Guest

Potential future ability to share the library read-only with a small number of friends. **Not in current scope.**

---

## Scope & Boundaries

### In Scope

- Ingest individual YouTube videos by URL
- Batch-ingest all or selected videos from a channel
- Process each video: transcript → summary → embeddings → relationship extraction
- Browse the library with filters (channel, date range, tags/facets)
- Query the library via an AI copilot with scoped, citation-backed answers
- Discover related videos automatically through extracted relationships
- "Why this?" transparency panel for any recommended video
- Synthesize structured outputs (learning paths, watch lists) from library content
- Domain-agnostic — supports any topic, not workout-specific

### Out of Scope

- **Copilot writes nothing** — the copilot is strictly read-only and MUST NOT trigger ingestion, write to the knowledge store, or modify any stored data
- **Web search off by default** — available as an optional knowledge source toggle; disabled unless the user explicitly enables it
- **No scale optimisation beyond hobby** — designed for ~1,500 videos and ~15,000 segments
- **No multi-tenant or multi-user architecture** — single-owner system
- Multi-user sharing, playlists, export, notifications, mobile app, podcast support, live transcription

---

## Assumptions

The following constraints are acknowledged realities of the current implementation, not prescriptive requirements for future builds:

- Frontend hosted on Azure Static Web Apps (Next.js)
- Backend runs as containerised Python services (FastAPI API + background workers)
- Single Azure SQL Database (serverless tier) stores all operational data, vector embeddings, and relationships
- Blob storage holds large artifacts (transcripts, summaries); a storage queue drives background processing
- Identity managed via Azure Entra ID with Managed Identity
- Network-boundary trust model — no per-request API authentication between containers
- AI services: GPT-4o for chat and summarisation; text-embedding-3-small (1 536 dimensions) for embeddings
- Channel video lists are fetched via yt-dlp (no YouTube Data API key required)
- Transcript source: YouTube auto-generated captions are the primary source; Whisper transcription is the fallback for videos without captions

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

4. **Given** a curated video series with a known correct pedagogical order (e.g., "Lecture 1", "Lecture 2", etc.), **When** user asks for a "learning path", **Then** the returned order matches the human-verified correct sequence (beginner → intermediate → advanced).

5. **Given** videos with explicit difficulty indicators in their content (e.g., "for beginners", "advanced technique"), **When** building a learning path, **Then** beginner content appears before advanced content.

**Testing Constraints for Ordering Verification**:
- Tests MUST use videos from curated sources (e.g., GitHub repos like `karpathy/nn-zero-to-hero`) with known human-verified correct order
- Videos shorter than 60 seconds (shorts) MUST be excluded as they lack captions and are insufficient for LLM analysis
- All test videos MUST have YouTube auto-captions to avoid expensive Whisper transcription
- Tests should verify that the LLM returns the same ordering that humans determined is correct

---

### Edge Cases

- **Duplicate URL submission**: System detects already-ingested videos and offers skip or reprocess options.
- **Video unavailable**: If YouTube returns 404 or private, system marks job as failed with clear message.
- **Partial transcript**: If transcription is incomplete, system marks it and shows what's available.
- **Serverless DB cold start**: API retries with timeout; UI polls health endpoint (which includes uptime) and shows "Warming up..." indicator instead of crashing. UI retries failed requests with backoff while status is "degraded".
- **Empty query scope**: If user narrows scope to zero videos, system explains and suggests broadening.
- **Very long video**: System handles gracefully (may take longer); shows progress.
- **Rate limiting**: If YouTube or AI provider rate-limits, system queues retries with backoff.

---

## Requirements *(mandatory)*

### Functional Requirements

#### Ingestion & Processing

- **FR-001**: System MUST accept a YouTube video URL and queue it for processing.
- **FR-002**: System MUST process videos through four sequential stages: transcript acquisition → summarisation → chunking with semantic embedding → relationship extraction.
- **FR-003**: System MUST expose per-video job status at all times: pending, running (with current stage), succeeded, or failed (with error detail).
- **FR-004**: System MUST allow the user to retry failed jobs from the library UI — not via the copilot.
- **FR-005**: System MUST support batch ingestion from a channel: fetch the channel's video list, display up to 100 videos with "Load More" pagination, allow per-video selection or "Ingest All", and track per-video status throughout.
- **FR-006**: System MUST NOT duplicate content on reprocessing — all pipeline outputs (segments, embeddings, relationships) MUST use upsert semantics.

#### Library & Browsing

- **FR-007**: System MUST provide library browse with filters: channel, date range, and tags/facets.
- **FR-008**: System MUST display video detail pages with: title, thumbnail, summary, full transcript, timestamped segments (clickable to the source video at that timestamp), and extracted metadata/tags.
- **FR-009**: System MUST paginate library results with sensible defaults (10 per page, 50 maximum per request) to stay responsive at hobby scale.

#### Copilot & Queries

- **FR-010**: Copilot MUST be strictly read-only — it MUST NOT trigger ingestion, write to the knowledge store, modify relationships or embeddings, or execute any side effect.
- **FR-011**: Copilot MUST expose three independently togglable knowledge sources: **Your Videos** (semantic search over the library — on by default), **AI Knowledge** (the model's general training — on by default), and **Web Search** (live internet search — off by default).
- **FR-011a**: When "Your Videos" is off but "AI Knowledge" is on, the copilot answers from general knowledge and displays an uncertainty indicator.
- **FR-011b**: When both "Your Videos" and "AI Knowledge" are off, the copilot returns an error asking the user to enable at least one source.
- **FR-012**: Every copilot answer MUST include: a short response text, recommended video cards, timestamped evidence citations (clickable to the video at that moment), and optional follow-up suggestion buttons.
- **FR-013**: Copilot MUST display the active query scope as visible chips (channels, time range, content types) alongside the answer, including a "Topics in Scope" panel showing top facets with counts.
- **FR-014**: User MUST be able to adjust scope chips and immediately re-run the query with the new scope.
- **FR-015**: When the library contains insufficient content to answer a question, the copilot MUST acknowledge this explicitly and suggest ingesting more content via the library UI — never via chat.
- **FR-016**: Copilot MAY generate structured outputs (learning paths, ordered watch lists) synthesised entirely from library content.
- **FR-028**: Copilot conversation history MUST persist across page refreshes for the current session and MUST be cleared on explicit logout.

#### Transparency & Provenance

- **FR-017**: For any recommended video, user MUST be able to request a "Why this?" explanation showing the similarity basis and the specific evidence segments that drove the recommendation — delivered inline with no additional network request.
- **FR-018**: System MUST store relationships between videos with: type, confidence score, human-readable rationale, and an evidence pointer (segment or metadata field).
- **FR-019**: All derived artifacts (summaries, embeddings) SHOULD store traceability metadata (creation timestamp, model name, parameters) to support debugging.

#### Error Handling & Resilience

- **FR-020**: System MUST detect when the backend data store is resuming from idle and respond with user-friendly "Warming up…" messaging rather than an error.
- **FR-020a**: The system health endpoint MUST report service status and readiness indicators so the UI can determine whether the backend needs time to warm up.
- **FR-020b**: The UI MUST poll the health endpoint on startup and display a "Warming up" indicator when the backend reports unavailable or degraded status.
- **FR-020c**: The UI MUST automatically retry failed requests with exponential backoff while the backend is in a degraded/warming state.
- **FR-021**: All background processing MUST retry transient failures with exponential backoff before escalating.
- **FR-022**: Jobs that exceed the maximum retry count MUST be dead-lettered with full diagnostic context and shown to the user in the UI.
- **FR-026**: System MUST validate fetched transcript content before storing it — invalid or error responses from external services MUST be detected and treated as transient failures.
- **FR-027**: System MUST detect rate-limit responses from external services and automatically retry after an appropriate delay.

#### Observability

- **FR-023**: System MUST propagate a correlation ID generated at the UI through every processing step — API calls, background jobs, and data operations.
- **FR-024**: System MUST display job timelines in the UI showing stage transitions, timestamps, and durations for each processing step.
- **FR-025**: All system components MUST emit structured (JSON) logs with: timestamp, severity, correlation ID, component name, message, and relevant entity IDs.

---

### Key Entities

- **Channel**: A YouTube channel. Has: channel ID, name, thumbnail, last synced date, video count.

- **Video**: A YouTube video. Has: video ID, channel reference, title, description, duration, publish date, thumbnail, processing status.

- **Batch**: A group of videos queued together for processing. Has: batch ID, optional channel reference, created date, status counts (pending / running / succeeded / failed).

- **Job**: A single processing task for a video. Has: job ID, video reference, optional batch reference, current stage, status, start/end timestamps, error message, correlation ID.

- **Artifact**: A derived output stored at rest (transcript or summary). Has: artifact ID, video reference, type, content location, traceability metadata (creation time, model used, parameters).

- **Segment**: A time-bounded chunk of transcript with a semantic embedding. Has: segment ID, video reference, start/end timestamps, text, embedding vector.

- **Relationship**: A directional connection between two videos. Has: relationship ID, source video, target video, type (series / progression / same-topic / references / related), confidence score, human-readable rationale, evidence pointer.

- **Facet / Tag**: Generic metadata attached to videos. Has: facet ID, name, type (topic / format / level / language / concept), video references.

---

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: User can ingest a video and view its AI-generated summary within 5 minutes of submission for a typical 10-minute video.
- **SC-002**: User can ask a question and receive a cited answer within 3 seconds (excluding cold-start delay when the backend is resuming from idle).
- **SC-003**: Library browse returns filtered results within 1 second across a library of up to 1,500 videos.
- **SC-004**: Every copilot answer includes at least one timestamped citation when video content exists for the query.
- **SC-005**: Any failed ingestion job is visible to the user with a clear error description and a one-click retry action.
- **SC-006**: The active query scope is always visible to the user during copilot interaction — the user can always see which channels, time ranges, and knowledge sources are being searched.
- **SC-007**: A synthesized learning path produced for a curated series with a known correct pedagogical order matches the human-verified sequence from beginner to advanced.
