# Requirements: YT Summarizer Product Foundation

**Status**: Implementing
**Milestone**: M1
**Spec Phase**: execution
**Created**: 2025-12-13
**Updated**: 2026-04-04

---

## User Stories

### US1 — Ingest a Single Video (Priority: P1 🎯 MVP)

**As a** library owner,  
**I want to** submit a YouTube URL and watch it progress through processing,  
**So that** I can view the AI-generated summary, transcript, and key segments when complete.

**Acceptance Criteria**:
- AC-US1-01: Given an empty library, when user submits a valid YouTube URL, then the system queues the video and shows progress stages (transcribe → summarize → embed → build relationships), marking complete when done.
- AC-US1-02: Given a video in progress, when user views the jobs page, then they see current stage, elapsed time, and estimated remaining time.
- AC-US1-03: Given a completed video, when user opens the video detail page, then they see: title, thumbnail, duration, summary, full transcript, and key segments with timestamps.
- AC-US1-04: Given a failed ingestion, when user views the video in the library, then they see a clear error message and a "Retry" button (not via chat).
- AC-US1-05: Given a video URL already ingested, when user submits it again, then the system either skips (unchanged) or offers to reprocess.

---

### US2 — Ingest from a Channel (Batch) (Priority: P2)

**As a** library owner,  
**I want to** provide a channel URL, browse available videos, and start a batch ingestion,  
**So that** I can build a library from a channel at scale with full progress tracking.

**Acceptance Criteria**:
- AC-US2-01: Given a channel URL, when user submits it, then the system fetches the channel's video list and displays them for selection with an "Ingest All Videos" option.
- AC-US2-02: Given a list of channel videos, when user selects multiple and clicks "Start Batch", then a batch is created and each selected video is queued.
- AC-US2-03: Given a list of channel videos, when user clicks "Ingest All Videos", then a batch is created containing all videos from the channel.
- AC-US2-04: Given an active batch, when user views the batch status page, then they see: total count, completed count, failed count, and per-video status rows.
- AC-US2-05: Given some videos in the batch fail, when user views the batch, then they can retry failed videos individually or all-at-once (not via chat).
- AC-US2-06: Given a batch completes, when user views "Ready to Review" list, then they see all newly-ingested videos with links to detail pages.
- AC-US2-07: Given a channel previously ingested, when user submits it again, then the system shows which videos are new, which are already ingested, and offers to ingest only new or reprocess all.

---

### US3 — Browse the Library (Priority: P2)

**As a** library owner,  
**I want to** filter the library by channel, time range, and facets,  
**So that** I can navigate my content collection and open video detail pages.

**Acceptance Criteria**:
- AC-US3-01: Given a library with videos from multiple channels, when user applies a channel filter, then only videos from that channel appear.
- AC-US3-02: Given a library with videos over time, when user applies a date range filter, then only videos published within that range appear.
- AC-US3-03: Given videos with extracted tags/facets, when user clicks a tag chip, then only videos with that tag appear.
- AC-US3-04: Given filter results, when user clicks a video card, then they navigate to the video detail page.
- AC-US3-05: Given the video detail page, when user views it, then they see: summary, transcript, segments with timestamps (clickable to YouTube), and extracted metadata/tags.

---

### US4 — Query with the Copilot (Priority: P1 🎯)

**As a** library owner,  
**I want to** ask questions scoped to a channel or the whole library,  
**So that** I receive cited answers grounded in my video content.

**Acceptance Criteria**:
- AC-US4-01: Given ingested content, when user types a question, then the copilot returns: a short answer, recommended videos (as cards), and evidence citations (timestamped snippets).
- AC-US4-02: Given a query, when the answer is displayed, then the UI shows the active scope (channels, time range, content types) as chips.
- AC-US4-03: Given scope chips, when user changes scope, then the query re-runs with the new scope and results update.
- AC-US4-04: Given an answer with citations, when user clicks a citation, then they see the segment text and can click through to the video at that timestamp.
- AC-US4-05: Given insufficient ingested content, when user asks a question, then the copilot responds: "I don't have enough information on this topic" and suggests ingesting more via the library UI.
- AC-US4-06: Given any answer, when user views it, then follow-up suggestion buttons are displayed.
- AC-US4-07: Given a query, when user clicks "Topics in Scope", then a panel shows top facets/concepts with counts relevant to current scope.

---

### US5 — "Explain Why" Transparency (Priority: P3)

**As a** library owner,  
**I want to** see why a video was recommended,  
**So that** I can trust the copilot's suggestions and verify the reasoning.

**Acceptance Criteria**:
- AC-US5-01: Given a recommended video in query results, when user clicks "Why this?", then a panel shows: similarity basis, relationship basis, and evidence segment snippets.
- AC-US5-02: Given the explanation panel, when user clicks an evidence segment, then they navigate to that video at the relevant timestamp.
- AC-US5-03: Given a video with stored relationships, when user views "Why this?", then the panel shows relationship type and which segment/metadata established it.

---

### US6 — Synthesize Structured Outputs (Priority: P3)

**As a** library owner,  
**I want to** ask the copilot to create learning paths or watch lists,  
**So that** I can extract structured knowledge from my library.

**Acceptance Criteria**:
- AC-US6-01: Given multiple related videos, when user asks "Build a learning path for X", then the copilot returns an ordered list of videos with rationale.
- AC-US6-02: Given a synthesized output, when user views it, then each item cites the evidence (segments, relationships) that informed its position.
- AC-US6-03: Given a synthesized output, when content is insufficient, then the copilot states what's missing and suggests ingesting more.
- AC-US6-04: Given a curated video series with a known correct order, when user asks for a "learning path", then the returned order matches the human-verified sequence.
- AC-US6-05: Given videos with explicit difficulty indicators, when building a learning path, then beginner content appears before advanced content.

---

## Functional Requirements

### Ingestion & Processing

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| FR-001 | System MUST accept a YouTube video URL and queue it for processing | P1 | ✅ Done |
| FR-002 | System MUST process videos through four sequential stages: transcript → summarisation → chunking with semantic embedding → relationship extraction | P1 | ✅ Done |
| FR-003 | System MUST expose per-video job status at all times: pending, running (with current stage), succeeded, or failed (with error detail) | P1 | ✅ Done |
| FR-004 | System MUST allow the user to retry failed jobs from the library UI — not via the copilot | P1 | ✅ Done |
| FR-005 | System MUST support batch ingestion from a channel: fetch video list, display up to 100 videos with "Load More" pagination, allow per-video selection or "Ingest All", track per-video status | P2 | ✅ Done |
| FR-006 | System MUST NOT duplicate content on reprocessing — all pipeline outputs MUST use upsert semantics | P1 | ✅ Done |

### Library & Browsing

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| FR-007 | System MUST provide library browse with filters: channel, date range, and tags/facets | P2 | ✅ Done |
| FR-008 | System MUST display video detail pages with: title, thumbnail, summary, full transcript, timestamped segments (clickable to source video), and extracted metadata/tags | P2 | ✅ Done |
| FR-009 | System MUST paginate library results (10 per page, 50 maximum per request) | P2 | ✅ Done |

### Copilot & Queries

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| FR-010 | Copilot MUST be strictly read-only — MUST NOT trigger ingestion, write to knowledge store, or execute any side effect | P1 | ✅ Done |
| FR-011 | Copilot MUST expose three independently togglable knowledge sources: Your Videos (on by default), AI Knowledge (on by default), Web Search (off by default) | P1 | ✅ Done |
| FR-011a | When "Your Videos" off but "AI Knowledge" on, copilot answers from general knowledge with uncertainty indicator | P1 | ✅ Done |
| FR-011b | When both "Your Videos" and "AI Knowledge" off, copilot returns error asking user to enable at least one source | P1 | ✅ Done |
| FR-012 | Every copilot answer MUST include: short response text, recommended video cards, timestamped evidence citations (clickable), and optional follow-up suggestion buttons | P1 | ✅ Done |
| FR-013 | Copilot MUST display active query scope as visible chips (channels, time range, content types) including "Topics in Scope" panel | P1 | ✅ Done |
| FR-014 | User MUST be able to adjust scope chips and immediately re-run the query with new scope | P1 | ✅ Done |
| FR-015 | When library contains insufficient content, copilot MUST acknowledge explicitly and suggest ingesting more via library UI — never via chat | P1 | ✅ Done |
| FR-016 | Copilot MAY generate structured outputs (learning paths, watch lists) synthesised entirely from library content | P3 | ✅ Done |
| FR-028 | Copilot conversation history MUST persist across page refreshes for the current session and MUST be cleared on explicit logout | P2 | ✅ Done |

### Transparency & Provenance

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| FR-017 | For any recommended video, user MUST be able to request a "Why this?" explanation showing similarity basis and evidence segments — delivered inline with no additional network request | P3 | ✅ Done |
| FR-018 | System MUST store relationships between videos with: type, confidence score, human-readable rationale, and evidence pointer | P2 | ✅ Done |
| FR-019 | All derived artifacts SHOULD store traceability metadata (creation timestamp, model name, parameters) | P2 | ✅ Done |

### Error Handling & Resilience

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| FR-020 | System MUST detect when backend data store is resuming from idle and respond with "Warming up…" messaging | P2 | ✅ Done |
| FR-020a | Health endpoint MUST report service status and readiness indicators | P2 | ✅ Done |
| FR-020b | UI MUST poll health endpoint on startup and display "Warming up" indicator when backend is unavailable/degraded | P2 | ✅ Done |
| FR-020c | UI MUST automatically retry failed requests with exponential backoff while backend is in degraded/warming state | P2 | ✅ Done |
| FR-021 | All background processing MUST retry transient failures with exponential backoff before escalating | P1 | ✅ Done |
| FR-022 | Jobs exceeding maximum retry count MUST be dead-lettered with full diagnostic context shown to user | P1 | ✅ Done |
| FR-026 | System MUST validate fetched transcript content before storing — invalid responses treated as transient failures | P1 | ✅ Done |
| FR-027 | System MUST detect rate-limit responses from external services and automatically retry after appropriate delay | P1 | ✅ Done |

### Observability

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| FR-023 | System MUST propagate a correlation ID generated at the UI through every processing step — API calls, background jobs, and data operations | P2 | ✅ Done |
| FR-024 | System MUST display job timelines in the UI showing stage transitions, timestamps, and durations | P2 | ✅ Done |
| FR-025 | All system components MUST emit structured JSON logs with: timestamp, severity, correlation ID, component name, message, and relevant entity IDs | P2 | ✅ Done |

---

## Non-Functional Requirements

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-001 | Query response time | < 3s (excluding cold start) |
| NFR-002 | Video ingestion time | < 5 min for typical 10-min video |
| NFR-003 | Library browse response time | < 1s across up to 1,500 videos |
| NFR-004 | Scale ceiling | ~1,500 videos, ~15,000 segments |
| NFR-005 | Concurrency | Hobby scale — 1-5 users |
| NFR-006 | Availability | Serverless (auto-sleep when idle) |

---

## Key Entities

| Entity | Description |
|--------|-------------|
| Channel | YouTube channel with ID, name, thumbnail, last synced date, video count |
| Video | YouTube video with ID, channel reference, title, duration, publish date, processing status |
| Batch | Group of videos queued together; tracks pending/running/succeeded/failed counts |
| Job | Single processing task for a video; tracks stage, status, timestamps, error, correlation ID |
| Artifact | Derived output (transcript or summary) stored in blob with traceability metadata |
| Segment | Time-bounded transcript chunk with semantic embedding vector |
| Relationship | Directional connection between two videos: type, confidence, rationale, evidence pointer |
| Facet | Generic tag/metadata attached to videos: topic, format, level, language, concept |

---

## Out of Scope

- Copilot writing anything or triggering ingestion
- Web search on by default
- Scale optimisation beyond hobby (~1,500 videos)
- Multi-tenant or multi-user architecture
- Multi-user sharing, playlists, export, notifications, mobile app, podcast support, live transcription

---

## Dependencies

| Dependency | Type | Notes |
|------------|------|-------|
| OpenAI API | External | GPT-4o for summarisation/chat; text-embedding-3-small for embeddings |
| yt-dlp | Library | YouTube transcript/metadata extraction |
| Azure SQL Database (Serverless) | Infrastructure | Operational data + VECTOR columns |
| Azure Blob Storage | Infrastructure | Large artifacts (transcripts, summaries) |
| Azure Storage Queue | Infrastructure | Async job coordination |
| CopilotKit | Library | Frontend chat UI framework |
