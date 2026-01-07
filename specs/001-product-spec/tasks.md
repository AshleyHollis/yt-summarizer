# Tasks: YT Summarizer

**Input**: Design documents from `/specs/001-product-spec/`
**Prerequisites**: plan.md ✅, spec.md ✅, research.md ✅, data-model.md ✅, contracts/ ✅

---

## Format: `[ID] [P?] [Story?] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (US1, US2, US3, US4, US5, US6)
- Include exact file paths in descriptions

---

## Phase 1: Setup (Shared Infrastructure) ✅

**Purpose**: Project initialization, mono-repo structure, development environment

- [X] T001 Create mono-repo structure per plan.md (apps/, services/, db/, infra/, docs/)
- [X] T002 [P] Initialize Next.js app in apps/web/ with TypeScript, TailwindCSS, App Router
- [X] T003 [P] Initialize Python API project in services/api/ with FastAPI, pyproject.toml
- [X] T004 [P] Initialize Python workers project in services/workers/ with pyproject.toml
- [X] T005 [P] Initialize shared Python package in services/shared/ with pyproject.toml
- [X] T006 [P] Create .NET Aspire AppHost in services/aspire/AppHost/Program.cs
- [X] T007 [P] Configure linting: ESLint + Prettier for web, ruff for Python
- [X] T008 Create docker-compose.yml or Aspire emulators for local Azurite (blob + queue)
- [X] T009 [P] Create .env.example files for all services with required environment variables
- [X] T010 [P] Create README.md with development setup instructions

---

## Phase 2: Foundational (Blocking Prerequisites) ✅

**Purpose**: Core infrastructure that MUST be complete before ANY user story can be implemented

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

### Database & Migrations

- [X] T011 Create Alembic configuration in services/shared/alembic/ with alembic.ini, env.py
- [X] T012 Create SQLAlchemy models for Channels, Videos in services/shared/db/models/
- [X] T013 Create migration 001_initial_schema.py for Channels and Videos tables
- [X] T014 Create SQLAlchemy models for Batches, BatchItems, Jobs in services/shared/db/models/
- [X] T015 Create migration 002_batches_and_jobs.py for Batches, BatchItems, Jobs tables
- [X] T016 Create SQLAlchemy models for Artifacts, Segments in services/shared/db/models/
- [X] T017 Create migration 003_artifacts_and_segments.py with VECTOR(1536) column
- [X] T018 Create SQLAlchemy models for Relationships, Facets, VideoFacets in services/shared/db/models/
- [X] T019 Create migration 004_relationships_and_facets.py

### Shared Infrastructure

- [X] T020 [P] Implement database connection factory in services/shared/db/connection.py with retry logic
- [X] T021 [P] Implement Azure Blob client wrapper in services/shared/blob/client.py
- [X] T022 [P] Implement Azure Storage Queue client wrapper in services/shared/queue/client.py
- [X] T023 [P] Implement structured logging (structlog) in services/shared/logging/config.py
- [X] T024 [P] Implement correlation ID middleware for FastAPI in services/api/src/api/middleware/correlation.py
- [X] T025 [P] Create Pydantic settings for configuration in services/shared/config.py

### API Foundation

- [X] T026 Create FastAPI app factory in services/api/src/api/main.py with CORS, error handlers
- [X] T027 [P] Implement health check endpoint GET /health in services/api/src/api/routes/health.py
- [X] T028 [P] Create base Pydantic response models (ErrorResponse, PaginatedResponse) in services/api/src/api/models/base.py
- [X] T029 Configure Dockerfile for API in services/api/Dockerfile

### Worker Foundation

- [X] T030 Create worker base class with queue polling in services/workers/shared/base_worker.py
- [X] T031 [P] Configure Dockerfile for workers in services/workers/Dockerfile

### Frontend Foundation

- [X] T032 Create API client service in apps/web/src/services/api.ts with fetch wrapper
- [X] T033 [P] Create base layout component in apps/web/src/app/layout.tsx
- [X] T034 [P] Configure environment variables in apps/web/next.config.js for API URL
- [X] T034a [P] Implement correlation ID generator in apps/web/src/services/correlation.ts (FR-023)

**Checkpoint**: Foundation ready - user story implementation can now begin ✅

---

## Phase 3: User Story 1 — Ingest a Single Video (Priority: P1) 🎯 MVP ✅

**Goal**: User submits a YouTube URL, watches progress through transcription → summarization → embedding → relationship extraction, views completed summary

**Independent Test**: Submit one URL, wait for completion, view the video detail page with summary and transcript

### API Implementation for US1

- [X] T035 [US1] Create video Pydantic models (SubmitVideoRequest, VideoResponse) in services/api/src/api/models/video.py
- [X] T036 [US1] Implement video service with submit logic in services/api/src/api/services/video_service.py
- [X] T037 [US1] Implement POST /api/v1/videos endpoint in services/api/src/api/routes/videos.py
- [X] T038 [US1] Implement GET /api/v1/videos/{videoId} endpoint in services/api/src/api/routes/videos.py
- [X] T039 [US1] Implement POST /api/v1/videos/{videoId}/reprocess endpoint in services/api/src/api/routes/videos.py

### Job API for US1

- [X] T040 [P] [US1] Create job Pydantic models in services/api/src/api/models/job.py
- [X] T041 [US1] Implement job service in services/api/src/api/services/job_service.py
- [X] T042 [US1] Implement GET /api/v1/jobs/{jobId} endpoint in services/api/src/api/routes/jobs.py
- [X] T043 [US1] Implement GET /api/v1/jobs (list with filters) in services/api/src/api/routes/jobs.py
- [X] T044 [US1] Implement POST /api/v1/jobs/{jobId}/retry endpoint in services/api/src/api/routes/jobs.py

### Workers for US1

- [X] T045 [US1] Implement transcribe worker in services/workers/transcribe/worker.py (YouTube captions + yt-dlp fallback)
- [X] T046 [US1] Implement summarize worker in services/workers/summarize/worker.py (OpenAI)
- [X] T047 [US1] Implement embed worker in services/workers/embed/worker.py (chunking + embeddings)
- [X] T048 [US1] Implement relationships worker in services/workers/relationships/worker.py

### Frontend for US1

- [X] T049 [US1] Create video submission form component in apps/web/src/components/ingestion/SubmitVideoForm.tsx
- [X] T050 [US1] Create job progress component in apps/web/src/components/jobs/JobProgress.tsx
- [X] T051 [US1] Create submit video page in apps/web/src/app/ingest/page.tsx
- [X] T052 [US1] Create video detail page in apps/web/src/app/videos/[videoId]/page.tsx
- [X] T053 [US1] Create transcript viewer component in apps/web/src/components/library/TranscriptViewer.tsx
- [X] T054 [US1] Create summary display component in apps/web/src/components/library/SummaryCard.tsx
- [X] T055 [US1] Add retry button with error message display in job progress component

**Checkpoint**: User Story 1 complete — can submit a video URL, track progress, view summary and transcript ✅

---

## Phase 4: User Story 3 — Browse the Library (Priority: P2) ✅

**Goal**: User filters the library by channel, time range, and facets; opens video detail pages

**Independent Test**: With 10+ ingested videos, filter by channel, verify correct results, open a detail page

### API Implementation for US3

- [X] T056 [P] [US3] Create library Pydantic models (VideoListResponse, filters) in services/api/src/api/models/library.py
- [X] T057 [US3] Implement library service with filter logic in services/api/src/api/services/library_service.py
- [X] T058 [US3] Implement GET /api/v1/library/videos endpoint with filters in services/api/src/api/routes/library.py
- [X] T059 [US3] Implement GET /api/v1/library/videos/{videoId}/segments endpoint in services/api/src/api/routes/library.py
- [X] T060 [P] [US3] Create channel Pydantic models (ChannelResponse, ChannelListResponse) in services/api/src/api/models/channel.py
- [X] T061 [US3] Implement GET /api/v1/library/channels endpoint in services/api/src/api/routes/library.py
- [X] T062 [P] [US3] Create facet Pydantic models in services/api/src/api/models/facet.py
- [X] T063 [US3] Implement GET /api/v1/library/facets endpoint in services/api/src/api/routes/library.py

### Frontend for US3

- [X] T064 [US3] Create library page in apps/web/src/app/library/page.tsx
- [X] T065 [P] [US3] Create video card component in apps/web/src/components/library/VideoCard.tsx
- [X] T066 [P] [US3] Create filter sidebar component in apps/web/src/components/library/FilterSidebar.tsx
- [X] T067 [P] [US3] Create channel filter component in apps/web/src/components/library/ChannelFilter.tsx
- [X] T068 [P] [US3] Create date range picker component in apps/web/src/components/library/DateRangePicker.tsx
- [X] T069 [P] [US3] Create facet chips component in apps/web/src/components/library/FacetChips.tsx
- [X] T070 [US3] Create pagination component in apps/web/src/components/common/Pagination.tsx
- [X] T071 [US3] Implement segment list with timestamps on video detail page in apps/web/src/components/library/SegmentList.tsx
- [X] T072 [US3] Add clickable timestamps linking to YouTube in segment list

**Checkpoint**: User Story 3 complete — can browse library with filters, view video details with segments ✅

---

## Phase 5: User Story 2 — Ingest from Channel (Batch) (Priority: P2) ✅

**Goal**: User provides channel URL, browses available videos (with "Ingest All" option), starts batch; sees batch progress

**Independent Test**: Submit a channel, select 5 videos OR click "Ingest All", start batch, verify all complete

**Technical Decisions** (from clarifications):
- Channel video lists fetched via yt-dlp extraction (no YouTube API key needed)
- UI displays up to 100 videos with "Load More" pagination
- "Ingest All" queues all videos via backend cursor-based fetching

### API Implementation for US2

- [X] T073 [P] [US2] Add ingestion channel models (FetchChannelRequest, ChannelVideosResponse, ChannelVideo) to services/api/src/api/models/channel.py
- [X] T074 [US2] Implement YouTube service with yt-dlp channel extraction in services/api/src/api/services/youtube_service.py
- [X] T075 [US2] Implement channel service for fetch/pagination in services/api/src/api/services/channel_service.py
- [X] T076 [US2] Implement POST /api/v1/channels endpoint (fetch channel videos) in services/api/src/api/routes/channels.py
- [X] T077 [P] [US2] Create batch Pydantic models (CreateBatchRequest, BatchResponse, BatchDetailResponse, BatchItem) in services/api/src/api/models/batch.py
- [X] T078 [US2] Implement batch service (create, get, list, retry) in services/api/src/api/services/batch_service.py
- [X] T079 [US2] Implement POST /api/v1/batches endpoint (create batch) in services/api/src/api/routes/batches.py
- [X] T080 [US2] Implement GET /api/v1/batches endpoint (list batches) in services/api/src/api/routes/batches.py
- [X] T081 [US2] Implement GET /api/v1/batches/{batchId} endpoint (batch detail with items) in services/api/src/api/routes/batches.py
- [X] T082 [US2] Implement POST /api/v1/batches/{batchId}/retry endpoint (retry all failed) in services/api/src/api/routes/batches.py
- [X] T083 [US2] Implement POST /api/v1/batches/{batchId}/items/{videoId}/retry endpoint (retry single) in services/api/src/api/routes/batches.py

### Frontend for US2

- [X] T084 [US2] Create channel submission form in apps/web/src/components/ChannelForm.tsx
- [X] T085 [US2] Create channel video list with multi-select + "Ingest All" button in apps/web/src/components/ChannelVideoList.tsx
- [X] T086 [US2] Create "Load More" pagination for channel videos in apps/web/src/components/ChannelVideoList.tsx
- [X] T087 [US2] Create batch creation page in apps/web/src/app/ingest/page.tsx
- [X] T088 [US2] Create batch status page in apps/web/src/app/ingest/[batchId]/page.tsx
- [X] T089 [P] [US2] Create batch progress summary component in apps/web/src/components/BatchProgress.tsx
- [X] T090 [P] [US2] Create per-video status row component in apps/web/src/components/BatchProgress.tsx (integrated)
- [X] T091 [US2] Create batches list page in apps/web/src/app/batches/page.tsx
- [X] T092 [US2] Add retry failed videos button (all-at-once) on batch status page
- [X] T093 [US2] Add individual retry button per failed video row
- [X] T094 [US2] Add "already ingested" indicator for re-submitted channels (acceptance scenario 7)
- [X] T095 [US2] Add navigation link from completed batch to "Ready to Review" filtered library view

**Checkpoint**: User Story 2 complete — can batch ingest from a channel with full status tracking ✅

---

## Phase 6: User Story 4 — Query with the Copilot (Priority: P1) 🎯

**Goal**: User asks a question scoped to channel or library; receives answer with citations; can adjust scope and re-query

**Independent Test**: With 5+ ingested videos, ask a question, receive an answer with citations and video cards

**Technical Context**:
- Copilot is READ-ONLY (no data modifications, no ingestion triggers)
- Uses vector search on segment embeddings for semantic similarity
- Uses relationship graph for related video discovery
- CopilotKit provides the chat UI framework
- Scope filters: channels, videoIds, dateRange, facets, contentTypes

### API Models for US4

- [X] T096 [P] [US4] Create QueryScope Pydantic model (channels, videoIds, dateRange, facets, contentTypes) in services/api/src/api/models/copilot.py
- [X] T097 [P] [US4] Create CopilotQueryRequest model (query, scope, conversationId, correlationId) in services/api/src/api/models/copilot.py
- [X] T098 [P] [US4] Create CopilotQueryResponse model (answer, videoCards, evidence, scopeEcho, followups, uncertainty) in services/api/src/api/models/copilot.py
- [X] T099 [P] [US4] Create Evidence model (videoId, segmentId, segmentText, startTime, endTime, youTubeUrl, confidence) in services/api/src/api/models/copilot.py
- [X] T100 [P] [US4] Create RecommendedVideo model (videoId, title, channelName, thumbnailUrl, relevanceScore, primaryReason) in services/api/src/api/models/copilot.py
- [X] T101 [P] [US4] Create SegmentSearchRequest/Response, ScoredSegment models in services/api/src/api/models/copilot.py
- [X] T102 [P] [US4] Create TopicsResponse, TopicCount, CoverageResponse models in services/api/src/api/models/copilot.py

### API Services for US4

- [X] T103 [US4] Implement vector search service with pgvector cosine similarity in services/api/src/api/services/search_service.py
- [X] T104 [US4] Implement scope filter builder (convert QueryScope to SQL WHERE clauses) in services/api/src/api/services/search_service.py
- [X] T105 [US4] Implement copilot orchestrator (query → search → LLM → response) in services/api/src/api/services/copilot_service.py
- [X] T106 [US4] Add LLM client wrapper for OpenAI chat completions in services/api/src/api/services/llm_service.py
- [X] T107 [US4] Implement follow-up suggestion generator in services/api/src/api/services/copilot_service.py
- [X] T108 [US4] Implement uncertainty detection (insufficient content handling) in services/api/src/api/services/copilot_service.py

### API Routes for US4

- [X] T109 [US4] Implement POST /api/v1/copilot/query endpoint in services/api/src/api/routes/copilot.py
- [X] T110 [US4] Implement POST /api/v1/copilot/search/segments endpoint in services/api/src/api/routes/copilot.py
- [X] T111 [US4] Implement POST /api/v1/copilot/search/videos endpoint in services/api/src/api/routes/copilot.py
- [X] T112 [US4] Implement POST /api/v1/copilot/topics endpoint in services/api/src/api/routes/copilot.py
- [X] T113 [US4] Implement POST /api/v1/copilot/coverage endpoint in services/api/src/api/routes/copilot.py
- [X] T114 [US4] Implement GET /api/v1/copilot/neighbors/{videoId} endpoint in services/api/src/api/routes/copilot.py

### CopilotKit Integration for US4

- [X] T115 [US4] Install CopilotKit packages (@copilotkit/react-core, @copilotkit/react-ui) in apps/web/package.json
- [X] T116 [US4] Configure CopilotKit provider with API endpoint in apps/web/src/app/providers.tsx
- [X] T117 [US4] Create useCopilotAction hooks for search/query in apps/web/src/hooks/useCopilotActions.ts

### Frontend Components for US4

- [X] T118 [US4] Create CopilotSidebar component (chat panel with message history) in apps/web/src/components/copilot/CopilotSidebar.tsx
- [X] T119 [P] [US4] Create ScopeChips component (display/edit query scope filters) in apps/web/src/components/copilot/ScopeChips.tsx
- [X] T120 [P] [US4] Create Citation component (clickable evidence with timestamp link) in apps/web/src/components/copilot/Citation.tsx
- [X] T121 [P] [US4] Create CopilotVideoCard component (recommended video with reason) in apps/web/src/components/copilot/CopilotVideoCard.tsx
- [X] T122 [US4] Create TopicsPanel component (facets with counts in scope) in apps/web/src/components/copilot/TopicsPanel.tsx
- [X] T123 [US4] Create FollowupButtons component (suggested next queries) in apps/web/src/components/copilot/FollowupButtons.tsx
- [X] T124 [US4] Create CopilotMessage component (answer with embedded citations and video cards) in apps/web/src/components/copilot/CopilotMessage.tsx

### Frontend State & Integration for US4

- [X] T125 [US4] Create ScopeContext for scope state management in apps/web/src/context/ScopeContext.tsx
- [X] T126 [US4] Add coverage indicator (indexed video count) to copilot header in apps/web/src/components/copilot/CoverageIndicator.tsx
- [X] T127 [US4] Implement uncertainty messaging component in apps/web/src/components/copilot/UncertaintyMessage.tsx
- [X] T128 [US4] Integrate CopilotSidebar into library and video detail pages in apps/web/src/app/layout.tsx
- [X] T129 [US4] Add scope chip interactions (click to narrow/broaden scope) in apps/web/src/components/copilot/ScopeChips.tsx

### AI Knowledge Settings for US4

- [X] T129a [P] [US4] Create AIKnowledgeSettings Pydantic model (useVideoContext, useLLMKnowledge, useWebSearch) in services/api/src/api/models/copilot.py
- [X] T129b [US4] Add ai_settings field to CopilotQueryRequest model in services/api/src/api/models/copilot.py
- [X] T129c [US4] Update CopilotService.query() to respect AI settings (skip RAG when useVideoContext=false) in services/api/src/api/services/copilot_service.py
- [X] T129d [US4] Add generate_answer_without_evidence() to LLMService for LLM-only answers in services/api/src/api/services/llm_service.py
- [X] T129e [US4] Update query_library agent tool with AI settings parameters in services/api/src/api/agents/yt_summarizer_agent.py
- [X] T129f [P] [US4] Create AISettingsContext and useAISettings hook in apps/web/src/app/providers.tsx
- [X] T129g [US4] Update ScopeIndicator with knowledge source toggles (Your Videos, AI Knowledge, Web Search) in apps/web/src/components/copilot/subcomponents/ScopeIndicator.tsx
- [X] T129h [US4] Add help panel to ScopeIndicator explaining each option in apps/web/src/components/copilot/subcomponents/ScopeIndicator.tsx
- [X] T129i [US4] Pass AI settings to agent via useCopilotReadable in apps/web/src/hooks/useCopilotActionsRefactored.tsx

### Tests for US4

- [X] T130 [P] [US4] Create API tests for copilot endpoints in services/api/tests/test_copilot.py
- [X] T130a [P] [US4] Create API tests for AI knowledge settings combinations in services/api/tests/test_copilot.py
- [X] T131 [P] [US4] Create integration tests for vector search in services/api/tests/test_search_service.py
- [X] T132 [P] [US4] Create E2E tests for copilot query flow in apps/web/e2e/copilot.spec.ts
- [X] T132a [P] [US4] Create unit tests for agent module and AG-UI endpoint registration in services/api/tests/test_agents.py
- [X] T132b [P] [US4] Create unit tests for ScopeIndicator component toggles in apps/web/src/__tests__/components/copilot/ScopeIndicator.test.tsx

**Checkpoint**: User Story 4 complete — full copilot query with scope visibility, citations, follow-ups, AI knowledge settings ✅

---

## Phase 7: User Story 5 — "Explain Why" (Transparency) (Priority: P3)

**Goal**: Each recommended video includes explanation data; user clicks "Why this?" to reveal it (no API call)

**Independent Test**: After a query, click "Why this?" on a video card, see human-readable explanation with evidence links

**Design Decision**: Explanation is generated during the main query LLM call and included in the response. No separate `/explain` endpoint needed. This eliminates redundant embedding calls and provides instant UI response.

### API Changes for US5

- [X] T133 [US5] Add VideoExplanation, KeyMoment models to services/api/src/api/models/copilot.py
- [X] T134 [US5] Add `explanation` field to RecommendedVideo model in services/api/src/api/models/copilot.py
- [X] T135 [US5] Update LLM prompt in copilot_service.py to generate per-video explanations during answer generation
- [X] T136 [US5] Update copilot response builder to populate explanation from LLM output in services/api/src/api/services/copilot_service.py

### Frontend for US5

- [X] T137 [US5] Create "Why this?" button on video cards in apps/web/src/components/copilot/WhyThisButton.tsx
- [X] T138 [US5] Create ExplanationPanel component (displays inline explanation data) in apps/web/src/components/copilot/ExplanationPanel.tsx
- [X] T139 [P] [US5] Create KeyMomentsList component with clickable timestamps in apps/web/src/components/copilot/KeyMomentsList.tsx
- [X] T140 [P] [US5] Create RelationshipBadge component (shows series/related info) in apps/web/src/components/copilot/RelationshipBadge.tsx
- [X] T141 [US5] Wire "Why this?" to toggle ExplanationPanel visibility (local state, no API call)

### Tests for US5

- [X] T142 [P] [US5] Update copilot API tests to verify explanation field populated in services/api/tests/test_copilot.py
- [X] T143 [P] [US5] Create E2E tests for "Why this?" toggle in apps/web/e2e/explain.spec.ts

**Checkpoint**: User Story 5 complete — transparency for all recommendations ✅

---

## Phase 8: User Story 6 — Synthesize Structured Outputs (Priority: P3)

**Goal**: User asks copilot to create learning paths, watch lists synthesized from library content

**Independent Test**: With 10+ related videos, ask for a "learning path", receive ordered list with citations

### API Implementation for US6

- [X] T146 [P] [US6] Create LearningPath model (items with order, rationale, videoId, evidence) in services/api/src/api/models/synthesis.py
- [X] T147 [P] [US6] Create WatchList model (items with videoId, reason, priority) in services/api/src/api/models/synthesis.py
- [X] T148 [US6] Implement synthesis service in services/api/src/api/services/synthesis_service.py
- [X] T149 [US6] Add structured output tools to copilot query handler in services/api/src/api/agents/yt_summarizer_agent.py
- [X] T150 [US6] Implement POST /api/v1/copilot/synthesize endpoint in services/api/src/api/routes/copilot.py

### Frontend for US6

- [X] T151 [US6] Create learning path renderer in apps/web/src/components/copilot/LearningPathView.tsx
- [X] T152 [P] [US6] Create watch list renderer in apps/web/src/components/copilot/WatchListView.tsx
- [X] T153 [US6] Add rationale display for each item in structured outputs
- [X] T154 [US6] Add "what's missing" messaging when content insufficient for synthesis

### Tests for US6

- [X] T155 [P] [US6] Create API tests for synthesis endpoint in services/api/tests/test_synthesis.py
- [X] T156 [P] [US6] Create E2E tests for synthesis flow in apps/web/e2e/synthesis.spec.ts

### Learning Path Ordering Verification Tests

- [X] T157 [P] [US6] Add test video fixture with curated series having known correct order (e.g., push-up progression) in apps/web/e2e/global-setup.ts
- [X] T158 [P] [US6] Create ordering verification tests using videos with explicit difficulty levels in apps/web/e2e/synthesis-api.spec.ts
- [X] T159 [P] [US6] Add validation that videos under 60 seconds (shorts) are excluded from learning path generation
- [X] T160a [P] [US6] Create test that verifies beginner content appears before advanced content in learning path results

**Checkpoint**: User Story 6 complete — full synthesis capabilities with verified ordering ✅

---

## Phase 9: Worker Resilience & Content Validation ✅

**Purpose**: Ensure workers handle transient failures and validate external content

### Transcribe Worker Resilience

- [X] T175 [US1] Add content validation to detect HTML error pages vs valid VTT/SRT in services/workers/transcribe/worker.py
- [X] T176 [US1] Implement retry with exponential backoff for YouTube rate-limit errors in transcribe worker
- [X] T177 [US1] Add HTTP status code validation when fetching subtitles (reject non-2xx responses)
- [X] T178 [US1] Add unit tests for content validation and rate-limit detection in services/workers/tests/test_transcribe_resilience.py

### Transcribe Worker Optimization

- [X] T178a [US1] Refactor transcribe worker to use yt-dlp exclusively (remove youtube-transcript-api dependency)
  - yt-dlp has better rate-limit handling: cookie support, client spoofing, frequent updates
  - youtube-transcript-api was making duplicate requests, triggering rate limits faster
  - Single library = simpler codebase, fewer requests per video
- [X] T178b [US1] Add request timing logs to monitor YouTube API request rate in transcribe worker
- [X] T178c [US1] Parse VTT subtitles with timestamps for semantic search (start_time, duration, text)

### Re-Ingest API

- [X] T179 [US1] Add POST /api/v1/videos/{videoId}/reprocess endpoint to re-queue failed videos (already exists)
- [X] T180 [US1] Add "Reprocess" button to video detail page for videos with failed/empty transcripts

**Checkpoint**: Workers gracefully handle YouTube rate limits and transient failures ✅

---

## Phase 10: Polish & Cross-Cutting Concerns ✅

**Purpose**: Production readiness, deployment, observability

### Error Handling & UX Polish

#### Serverless DB Wake-up Handling (FR-020, FR-020a, FR-020b, FR-020c)

- [X] T181a Add `uptime_seconds` and `started_at` fields to HealthStatus response model in services/api/src/api/routes/health.py
- [X] T181b Store API startup timestamp in app.state during FastAPI lifespan startup in services/api/src/api/main.py
- [X] T181c Calculate and return uptime in health endpoint from stored startup timestamp
- [X] T181d Update healthApi types in apps/web/src/services/api.ts to include uptime_seconds and started_at fields
- [X] T181e Create useHealthCheck hook in apps/web/src/hooks/useHealthCheck.ts that polls /health endpoint
- [X] T181f Create HealthStatusProvider context in apps/web/src/contexts/HealthStatusContext.tsx to share health state across app
- [X] T181g Create WarmingUpIndicator component in apps/web/src/components/common/WarmingUpIndicator.tsx showing "Warming up..." banner when status is degraded
- [X] T181h Integrate WarmingUpIndicator into layout.tsx to display globally when database is unavailable
- [X] T181i Add retry logic to API client fetch wrapper that auto-retries on 503/degraded with exponential backoff
- [X] T181j Add unit tests for health endpoint uptime calculation in services/api/tests/test_health.py
- [X] T181k Add unit tests for useHealthCheck hook and WarmingUpIndicator component
- [X] T181l Add E2E test verifying warming up indicator displays when API returns degraded status

#### Global Error Handling

- [X] T183 [P] Create global error boundary in apps/web/src/app/error.tsx
  - Handle: API unreachable → "Cannot connect to server. Retrying..."
  - Handle: 503 Service Unavailable → "Database is waking up. Please wait..."
  - Handle: 500 Server Error → "Something went wrong. Please try again."
  - Handle: Network offline → "You appear to be offline. Check your connection."
  - Include "Retry" button and option to copy error details for support
  - Log error to console with correlation_id if available

- [X] T183a Create not-found page in apps/web/src/app/not-found.tsx
  - User-friendly 404 page with link back to library/home
  - Suggest related actions: "Browse Library", "Submit a Video"

#### Loading States & Skeletons

- [X] T184 Add loading skeletons for async data fetches
  - apps/web/src/components/library/VideoCardSkeleton.tsx for library grid
  - apps/web/src/components/jobs/JobProgressSkeleton.tsx for job status
  - apps/web/src/components/common/TableRowSkeleton.tsx for table views (batches, dead-letter)
  - apps/web/src/components/copilot/MessageSkeleton.tsx for copilot responses
  - Apply skeletons to: library page, video detail, batch status, jobs list, copilot sidebar

### Observability — End-to-End Video Ingestion Tracing

**Goal**: Trace the complete video ingestion flow from UI submission through all worker stages, enabling rapid identification of failures and bottlenecks in Aspire dashboard.

#### OpenTelemetry SDK Setup

- [X] T185 [P] Add OpenTelemetry SDK to Python API in services/api/pyproject.toml
  - Install: opentelemetry-api, opentelemetry-sdk, opentelemetry-exporter-otlp
  - Install: opentelemetry-instrumentation-fastapi, opentelemetry-instrumentation-sqlalchemy
  - Install: opentelemetry-instrumentation-httpx (for yt-dlp/YouTube calls)

- [X] T185a Configure OpenTelemetry TracerProvider in services/api/src/api/main.py
  - Set service name from environment (OTEL_SERVICE_NAME or SERVICE_NAME)
  - Configure OTLP exporter pointing to Aspire collector (OTEL_EXPORTER_OTLP_ENDPOINT)
  - Add BatchSpanProcessor for production performance
  - Instrument FastAPI, SQLAlchemy, and httpx automatically

- [X] T186 [P] Add OpenTelemetry SDK to workers in services/workers/pyproject.toml
  - Install same packages as API plus opentelemetry-instrumentation-azure-sdk (for queue/blob)
  
- [X] T186a Create shared OpenTelemetry configuration in services/shared/shared/telemetry/config.py
  - configure_telemetry(service_name: str) function reusable by API and workers
  - Auto-detect Aspire OTLP endpoint from environment
  - Graceful fallback if OTLP endpoint not configured (local dev without Aspire)

#### Video Ingestion Trace Spans

- [X] T185b Add trace spans for video submission flow in services/api/src/api/services/video_service.py
  - Span: `video.submit` (root span for submission with video_id, youtube_video_id attributes)
  - Span: `video.metadata.fetch` (child span for YouTube metadata fetch with duration)
  - Span: `video.channel.get_or_create` (child span for channel lookup/creation)
  - Span: `video.persist` (child span for database insert)
  - Span: `job.queue` (child span for transcribe job queue message)
  - Add video_id, youtube_video_id, channel_id, job_id as span attributes

- [X] T186b Add trace spans to transcribe worker in services/workers/transcribe/worker.py
  - Span: `transcribe.process` (root span with job_id, video_id, youtube_video_id)
  - Span: `transcribe.youtube.fetch` (child span for YouTube API call with timing)
  - Span: `transcribe.blob.store` (child span for blob storage with content_length)
  - Span: `transcribe.artifact.persist` (child span for artifact DB record)
  - Span: `transcribe.queue.next` (child span for queuing summarize job)
  - Add error details as span events on failure, rate_limit_detected event on 429

- [X] T186c Add trace spans to summarize worker in services/workers/summarize/worker.py
  - Span: `summarize.process` (root span with job_id, video_id)
  - Span: `summarize.transcript.load` (child span for blob fetch)
  - Span: `summarize.openai.generate` (child span with model, token_count, latency)
  - Span: `summarize.blob.store` (child span for storing summary)
  - Span: `summarize.queue.next` (child span for queuing embed job)

- [X] T186d Add trace spans to embed worker in services/workers/embed/worker.py
  - Span: `embed.process` (root span with job_id, video_id)
  - Span: `embed.segments.create` (child span with segment_count attribute)
  - Span: `embed.openai.batch` (child span with batch_size, token_count)
  - Span: `embed.segments.persist` (child span for DB upserts)
  - Span: `embed.queue.next` (child span for queuing relationships job)

- [X] T186e Add trace spans to relationships worker in services/workers/relationships/worker.py
  - Span: `relationships.process` (root span with job_id, video_id)
  - Span: `relationships.extract` (child span for relationship extraction logic)
  - Span: `relationships.persist` (child span with relationship_count)
  - Span: `relationships.video.complete` (child span for marking video completed)

#### Trace Context Propagation

- [X] T187 Verify correlation ID propagation from UI → API → workers
  - UI: Include X-Correlation-ID header in all API requests (already exists in apps/web/src/services/correlation.ts)
  - API: Extract correlation ID and set as span attribute + baggage (update middleware/correlation.py)
  - Queue: Include trace context (traceparent, tracestate) in queue message body
  - Workers: Extract trace context from message and create child spans linked to parent

- [X] T187a Update queue message schema to include trace context in services/shared/shared/queue/client.py
  - Add traceparent and tracestate fields to job messages
  - Create helper: inject_trace_context(message: dict) → dict
  - Create helper: extract_trace_context(message: dict) → Context

- [X] T187b Update base worker to propagate trace context in services/workers/worker_utils/base_worker.py
  - Extract trace context from incoming message
  - Create span with extracted context as parent
  - Bind trace_id and span_id to structlog context for log correlation

#### Aspire Dashboard Integration

- [X] T185c Add OpenTelemetry environment variables to Aspire AppHost.cs
  - Set OTEL_EXPORTER_OTLP_ENDPOINT for API and all workers pointing to Aspire collector
  - Set OTEL_SERVICE_NAME for each resource (api, transcribe-worker, summarize-worker, embed-worker, relationships-worker)
  - Enable OTEL_TRACES_SAMPLER=always_on for development (100% sampling)

- [X] T185d Verify traces appear in Aspire dashboard with linked spans across services
  - Test: Submit video → verify single trace with spans from API through all 4 workers
  - Test: Failed job → verify error spans with exception details visible

#### Structured Logging Enhancements for Trace Correlation

- [X] T188 Add trace correlation to structured logs in services/shared/shared/logging/config.py
  - Add trace_id and span_id to log context automatically when tracing is active
  - Format: {"trace_id": "...", "span_id": "...", "correlation_id": "...", ...}
  - Enable log-to-trace linking in Aspire dashboard

- [X] T188a Create standardized log events for video ingestion pipeline stages
  - Log event: `video.submitted` (video_id, youtube_video_id, channel_id)
  - Log event: `job.started` (job_id, video_id, job_type, stage)
  - Log event: `job.completed` (job_id, video_id, job_type, duration_ms)
  - Log event: `job.failed` (job_id, video_id, job_type, error, retry_count)
  - Log event: `job.rate_limited` (job_id, video_id, retry_delay_seconds)
  - Log event: `video.completed` (video_id, youtube_video_id, total_duration_ms)

#### Diagnostic Runbooks

- [X] T188b [P] Create runbook: Investigating failed video ingestion in docs/runbooks/video-ingestion-troubleshooting.md
  - How to find traces for a specific video in Aspire dashboard
  - Common failure patterns: rate limiting, missing transcripts, OpenAI errors
  - How to retry failed jobs via API
  - How to identify which worker stage failed

- [X] T188c [P] Create runbook: Understanding video ingestion latency in docs/runbooks/video-ingestion-latency.md
  - How to identify slow stages using Aspire traces
  - Expected duration per stage (transcribe: 5-30s, summarize: 10-60s, embed: 5-20s, relationships: 2-10s)
  - Bottleneck identification: YouTube rate limits, OpenAI token limits, database contention

- [X] T188d [P] Create Log Analytics / Aspire structured log queries in docs/runbooks/observability-queries.md
  - Query: All failed jobs in last 24 hours with error details
  - Query: Average processing time per stage
  - Query: Rate limit occurrences by hour
  - Query: Videos stuck in processing (started > 1 hour ago, not completed)
  - Query: End-to-end latency percentiles (p50, p90, p99) for video ingestion

### Documentation

- [X] T196 [P] Create architecture overview in docs/architecture.md
  - System context diagram: User → Web → API → Workers → Storage/DB
  - Component diagram: All services with their responsibilities
  - Data flow: Video ingestion pipeline (submit → transcribe → summarize → embed → relationships)
  - Data flow: Copilot query (query → vector search → LLM → response)
  - Technology stack summary table
  - Key design decisions with rationale (Azure SQL for vectors, queue-based workers, CopilotKit)

- [X] T196a [P] Create API reference guide in docs/api-reference.md
  - Link to OpenAPI spec at /docs (FastAPI auto-generated)
  - Authentication: None (network boundary trust)
  - Common headers: X-Correlation-ID
  - Error response format with examples
  - Rate limiting: None currently, but respect YouTube rate limits in workers

- [X] T197 [P] Create operational runbook in docs/runbooks/operations.md
  - How to deploy a new version (CD pipeline or manual az commands)
  - How to roll back to previous version
  - How to scale workers up/down
  - How to check application health (API /health, Container Apps metrics)
  - How to view logs in Azure Portal / Log Analytics
  - How to restart a stuck worker
  - Cost monitoring: Which resources to watch, expected monthly cost range

- [X] T197a [P] Create incident response runbook in docs/runbooks/incident-response.md
  - Severity levels: P1 (all ingestion failing), P2 (specific worker down), P3 (degraded performance)
  - First responder checklist: Check health endpoint, check Aspire traces, check worker logs
  - Common incidents:
    - YouTube rate limiting → Wait 5-15 min, check transcribe-worker logs
    - OpenAI API errors → Check API key validity, check Azure OpenAI status page
    - Database connection failures → Check SQL Server status, check firewall rules
    - Queue message poison → Check dead-letter queue, inspect message content

- [X] T198 Run quickstart.md validation and update as needed
  - Verify all commands in quickstart.md work on clean checkout
  - Update versions if dependencies have changed
  - Add troubleshooting section for common setup issues
  - Verify E2E test scenario in quickstart.md passes

- [X] T198a [P] Create developer onboarding guide in docs/developer-guide.md
  - Prerequisites: Node.js, Python 3.11+, .NET 8, Docker, Azure CLI
  - Repository structure overview
  - How to run locally with Aspire
  - How to run tests (API, workers, frontend, E2E)
  - How to add a new worker stage
  - How to add a new API endpoint
  - Code style and linting (ruff, ESLint/Prettier)

---

## Dependencies & Execution Order

### Phase Dependencies

```
Phase 1 (Setup) ─────────────┐
                             ▼
Phase 2 (Foundational) ──────┬───────────────────────────────────────────────┐
                             │                                               │
                             ▼                                               ▼
              ┌─────────────────────────────┐                    ┌─────────────────────┐
              │  Phase 3: US1 (P1) 🎯 MVP   │                    │ Phase 4: US3 (P2)   │
              │  Single Video Ingestion     │                    │ Browse Library      │
              └──────────────┬──────────────┘                    └──────────┬──────────┘
                             │                                               │
                             ├───────────────────────────────────────────────┘
                             ▼
              ┌─────────────────────────────┐
              │  Phase 5: US2 (P2)          │
              │  Batch Ingestion            │
              └──────────────┬──────────────┘
                             │
                             ▼
              ┌─────────────────────────────┐
              │  Phase 6: US4 (P1) 🎯       │
              │  Copilot Query              │
              └──────────────┬──────────────┘
                             │
              ┌──────────────┴──────────────┐
              ▼                             ▼
┌─────────────────────────┐   ┌─────────────────────────┐
│  Phase 7: US5 (P3)      │   │  Phase 8: US6 (P3)      │
│  Explain Why            │   │  Structured Outputs     │
└───────────┬─────────────┘   └───────────┬─────────────┘
            │                             │
            └──────────────┬──────────────┘
                           ▼
              ┌─────────────────────────────┐
              │  Phase 9: Polish            │
              │  Deployment & Observability │
              └─────────────────────────────┘
```

### User Story Dependencies

| Story | Depends On | Can Parallelize With |
|-------|-----------|---------------------|
| US1 (Single Video) | Foundational only | US3 (after workers exist) |
| US3 (Browse Library) | Foundational only | US1 (after models exist) |
| US2 (Batch Ingestion) | US1 (workers), US3 (browse) | — |
| US4 (Copilot Query) | US1 (content), US3 (browse) | — |
| US5 (Explain Why) | US4 (copilot) | US6 |
| US6 (Synthesis) | US4 (copilot) | US5 |

### Within Each User Story

1. API models (Pydantic) → can parallelize
2. API services → depend on models
3. API routes → depend on services
4. Frontend components → can parallelize many
5. Frontend pages → depend on components

### Parallel Opportunities

**Phase 1 (Setup)**: T002, T003, T004, T005, T006, T007 can all run in parallel

**Phase 2 (Foundational)**: T020, T021, T022, T023, T024, T25 can run in parallel after migrations

**Phase 3 (US1)**: 
- T035, T040 (models) can run in parallel
- T049, T050, T053, T054 (components) can run in parallel

**Phase 4 (US3)**:
- T056, T060, T062 (models) can run in parallel
- T065, T066, T067, T068, T069 (filter components) can run in parallel

---

## Parallel Example: MVP Development

For fastest MVP (US1 + US4):

```text
Day 1-2: Phase 1 Setup (all parallel)
├── T001 Create structure
├── T002 Init Next.js
├── T003 Init API
├── T004 Init Workers
├── T005 Init Shared
└── T006 Init Aspire

Day 3-4: Phase 2 Foundation
├── T011-T019 Migrations (sequential)
└── T020-T034 Infrastructure (parallel after migrations)

Day 5-7: US1 Core
├── T035-T044 API (models → services → routes)
├── T045-T048 Workers (parallel)
└── T049-T055 Frontend (parallel)

Day 8-9: US4 Copilot
├── T090-T097 API
└── T098-T107 Frontend + CopilotKit

MVP Complete: Single video ingestion + copilot query
```

---

## Implementation Strategy

### MVP Scope (Recommended)

**Target**: User Story 1 (Single Video) + User Story 4 (Copilot Query)

This delivers:
- Submit a video → transcribe → summarize → embed
- Ask questions with citations
- Core value proposition validated

### Incremental Delivery

1. **Increment 1 (MVP)**: US1 + US4 — Ask questions about ingested videos
2. **Increment 2**: US3 — Browse and filter library
3. **Increment 3**: US2 — Batch ingestion from channels
4. **Increment 4**: US5 + US6 — Transparency and synthesis

### Risk Mitigation

| Risk | Mitigation in Tasks |
|------|-------------------|
| YouTube caption access | T045 includes fallback to yt-dlp + Whisper |
| Vector search latency | T103 implements exact search first; add HNSW later |
| LLM grounding quality | T105, T108 handle uncertainty explicitly |
| Cold start UX | T181a-T181l: Health endpoint includes uptime, UI polls and shows "Warming up" indicator, auto-retries on degraded status |
| YouTube rate limiting | T074 uses yt-dlp with backoff for channel extraction; T175-T177 add content validation and retry |
| Debugging ingestion failures | T185-T188d: End-to-end OpenTelemetry tracing with Aspire dashboard integration, trace context propagation across all workers |

---

## Summary

| Metric | Count |
|--------|-------|
| **Total Tasks** | 237 |
| **Setup Phase** | 10 |
| **Foundational Phase** | 24 |
| **US1 (Single Video)** | 21 |
| **US2 (Batch Ingestion)** | 23 |
| **US3 (Browse Library)** | 17 |
| **US4 (Copilot Query)** | 37 |
| **US5 (Explain Why)** | 13 |
| **US6 (Synthesis)** | 15 |
| **Worker Resilience** | 6 |
| **Polish Phase** | 57 |
| **Parallel Tasks** | ~105 (44%) |

**MVP Scope**: Phases 1-3 + Phase 6 = ~92 tasks for core value delivery

**Phase 10 Breakdown**:
- Error Handling & UX: 16 tasks (T181a-T184)
- Observability: 21 tasks (T185-T188d)
- Documentation: 6 tasks (T196-T198a)

**Deferred to Future Specs**:
- Admin functionality (dead-letter visibility, job management, system monitoring)
- Azure Deployment (Bicep modules, CI/CD pipelines, Container Apps configuration)
