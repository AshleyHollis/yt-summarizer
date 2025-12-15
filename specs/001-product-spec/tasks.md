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

### Tests for US4

- [X] T130 [P] [US4] Create API tests for copilot endpoints in services/api/tests/test_copilot.py
- [X] T131 [P] [US4] Create integration tests for vector search in services/api/tests/test_search_service.py
- [X] T132 [P] [US4] Create E2E tests for copilot query flow in apps/web/e2e/copilot.spec.ts
- [X] T132a [P] [US4] Create unit tests for agent module and AG-UI endpoint registration in services/api/tests/test_agents.py

**Checkpoint**: User Story 4 complete — full copilot query with scope visibility, citations, follow-ups ✅

---

## Phase 7: User Story 5 — "Explain Why" (Transparency) (Priority: P3)

**Goal**: For any recommended video, user sees why it was recommended — similarity basis, relationship basis, evidence

**Independent Test**: After a query, click "Why this?" on a video card, see explanation with evidence links

### API Implementation for US5

- [ ] T133 [P] [US5] Create ExplainRequest model (queryText, scope) in services/api/src/api/models/explanation.py
- [ ] T134 [P] [US5] Create ExplainResponse model (similarityBasis, relationshipBasis, overallConfidence) in services/api/src/api/models/explanation.py
- [ ] T135 [P] [US5] Create SimilarityEvidence model (segmentId, segmentText, startTime, score) in services/api/src/api/models/explanation.py
- [ ] T136 [P] [US5] Create RelationshipEvidence model (relationshipType, relatedVideoId, confidence, rationale) in services/api/src/api/models/explanation.py
- [ ] T137 [US5] Implement explanation service in services/api/src/api/services/explanation_service.py
- [ ] T138 [US5] Implement POST /api/v1/copilot/explain/{videoId} endpoint in services/api/src/api/routes/copilot.py

### Frontend for US5

- [ ] T139 [US5] Create "Why this?" button on video cards in apps/web/src/components/copilot/WhyThisButton.tsx
- [ ] T140 [US5] Create explanation panel component in apps/web/src/components/copilot/ExplanationPanel.tsx
- [ ] T141 [P] [US5] Create similarity evidence display in apps/web/src/components/copilot/SimilarityEvidence.tsx
- [ ] T142 [P] [US5] Create relationship evidence display in apps/web/src/components/copilot/RelationshipEvidence.tsx
- [ ] T143 [US5] Add clickable evidence segments linking to video timestamps

### Tests for US5

- [ ] T144 [P] [US5] Create API tests for explain endpoint in services/api/tests/test_explain.py
- [ ] T145 [P] [US5] Create E2E tests for "Why this?" flow in apps/web/e2e/explain.spec.ts

**Checkpoint**: User Story 5 complete — transparency for all recommendations

---

## Phase 8: User Story 6 — Synthesize Structured Outputs (Priority: P3)

**Goal**: User asks copilot to create learning paths, watch lists synthesized from library content

**Independent Test**: With 10+ related videos, ask for a "learning path", receive ordered list with citations

### API Implementation for US6

- [ ] T146 [P] [US6] Create LearningPath model (items with order, rationale, videoId, evidence) in services/api/src/api/models/synthesis.py
- [ ] T147 [P] [US6] Create WatchList model (items with videoId, reason, priority) in services/api/src/api/models/synthesis.py
- [ ] T148 [US6] Implement synthesis service in services/api/src/api/services/synthesis_service.py
- [ ] T149 [US6] Add structured output tools to copilot query handler in services/api/src/api/services/copilot_service.py
- [ ] T150 [US6] Implement POST /api/v1/copilot/synthesize endpoint in services/api/src/api/routes/copilot.py

### Frontend for US6

- [ ] T151 [US6] Create learning path renderer in apps/web/src/components/copilot/LearningPathView.tsx
- [ ] T152 [P] [US6] Create watch list renderer in apps/web/src/components/copilot/WatchListView.tsx
- [ ] T153 [US6] Add rationale display for each item in structured outputs
- [ ] T154 [US6] Add "what's missing" messaging when content insufficient for synthesis

### Tests for US6

- [ ] T155 [P] [US6] Create API tests for synthesis endpoint in services/api/tests/test_synthesis.py
- [ ] T156 [P] [US6] Create E2E tests for synthesis flow in apps/web/e2e/synthesis.spec.ts

**Checkpoint**: User Story 6 complete — full synthesis capabilities

---

## Phase 9: Polish & Cross-Cutting Concerns

**Purpose**: Production readiness, deployment, observability

### Error Handling & UX Polish

- [ ] T157 [P] Implement serverless DB wake-up handling with "Warming up" toast in apps/web
- [ ] T158 [P] Add dead-letter visibility page in apps/web/src/app/jobs/dead-letter/page.tsx
- [ ] T159 [P] Create global error boundary in apps/web/src/app/error.tsx
- [ ] T160 Add loading skeletons for all async data fetches

### Observability

- [ ] T161 [P] Add OpenTelemetry SDK to Python API in services/api
- [ ] T162 [P] Add OpenTelemetry to workers in services/workers
- [ ] T163 Verify correlation ID propagation from UI → API → workers
- [ ] T164 [P] Create Log Analytics queries for common issues in docs/runbooks/

### Infrastructure

- [ ] T165 [P] Create Bicep module for Azure SQL in infra/bicep/modules/sql.bicep
- [ ] T166 [P] Create Bicep module for Storage (blob + queue) in infra/bicep/modules/storage.bicep
- [ ] T167 [P] Create Bicep module for Container Apps in infra/bicep/modules/aca.bicep
- [ ] T168 [P] Create Bicep module for Key Vault in infra/bicep/modules/keyvault.bicep
- [ ] T169 Create main.bicep composing all modules in infra/bicep/main.bicep
- [ ] T170 [P] Create GitHub Actions workflow for CI in .github/workflows/ci.yml
- [ ] T171 [P] Create GitHub Actions workflow for CD in .github/workflows/deploy.yml

### Documentation

- [ ] T172 [P] Create architecture overview in docs/architecture.md
- [ ] T173 [P] Create operational runbook in docs/runbooks/operations.md
- [ ] T174 Run quickstart.md validation and update as needed

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
| Cold start UX | T157 adds "Warming up" toast |
| YouTube rate limiting | T074 uses yt-dlp with backoff for channel extraction |

---

## Summary

| Metric | Count |
|--------|-------|
| **Total Tasks** | 174 |
| **Setup Phase** | 10 |
| **Foundational Phase** | 24 |
| **US1 (Single Video)** | 21 |
| **US2 (Batch Ingestion)** | 23 |
| **US3 (Browse Library)** | 17 |
| **US4 (Copilot Query)** | 37 |
| **US5 (Explain Why)** | 13 |
| **US6 (Synthesis)** | 11 |
| **Polish Phase** | 18 |
| **Parallel Tasks** | ~85 (49%) |

**MVP Scope**: Phases 1-3 + Phase 6 = ~92 tasks for core value delivery
