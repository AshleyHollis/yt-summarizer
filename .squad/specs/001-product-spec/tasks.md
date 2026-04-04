# Tasks: YT Summarizer Product Foundation

**Status**: Implementing
**Milestone**: M1
**Spec Phase**: execution
**Created**: 2025-12-13
**Updated**: 2026-04-04

> Converted from `specs/001-product-spec/tasks.md`. All 220 tasks completed.
> Format: `[x]` = done, `[P]` = parallel-eligible, **Agent** = assignee.

---

## Phase 1: Setup (Shared Infrastructure) ✅

**Goal**: Project initialisation, mono-repo structure, development environment.

- [x] T001 Create mono-repo structure (apps/, services/, db/, infra/, docs/)
  - **Files**: `apps/`, `services/`, `infra/`, `docs/`, `db/`
  - **Agent**: Dallas
  - **Done when**: Directory structure matches plan.md
  - **Verify**: `Get-ChildItem -Directory`
  - _Requirements: —_

- [x] T002 [P] Initialize Next.js app in apps/web/ with TypeScript, TailwindCSS, App Router
  - **Files**: `apps/web/package.json`, `apps/web/next.config.js`, `apps/web/tailwind.config.js`
  - **Agent**: Lambert
  - **Done when**: `npm run build` succeeds in apps/web
  - **Verify**: `cd apps/web && npm run build`
  - _Requirements: —_

- [x] T003 [P] Initialize Python API project in services/api/ with FastAPI, pyproject.toml
  - **Files**: `services/api/pyproject.toml`, `services/api/src/api/main.py`
  - **Agent**: Ripley
  - **Done when**: `uv run uvicorn` starts without error
  - **Verify**: `cd services/api && uv run python -c "from api.main import app"`
  - _Requirements: —_

- [x] T004 [P] Initialize Python workers project in services/workers/
  - **Files**: `services/workers/pyproject.toml`
  - **Agent**: Ripley
  - **Done when**: Package installs cleanly
  - **Verify**: `cd services/workers && uv sync`
  - _Requirements: —_

- [x] T005 [P] Initialize shared Python package in services/shared/
  - **Files**: `services/shared/pyproject.toml`
  - **Agent**: Ripley
  - **Done when**: Package importable by API and workers
  - **Verify**: `cd services/shared && uv sync`
  - _Requirements: —_

- [x] T006 [P] Create .NET Aspire AppHost in services/aspire/AppHost/AppHost.cs
  - **Files**: `services/aspire/AppHost/AppHost.cs`, `services/aspire/AppHost/AppHost.csproj`
  - **Agent**: Parker
  - **Done when**: `dotnet build` succeeds
  - **Verify**: `cd services/aspire/AppHost && dotnet build`
  - _Requirements: —_

- [x] T007 [P] Configure linting: ESLint + Prettier for web, ruff for Python
  - **Files**: `apps/web/.eslintrc.json`, `services/api/pyproject.toml` (ruff config)
  - **Agent**: Dallas
  - **Done when**: `npm run lint` and `uv run ruff check .` pass
  - **Verify**: `cd apps/web && npm run lint`
  - _Requirements: —_

- [x] T008 Create docker-compose or Aspire emulators for local Azurite
  - **Files**: `docker-compose.yml`, or Aspire Azurite resource
  - **Agent**: Parker
  - **Done when**: Azurite starts locally
  - **Verify**: `docker compose up azurite -d`
  - _Requirements: —_

- [x] T009 [P] Create .env.example files for all services
  - **Files**: `services/api/.env.example`, `services/workers/.env.example`
  - **Agent**: Parker
  - **Done when**: All required env vars documented
  - **Verify**: File exists with all required vars
  - _Requirements: —_

- [x] T010 [P] Create README.md with development setup instructions
  - **Files**: `README.md`
  - **Agent**: Dallas
  - **Done when**: New dev can follow README to run locally
  - **Verify**: README exists with setup steps
  - _Requirements: —_

---

## Phase 2: Foundational (Blocking Prerequisites) ✅

**Goal**: Core infrastructure that must be complete before any user story implementation.

### Database & Migrations

- [x] T011 Create Alembic configuration in services/shared/alembic/
  - **Files**: `services/shared/alembic/alembic.ini`, `services/shared/alembic/env.py`
  - **Agent**: Ripley
  - **Done when**: `uv run alembic current` runs without error
  - **Verify**: `cd services/shared && uv run alembic current`
  - _Requirements: —_

- [x] T012 Create SQLAlchemy models for Channels, Videos
  - **Files**: `services/shared/shared/db/models/channel.py`, `services/shared/shared/db/models/video.py`
  - **Agent**: Ripley
  - **Done when**: Models import without error; relationships defined
  - **Verify**: `uv run python -c "from shared.db.models import Channel, Video"`
  - _Requirements: FR-001_

- [x] T013 Create migration 001_initial_schema.py for Channels and Videos
  - **Files**: `services/shared/alembic/versions/001_initial_schema.py`
  - **Agent**: Ripley
  - **Done when**: `alembic upgrade head` creates tables
  - **Verify**: `cd services/shared && uv run alembic upgrade head`
  - _Requirements: FR-001_

- [x] T014 Create SQLAlchemy models for Batches, BatchItems, Jobs
  - **Files**: `services/shared/shared/db/models/batch.py`, `services/shared/shared/db/models/job.py`
  - **Agent**: Ripley
  - **Done when**: Models importable; FK relations defined
  - **Verify**: `uv run python -c "from shared.db.models import Batch, Job"`
  - _Requirements: FR-003, FR-005_

- [x] T015 Create migration 002_batches_and_jobs.py
  - **Files**: `services/shared/alembic/versions/002_batches_and_jobs.py`
  - **Agent**: Ripley
  - **Done when**: Migration applies cleanly
  - **Verify**: `uv run alembic upgrade head`
  - _Requirements: FR-003, FR-005_

- [x] T016 Create SQLAlchemy models for Artifacts, Segments
  - **Files**: `services/shared/shared/db/models/artifact.py`, `services/shared/shared/db/models/segment.py`
  - **Agent**: Ripley
  - **Done when**: Segment model has VECTOR(1536) column
  - **Verify**: `uv run python -c "from shared.db.models import Artifact, Segment"`
  - _Requirements: FR-002_

- [x] T017 Create migration 003_artifacts_and_segments.py with VECTOR(1536)
  - **Files**: `services/shared/alembic/versions/003_artifacts_and_segments.py`
  - **Agent**: Ripley
  - **Done when**: VECTOR column exists in Segments table
  - **Verify**: `uv run alembic upgrade head`
  - _Requirements: FR-002_

- [x] T018 Create SQLAlchemy models for Relationships, Facets, VideoFacets
  - **Files**: `services/shared/shared/db/models/relationship.py`, `services/shared/shared/db/models/facet.py`
  - **Agent**: Ripley
  - **Done when**: Models importable; Relationship has type, confidence, rationale, evidence
  - **Verify**: `uv run python -c "from shared.db.models import Relationship, Facet"`
  - _Requirements: FR-018_

- [x] T019 Create migration 004_relationships_and_facets.py
  - **Files**: `services/shared/alembic/versions/004_relationships_and_facets.py`
  - **Agent**: Ripley
  - **Done when**: Tables created in DB
  - **Verify**: `uv run alembic upgrade head`
  - _Requirements: FR-018_

### Shared Infrastructure

- [x] T020 [P] Implement database connection factory in services/shared/db/connection.py
  - **Files**: `services/shared/shared/db/connection.py`
  - **Agent**: Ripley
  - **Done when**: Connection factory includes retry logic; usable from API and workers
  - **Verify**: `uv run python -c "from shared.db.connection import get_session"`
  - _Requirements: FR-020_

- [x] T021 [P] Implement Azure Blob client wrapper in services/shared/blob/client.py
  - **Files**: `services/shared/shared/blob/client.py`
  - **Agent**: Ripley
  - **Done when**: Upload/download/list operations work against Azurite
  - **Verify**: `cd services/api && uv run pytest tests/test_blob.py`
  - _Requirements: FR-002_

- [x] T022 [P] Implement Azure Storage Queue client wrapper
  - **Files**: `services/shared/shared/queue/client.py`
  - **Agent**: Ripley
  - **Done when**: Enqueue/dequeue operations work against Azurite
  - **Verify**: `cd services/api && uv run pytest tests/test_queue.py`
  - _Requirements: FR-003_

- [x] T023 [P] Implement structured logging (structlog)
  - **Files**: `services/shared/shared/logging/config.py`
  - **Agent**: Ripley
  - **Done when**: JSON logs emitted with timestamp, severity, correlation_id
  - **Verify**: `uv run python -c "from shared.logging.config import get_logger"`
  - _Requirements: FR-025_

- [x] T024 [P] Implement correlation ID middleware for FastAPI
  - **Files**: `services/api/src/api/middleware/correlation.py`
  - **Agent**: Ripley
  - **Done when**: X-Correlation-ID extracted/generated per request; added to logs
  - **Verify**: `cd services/api && uv run pytest tests/test_middleware.py`
  - _Requirements: FR-023_

- [x] T025 [P] Create Pydantic settings for configuration
  - **Files**: `services/shared/shared/config.py`
  - **Agent**: Ripley
  - **Done when**: Settings load from environment variables with defaults
  - **Verify**: `uv run python -c "from shared.config import Settings"`
  - _Requirements: —_

### API Foundation

- [x] T026 Create FastAPI app factory with CORS, error handlers
  - **Files**: `services/api/src/api/main.py`
  - **Agent**: Ripley
  - **Done when**: App starts; CORS configured; 404/500 handlers return JSON
  - **Verify**: `cd services/api && uv run uvicorn api.main:app`
  - _Requirements: FR-010_

- [x] T027 [P] Implement health check endpoint GET /health
  - **Files**: `services/api/src/api/routes/health.py`
  - **Agent**: Ripley
  - **Done when**: `/health` returns status, uptime_seconds, started_at
  - **Verify**: `cd services/api && uv run pytest tests/test_health.py`
  - _Requirements: FR-020a_

- [x] T028 [P] Create base Pydantic response models (ErrorResponse, PaginatedResponse)
  - **Files**: `services/api/src/api/models/base.py`
  - **Agent**: Ripley
  - **Done when**: Models importable; used across all routes
  - **Verify**: `uv run python -c "from api.models.base import ErrorResponse"`
  - _Requirements: FR-009_

- [x] T029 Configure Dockerfile for API
  - **Files**: `services/api/Dockerfile`
  - **Agent**: Parker
  - **Done when**: `docker build` succeeds; container starts
  - **Verify**: `docker build -t yt-summarizer-api services/api`
  - _Requirements: —_

### Worker Foundation

- [x] T030 Create worker base class with queue polling
  - **Files**: `services/workers/worker_utils/base_worker.py`
  - **Agent**: Ripley
  - **Done when**: Base class polls queue; handles visibility timeout; retries
  - **Verify**: `uv run python -c "from worker_utils.base_worker import BaseWorker"`
  - _Requirements: FR-021_

- [x] T031 [P] Configure Dockerfile for workers
  - **Files**: `services/workers/Dockerfile`
  - **Agent**: Parker
  - **Done when**: `docker build` succeeds
  - **Verify**: `docker build -t yt-summarizer-worker services/workers`
  - _Requirements: —_

### Frontend Foundation

- [x] T032 Create API client service in apps/web/src/services/api.ts
  - **Files**: `apps/web/src/services/api.ts`
  - **Agent**: Lambert
  - **Done when**: Type-safe fetch wrapper with retry logic; X-Correlation-ID header injected
  - **Verify**: `cd apps/web && npm test -- api`
  - _Requirements: FR-023, FR-020c_

- [x] T033 [P] Create base layout component
  - **Files**: `apps/web/src/app/layout.tsx`
  - **Agent**: Lambert
  - **Done when**: Layout renders; navigation present
  - **Verify**: `cd apps/web && npm run build`
  - _Requirements: —_

- [x] T034 [P] Configure environment variables in next.config.js
  - **Files**: `apps/web/next.config.js`
  - **Agent**: Lambert
  - **Done when**: `NEXT_PUBLIC_API_URL` available in client code
  - **Verify**: `cd apps/web && npm run build`
  - _Requirements: —_

- [x] T034a [P] Implement correlation ID generator
  - **Files**: `apps/web/src/services/correlation.ts`
  - **Agent**: Lambert
  - **Done when**: UUID generated per request; included in API calls
  - **Verify**: `cd apps/web && npm test -- correlation`
  - _Requirements: FR-023_

---

## Phase 3: User Story 1 — Ingest a Single Video ✅

**Goal**: User submits a YouTube URL, watches progress, views completed summary and transcript.

- [x] T035 [US1] Create video Pydantic models (SubmitVideoRequest, VideoResponse)
  - **Files**: `services/api/src/api/models/video.py`
  - **Agent**: Ripley
  - **Done when**: Models importable; VideoResponse includes status, stages
  - **Verify**: `uv run python -c "from api.models.video import SubmitVideoRequest"`
  - _Requirements: FR-001, FR-003_

- [x] T036 [US1] Implement video service with submit logic
  - **Files**: `services/api/src/api/services/video_service.py`
  - **Agent**: Ripley
  - **Done when**: submit() creates Video + Job + enqueues transcribe message
  - **Verify**: `cd services/api && uv run pytest tests/test_video_service.py`
  - _Requirements: FR-001, FR-006_

- [x] T037 [US1] Implement POST /api/v1/videos endpoint
  - **Files**: `services/api/src/api/routes/videos.py`
  - **Agent**: Ripley
  - **Done when**: Returns 201 with videoId; duplicate detection works
  - **Verify**: `cd services/api && uv run pytest tests/test_videos.py`
  - _Requirements: FR-001, FR-006_

- [x] T038 [US1] Implement GET /api/v1/videos/{videoId} endpoint
  - **Files**: `services/api/src/api/routes/videos.py`
  - **Agent**: Ripley
  - **Done when**: Returns video details with current status
  - **Verify**: `cd services/api && uv run pytest tests/test_videos.py`
  - _Requirements: FR-003_

- [x] T039 [US1] Implement POST /api/v1/videos/{videoId}/reprocess endpoint
  - **Files**: `services/api/src/api/routes/videos.py`
  - **Agent**: Ripley
  - **Done when**: Re-queues failed video; returns 202
  - **Verify**: `cd services/api && uv run pytest tests/test_videos.py`
  - _Requirements: FR-004_

- [x] T040 [P] [US1] Create job Pydantic models
  - **Files**: `services/api/src/api/models/job.py`
  - **Agent**: Ripley
  - **Done when**: JobResponse includes stage, status, timestamps, error
  - **Verify**: `uv run python -c "from api.models.job import JobResponse"`
  - _Requirements: FR-003_

- [x] T041 [US1] Implement job service
  - **Files**: `services/api/src/api/services/job_service.py`
  - **Agent**: Ripley
  - **Done when**: get/list/retry operations work
  - **Verify**: `cd services/api && uv run pytest tests/test_job_service.py`
  - _Requirements: FR-003, FR-004_

- [x] T042 [US1] Implement GET /api/v1/jobs/{jobId}
  - **Files**: `services/api/src/api/routes/jobs.py`
  - **Agent**: Ripley
  - **Done when**: Returns job details with stage and error
  - **Verify**: `cd services/api && uv run pytest tests/test_jobs.py`
  - _Requirements: FR-003_

- [x] T043 [US1] Implement GET /api/v1/jobs (list with filters)
  - **Files**: `services/api/src/api/routes/jobs.py`
  - **Agent**: Ripley
  - **Done when**: Filterable by status, videoId, batchId; paginated
  - **Verify**: `cd services/api && uv run pytest tests/test_jobs.py`
  - _Requirements: FR-003, FR-009_

- [x] T044 [US1] Implement POST /api/v1/jobs/{jobId}/retry
  - **Files**: `services/api/src/api/routes/jobs.py`
  - **Agent**: Ripley
  - **Done when**: Re-queues failed job; returns 202
  - **Verify**: `cd services/api && uv run pytest tests/test_jobs.py`
  - _Requirements: FR-004_

- [x] T045 [US1] Implement transcribe worker
  - **Files**: `services/workers/transcribe/worker.py`
  - **Agent**: Ripley
  - **Done when**: Fetches YouTube captions via yt-dlp; stores VTT to blob; parses timestamps
  - **Verify**: `cd services/workers && uv run pytest tests/test_transcribe.py`
  - _Requirements: FR-002, FR-026, FR-027_

- [x] T046 [US1] Implement summarize worker
  - **Files**: `services/workers/summarize/worker.py`
  - **Agent**: Ripley
  - **Done when**: Loads transcript from blob; generates GPT-4o summary; stores to blob
  - **Verify**: `cd services/workers && uv run pytest tests/test_summarize.py`
  - _Requirements: FR-002_

- [x] T047 [US1] Implement embed worker
  - **Files**: `services/workers/embed/worker.py`
  - **Agent**: Ripley
  - **Done when**: Chunks transcript; generates embeddings in batch; upserts Segments
  - **Verify**: `cd services/workers && uv run pytest tests/test_embed.py`
  - _Requirements: FR-002, FR-006_

- [x] T048 [US1] Implement relationships worker
  - **Files**: `services/workers/relationships/worker.py`
  - **Agent**: Ripley
  - **Done when**: Extracts LLM relationships; upserts Relationships; marks video completed
  - **Verify**: `cd services/workers && uv run pytest tests/test_relationships.py`
  - _Requirements: FR-002, FR-018_

- [x] T049 [US1] Create video submission form component
  - **Files**: `apps/web/src/components/ingestion/SubmitVideoForm.tsx`
  - **Agent**: Lambert
  - **Done when**: Form validates YouTube URL; shows submit button; handles loading state
  - **Verify**: `cd apps/web && npm test -- SubmitVideoForm`
  - _Requirements: FR-001_

- [x] T050 [US1] Create job progress component
  - **Files**: `apps/web/src/components/jobs/JobProgress.tsx`
  - **Agent**: Lambert
  - **Done when**: Shows pipeline stages with status indicators; polls for updates
  - **Verify**: `cd apps/web && npm test -- JobProgress`
  - _Requirements: FR-003, FR-024_

- [x] T051 [US1] Create submit video page
  - **Files**: `apps/web/src/app/ingest/page.tsx`
  - **Agent**: Lambert
  - **Done when**: Page renders SubmitVideoForm; navigates to job on success
  - **Verify**: `cd apps/web && npm run build`
  - _Requirements: FR-001_

- [x] T052 [US1] Create video detail page
  - **Files**: `apps/web/src/app/videos/[videoId]/page.tsx`
  - **Agent**: Lambert
  - **Done when**: Shows title, thumbnail, summary, transcript, segments
  - **Verify**: `cd apps/web && npm run build`
  - _Requirements: FR-008_

- [x] T053 [US1] Create transcript viewer component
  - **Files**: `apps/web/src/components/library/TranscriptViewer.tsx`
  - **Agent**: Lambert
  - **Done when**: Renders full transcript; sections are navigable
  - **Verify**: `cd apps/web && npm test -- TranscriptViewer`
  - _Requirements: FR-008_

- [x] T054 [US1] Create summary display component
  - **Files**: `apps/web/src/components/library/SummaryCard.tsx`
  - **Agent**: Lambert
  - **Done when**: Renders AI summary with appropriate formatting
  - **Verify**: `cd apps/web && npm test -- SummaryCard`
  - _Requirements: FR-008_

- [x] T055 [US1] Add retry button with error message display
  - **Files**: `apps/web/src/components/jobs/JobProgress.tsx`
  - **Agent**: Lambert
  - **Done when**: Failed jobs show error message and Retry button
  - **Verify**: `cd apps/web && npm test -- JobProgress`
  - _Requirements: FR-004, FR-022_

---

## Phase 4: User Story 3 — Browse the Library ✅

**Goal**: User filters library by channel, time range, facets; opens video detail pages.

- [x] T056 [P] [US3] Create library Pydantic models (VideoListResponse, filters)
  - **Files**: `services/api/src/api/models/library.py`
  - **Agent**: Ripley
  - **Done when**: Models include filter params; paginated response
  - **Verify**: `uv run python -c "from api.models.library import VideoListResponse"`
  - _Requirements: FR-007, FR-009_

- [x] T057 [US3] Implement library service with filter logic
  - **Files**: `services/api/src/api/services/library_service.py`
  - **Agent**: Ripley
  - **Done when**: SQL filters by channel, dateRange, facets; returns paginated results
  - **Verify**: `cd services/api && uv run pytest tests/test_library_service.py`
  - _Requirements: FR-007_

- [x] T058 [US3] Implement GET /api/v1/library/videos with filters
  - **Files**: `services/api/src/api/routes/library.py`
  - **Agent**: Ripley
  - **Done when**: Returns filtered, paginated video list
  - **Verify**: `cd services/api && uv run pytest tests/test_library.py`
  - _Requirements: FR-007, FR-009_

- [x] T059 [US3] Implement GET /api/v1/library/videos/{videoId}/segments
  - **Files**: `services/api/src/api/routes/library.py`
  - **Agent**: Ripley
  - **Done when**: Returns timestamped segments for a video
  - **Verify**: `cd services/api && uv run pytest tests/test_library.py`
  - _Requirements: FR-008_

- [x] T060 [P] [US3] Create channel Pydantic models
  - **Files**: `services/api/src/api/models/channel.py`
  - **Agent**: Ripley
  - **Done when**: ChannelResponse, ChannelListResponse models defined
  - **Verify**: `uv run python -c "from api.models.channel import ChannelResponse"`
  - _Requirements: FR-007_

- [x] T061 [US3] Implement GET /api/v1/library/channels
  - **Files**: `services/api/src/api/routes/library.py`
  - **Agent**: Ripley
  - **Done when**: Returns list of channels with video counts
  - **Verify**: `cd services/api && uv run pytest tests/test_library.py`
  - _Requirements: FR-007_

- [x] T062 [P] [US3] Create facet Pydantic models
  - **Files**: `services/api/src/api/models/facet.py`
  - **Agent**: Ripley
  - **Done when**: FacetResponse with name, type, count
  - **Verify**: `uv run python -c "from api.models.facet import FacetResponse"`
  - _Requirements: FR-007_

- [x] T063 [US3] Implement GET /api/v1/library/facets
  - **Files**: `services/api/src/api/routes/library.py`
  - **Agent**: Ripley
  - **Done when**: Returns facets with counts
  - **Verify**: `cd services/api && uv run pytest tests/test_library.py`
  - _Requirements: FR-007_

- [x] T064 [US3] Create library page
  - **Files**: `apps/web/src/app/library/page.tsx`
  - **Agent**: Lambert
  - **Done when**: Page renders video grid with filter sidebar
  - **Verify**: `cd apps/web && npm run build`
  - _Requirements: FR-007_

- [x] T065 [P] [US3] Create video card component
  - **Files**: `apps/web/src/components/library/VideoCard.tsx`
  - **Agent**: Lambert
  - **Done when**: Shows thumbnail, title, channel, duration, status badge
  - **Verify**: `cd apps/web && npm test -- VideoCard`
  - _Requirements: FR-007_

- [x] T066 [P] [US3] Create filter sidebar component
  - **Files**: `apps/web/src/components/library/FilterSidebar.tsx`
  - **Agent**: Lambert
  - **Done when**: Renders channel, date range, facet filter controls
  - **Verify**: `cd apps/web && npm test -- FilterSidebar`
  - _Requirements: FR-007_

- [x] T067 [P] [US3] Create channel filter component
  - **Files**: `apps/web/src/components/library/ChannelFilter.tsx`
  - **Agent**: Lambert
  - **Done when**: Multi-select channel filter; applies on change
  - **Verify**: `cd apps/web && npm test -- ChannelFilter`
  - _Requirements: FR-007_

- [x] T068 [P] [US3] Create date range picker component
  - **Files**: `apps/web/src/components/library/DateRangePicker.tsx`
  - **Agent**: Lambert
  - **Done when**: Date range filter applies to library results
  - **Verify**: `cd apps/web && npm test -- DateRangePicker`
  - _Requirements: FR-007_

- [x] T069 [P] [US3] Create facet chips component
  - **Files**: `apps/web/src/components/library/FacetChips.tsx`
  - **Agent**: Lambert
  - **Done when**: Clickable facet chips filter results
  - **Verify**: `cd apps/web && npm test -- FacetChips`
  - _Requirements: FR-007_

- [x] T070 [US3] Create pagination component
  - **Files**: `apps/web/src/components/common/Pagination.tsx`
  - **Agent**: Lambert
  - **Done when**: Prev/next page navigation; page count display
  - **Verify**: `cd apps/web && npm test -- Pagination`
  - _Requirements: FR-009_

- [x] T071 [US3] Create segment list with timestamps on video detail page
  - **Files**: `apps/web/src/components/library/SegmentList.tsx`
  - **Agent**: Lambert
  - **Done when**: Segments displayed with timestamps; clickable
  - **Verify**: `cd apps/web && npm test -- SegmentList`
  - _Requirements: FR-008_

- [x] T072 [US3] Add clickable timestamps linking to YouTube
  - **Files**: `apps/web/src/components/library/SegmentList.tsx`
  - **Agent**: Lambert
  - **Done when**: Timestamps open YouTube video at correct timestamp
  - **Verify**: `cd apps/web && npm test -- SegmentList`
  - _Requirements: FR-008_

---

## Phase 5: User Story 2 — Ingest from Channel (Batch) ✅

**Goal**: User provides channel URL, browses videos, starts batch, sees per-video progress.

- [x] T073 [P] [US2] Add ingestion channel models (FetchChannelRequest, ChannelVideosResponse)
  - **Files**: `services/api/src/api/models/channel.py`
  - **Agent**: Ripley
  - **Done when**: Models cover channel fetch request/response
  - **Verify**: `uv run python -c "from api.models.channel import FetchChannelRequest"`
  - _Requirements: FR-005_

- [x] T074 [US2] Implement YouTube service with yt-dlp channel extraction
  - **Files**: `services/api/src/api/services/youtube_service.py`
  - **Agent**: Ripley
  - **Done when**: Fetches channel video list via yt-dlp; paginated
  - **Verify**: `cd services/api && uv run pytest tests/test_youtube_service.py`
  - _Requirements: FR-005_

- [x] T075 [US2] Implement channel service for fetch/pagination
  - **Files**: `services/api/src/api/services/channel_service.py`
  - **Agent**: Ripley
  - **Done when**: Cursor-based pagination; "already ingested" detection
  - **Verify**: `cd services/api && uv run pytest tests/test_channel_service.py`
  - _Requirements: FR-005_

- [x] T076 [US2] Implement POST /api/v1/channels
  - **Files**: `services/api/src/api/routes/channels.py`
  - **Agent**: Ripley
  - **Done when**: Returns channel video list with ingestion status per video
  - **Verify**: `cd services/api && uv run pytest tests/test_channels.py`
  - _Requirements: FR-005_

- [x] T077 [P] [US2] Create batch Pydantic models
  - **Files**: `services/api/src/api/models/batch.py`
  - **Agent**: Ripley
  - **Done when**: CreateBatchRequest, BatchResponse, BatchDetailResponse, BatchItem defined
  - **Verify**: `uv run python -c "from api.models.batch import BatchResponse"`
  - _Requirements: FR-005_

- [x] T078 [US2] Implement batch service (create, get, list, retry)
  - **Files**: `services/api/src/api/services/batch_service.py`
  - **Agent**: Ripley
  - **Done when**: All CRUD operations work; status counts maintained
  - **Verify**: `cd services/api && uv run pytest tests/test_batch_service.py`
  - _Requirements: FR-005_

- [x] T079 [US2] Implement POST /api/v1/batches
  - **Files**: `services/api/src/api/routes/batches.py`
  - **Agent**: Ripley
  - **Done when**: Creates batch and queues all selected videos
  - **Verify**: `cd services/api && uv run pytest tests/test_batches.py`
  - _Requirements: FR-005_

- [x] T080 [US2] Implement GET /api/v1/batches
  - **Files**: `services/api/src/api/routes/batches.py`
  - **Agent**: Ripley
  - **Done when**: Returns list of batches with status counts
  - **Verify**: `cd services/api && uv run pytest tests/test_batches.py`
  - _Requirements: FR-005_

- [x] T081 [US2] Implement GET /api/v1/batches/{batchId}
  - **Files**: `services/api/src/api/routes/batches.py`
  - **Agent**: Ripley
  - **Done when**: Returns batch detail with all item statuses
  - **Verify**: `cd services/api && uv run pytest tests/test_batches.py`
  - _Requirements: FR-005_

- [x] T082 [US2] Implement POST /api/v1/batches/{batchId}/retry
  - **Files**: `services/api/src/api/routes/batches.py`
  - **Agent**: Ripley
  - **Done when**: Re-queues all failed items in batch
  - **Verify**: `cd services/api && uv run pytest tests/test_batches.py`
  - _Requirements: FR-005_

- [x] T083 [US2] Implement POST /api/v1/batches/{batchId}/items/{videoId}/retry
  - **Files**: `services/api/src/api/routes/batches.py`
  - **Agent**: Ripley
  - **Done when**: Re-queues single failed item
  - **Verify**: `cd services/api && uv run pytest tests/test_batches.py`
  - _Requirements: FR-005_

- [x] T084 [US2] Create channel submission form
  - **Files**: `apps/web/src/components/ChannelForm.tsx`
  - **Agent**: Lambert
  - **Done when**: Form accepts channel URL; validates and submits
  - **Verify**: `cd apps/web && npm test -- ChannelForm`
  - _Requirements: FR-005_

- [x] T085 [US2] Create channel video list with multi-select + "Ingest All" button
  - **Files**: `apps/web/src/components/ChannelVideoList.tsx`
  - **Agent**: Lambert
  - **Done when**: Multi-select checkboxes; "Ingest All" button; shows already-ingested badge
  - **Verify**: `cd apps/web && npm test -- ChannelVideoList`
  - _Requirements: FR-005_

- [x] T086 [US2] Create "Load More" pagination for channel videos
  - **Files**: `apps/web/src/components/ChannelVideoList.tsx`
  - **Agent**: Lambert
  - **Done when**: Loads next page of channel videos on click
  - **Verify**: `cd apps/web && npm test -- ChannelVideoList`
  - _Requirements: FR-005_

- [x] T087 [US2] Create batch creation page
  - **Files**: `apps/web/src/app/ingest/page.tsx`
  - **Agent**: Lambert
  - **Done when**: Page includes both single-video and channel batch submission
  - **Verify**: `cd apps/web && npm run build`
  - _Requirements: FR-005_

- [x] T088 [US2] Create batch status page
  - **Files**: `apps/web/src/app/ingest/[batchId]/page.tsx`
  - **Agent**: Lambert
  - **Done when**: Shows batch totals and per-video status rows; polls for updates
  - **Verify**: `cd apps/web && npm run build`
  - _Requirements: FR-005_

- [x] T089 [P] [US2] Create batch progress summary component
  - **Files**: `apps/web/src/components/BatchProgress.tsx`
  - **Agent**: Lambert
  - **Done when**: Summary bar shows pending/running/succeeded/failed counts
  - **Verify**: `cd apps/web && npm test -- BatchProgress`
  - _Requirements: FR-005_

- [x] T090 [P] [US2] Create per-video status row component (integrated into BatchProgress)
  - **Files**: `apps/web/src/components/BatchProgress.tsx`
  - **Agent**: Lambert
  - **Done when**: Each video row shows status and retry button if failed
  - **Verify**: `cd apps/web && npm test -- BatchProgress`
  - _Requirements: FR-005_

- [x] T091 [US2] Create batches list page
  - **Files**: `apps/web/src/app/batches/page.tsx`
  - **Agent**: Lambert
  - **Done when**: Lists all batches with status and link to detail
  - **Verify**: `cd apps/web && npm run build`
  - _Requirements: FR-005_

- [x] T092 [US2] Add retry all-at-once button on batch status page
  - **Files**: `apps/web/src/app/ingest/[batchId]/page.tsx`
  - **Agent**: Lambert
  - **Done when**: "Retry All Failed" button triggers batch retry
  - **Verify**: `cd apps/web && npm test -- BatchProgress`
  - _Requirements: FR-005_

- [x] T093 [US2] Add individual retry button per failed video row
  - **Files**: `apps/web/src/components/BatchProgress.tsx`
  - **Agent**: Lambert
  - **Done when**: Per-row retry triggers single-item retry
  - **Verify**: `cd apps/web && npm test -- BatchProgress`
  - _Requirements: FR-005_

- [x] T094 [US2] Add "already ingested" indicator for re-submitted channels
  - **Files**: `apps/web/src/components/ChannelVideoList.tsx`
  - **Agent**: Lambert
  - **Done when**: Previously ingested videos show badge; UI offers "new only" or "reprocess all"
  - **Verify**: `cd apps/web && npm test -- ChannelVideoList`
  - _Requirements: FR-005_

- [x] T095 [US2] Add navigation from completed batch to "Ready to Review" library view
  - **Files**: `apps/web/src/app/ingest/[batchId]/page.tsx`
  - **Agent**: Lambert
  - **Done when**: Completed batch page shows link to filtered library view
  - **Verify**: `cd apps/web && npm run build`
  - _Requirements: FR-005_

---

## Phase 6: User Story 4 — Query with the Copilot ✅

**Goal**: User asks questions scoped to channel or library; receives answer with citations.

- [x] T096 [P] [US4] Create QueryScope, CopilotQueryRequest, CopilotQueryResponse Pydantic models
  - **Files**: `services/api/src/api/models/copilot.py`
  - **Agent**: Ripley
  - **Done when**: All copilot models importable; AIKnowledgeSettings included
  - **Verify**: `uv run python -c "from api.models.copilot import CopilotQueryRequest"`
  - _Requirements: FR-010, FR-011, FR-012, FR-013_

- [x] T103 [US4] Implement vector search service with cosine similarity
  - **Files**: `services/api/src/api/services/search_service.py`
  - **Agent**: Ripley
  - **Done when**: VECTOR_DISTANCE() query returns top-K segments; scope filters applied
  - **Verify**: `cd services/api && uv run pytest tests/test_search_service.py`
  - _Requirements: FR-010, FR-013_

- [x] T105 [US4] Implement copilot orchestrator (query → search → LLM → response)
  - **Files**: `services/api/src/api/services/copilot_service.py`
  - **Agent**: Ripley
  - **Done when**: Full query pipeline works; respects AI settings (useVideoContext, useLLMKnowledge)
  - **Verify**: `cd services/api && uv run pytest tests/test_copilot.py`
  - _Requirements: FR-010, FR-011, FR-011a, FR-011b, FR-012, FR-015_

- [x] T106 [US4] Add LLM client wrapper for OpenAI chat completions
  - **Files**: `services/api/src/api/services/llm_service.py`
  - **Agent**: Ripley
  - **Done when**: Chat completions + LLM-only mode (no RAG) work
  - **Verify**: `cd services/api && uv run pytest tests/test_llm_service.py`
  - _Requirements: FR-011a_

- [x] T109 [US4] Implement POST /api/v1/copilot/query
  - **Files**: `services/api/src/api/routes/copilot.py`
  - **Agent**: Ripley
  - **Done when**: Returns CopilotQueryResponse with answer, video cards, evidence, follow-ups
  - **Verify**: `cd services/api && uv run pytest tests/test_copilot.py`
  - _Requirements: FR-010, FR-012, FR-013, FR-014, FR-015_

- [x] T110 [US4] Implement POST /api/v1/copilot/search/segments
  - **Files**: `services/api/src/api/routes/copilot.py`
  - **Agent**: Ripley
  - **Done when**: Returns semantically ranked segments
  - **Verify**: `cd services/api && uv run pytest tests/test_copilot.py`
  - _Requirements: FR-010_

- [x] T112 [US4] Implement POST /api/v1/copilot/topics
  - **Files**: `services/api/src/api/routes/copilot.py`
  - **Agent**: Ripley
  - **Done when**: Returns top facets with counts for current scope
  - **Verify**: `cd services/api && uv run pytest tests/test_copilot.py`
  - _Requirements: FR-013_

- [x] T115 [US4] Install and configure CopilotKit
  - **Files**: `apps/web/package.json`, `apps/web/src/app/providers.tsx`
  - **Agent**: Lambert
  - **Done when**: CopilotKit provider wraps app; AI settings context available
  - **Verify**: `cd apps/web && npm run build`
  - _Requirements: FR-010, FR-011_

- [x] T118 [US4] Create CopilotSidebar component
  - **Files**: `apps/web/src/components/copilot/CopilotSidebar.tsx`
  - **Agent**: Lambert
  - **Done when**: Chat panel renders; message history persists across page navigations
  - **Verify**: `cd apps/web && npm test -- CopilotSidebar`
  - _Requirements: FR-012, FR-028_

- [x] T119 [P] [US4] Create ScopeChips component
  - **Files**: `apps/web/src/components/copilot/ScopeChips.tsx`, `apps/web/src/components/copilot/subcomponents/ScopeIndicator.tsx`
  - **Agent**: Lambert
  - **Done when**: Scope chips show active filters; knowledge source toggles (Your Videos, AI Knowledge, Web Search)
  - **Verify**: `cd apps/web && npm test -- ScopeIndicator`
  - _Requirements: FR-013, FR-014, FR-011_

- [x] T120 [P] [US4] Create Citation component
  - **Files**: `apps/web/src/components/copilot/Citation.tsx`
  - **Agent**: Lambert
  - **Done when**: Shows segment text; links to YouTube at timestamp
  - **Verify**: `cd apps/web && npm test -- Citation`
  - _Requirements: FR-012_

- [x] T121 [P] [US4] Create CopilotVideoCard component
  - **Files**: `apps/web/src/components/copilot/CopilotVideoCard.tsx`
  - **Agent**: Lambert
  - **Done when**: Shows video thumbnail, title, relevance reason; "Why this?" button visible
  - **Verify**: `cd apps/web && npm test -- CopilotVideoCard`
  - _Requirements: FR-012, FR-017_

- [x] T122 [US4] Create TopicsPanel component
  - **Files**: `apps/web/src/components/copilot/TopicsPanel.tsx`
  - **Agent**: Lambert
  - **Done when**: Shows top facets with counts for current scope
  - **Verify**: `cd apps/web && npm test -- TopicsPanel`
  - _Requirements: FR-013_

- [x] T123 [US4] Create FollowupButtons component
  - **Files**: `apps/web/src/components/copilot/FollowupButtons.tsx`
  - **Agent**: Lambert
  - **Done when**: Renders follow-up suggestion buttons; clicking re-queries
  - **Verify**: `cd apps/web && npm test -- FollowupButtons`
  - _Requirements: FR-012_

- [x] T127 [US4] Implement uncertainty messaging component
  - **Files**: `apps/web/src/components/copilot/UncertaintyMessage.tsx`
  - **Agent**: Lambert
  - **Done when**: Renders when copilot has insufficient content; includes "Ingest more" CTA
  - **Verify**: `cd apps/web && npm test -- UncertaintyMessage`
  - _Requirements: FR-015_

- [x] T130 [P] [US4] Create API tests for copilot endpoints
  - **Files**: `services/api/tests/test_copilot.py`
  - **Agent**: Kane
  - **Done when**: Tests cover all AI settings combinations (no RAG, LLM-only, both)
  - **Verify**: `cd services/api && uv run pytest tests/test_copilot.py -v`
  - _Requirements: FR-010, FR-011, FR-011a, FR-011b_

- [x] T132 [P] [US4] Create E2E tests for copilot query flow
  - **Files**: `apps/web/e2e/copilot.spec.ts`
  - **Agent**: Kane
  - **Done when**: E2E tests cover query, scope change, citation click, follow-up
  - **Verify**: `cd apps/web && npx playwright test e2e/copilot.spec.ts`
  - _Requirements: FR-010, FR-012, FR-013, FR-014_

---

## Phase 7: User Story 5 — "Explain Why" Transparency ✅

**Goal**: Each recommended video includes explanation data; user clicks "Why this?" to reveal it inline.

- [x] T133 [US5] Add VideoExplanation, KeyMoment models to copilot.py
  - **Files**: `services/api/src/api/models/copilot.py`
  - **Agent**: Ripley
  - **Done when**: RecommendedVideo.explanation field populated in query response
  - **Verify**: `uv run python -c "from api.models.copilot import VideoExplanation"`
  - _Requirements: FR-017_

- [x] T135 [US5] Update LLM prompt to generate per-video explanations
  - **Files**: `services/api/src/api/services/copilot_service.py`
  - **Agent**: Ripley
  - **Done when**: LLM output includes explanation for each recommended video
  - **Verify**: `cd services/api && uv run pytest tests/test_copilot.py`
  - _Requirements: FR-017_

- [x] T137 [US5] Create "Why this?" button on video cards
  - **Files**: `apps/web/src/components/copilot/WhyThisButton.tsx`
  - **Agent**: Lambert
  - **Done when**: Button toggles explanation panel; no API call needed
  - **Verify**: `cd apps/web && npm test -- WhyThisButton`
  - _Requirements: FR-017_

- [x] T138 [US5] Create ExplanationPanel component
  - **Files**: `apps/web/src/components/copilot/ExplanationPanel.tsx`
  - **Agent**: Lambert
  - **Done when**: Shows similarity basis, relationship basis, evidence segments with timestamps
  - **Verify**: `cd apps/web && npm test -- ExplanationPanel`
  - _Requirements: FR-017_

- [x] T139 [P] [US5] Create KeyMomentsList component with clickable timestamps
  - **Files**: `apps/web/src/components/copilot/KeyMomentsList.tsx`
  - **Agent**: Lambert
  - **Done when**: Key moments link to YouTube at timestamp
  - **Verify**: `cd apps/web && npm test -- KeyMomentsList`
  - _Requirements: FR-017_

- [x] T141 [US5] Wire "Why this?" to toggle ExplanationPanel (local state, no API call)
  - **Files**: `apps/web/src/components/copilot/CopilotVideoCard.tsx`
  - **Agent**: Lambert
  - **Done when**: Panel toggles instantly from inline data
  - **Verify**: `cd apps/web && npm test -- CopilotVideoCard`
  - _Requirements: FR-017_

- [x] T143 [P] [US5] Create E2E tests for "Why this?" toggle
  - **Files**: `apps/web/e2e/explain.spec.ts`
  - **Agent**: Kane
  - **Done when**: E2E test verifies explanation panel appears and evidence links work
  - **Verify**: `cd apps/web && npx playwright test e2e/explain.spec.ts`
  - _Requirements: FR-017_

---

## Phase 8: User Story 6 — Synthesize Structured Outputs ✅

**Goal**: User asks copilot to create learning paths, watch lists synthesized from library content.

- [x] T146 [P] [US6] Create LearningPath model
  - **Files**: `services/api/src/api/models/synthesis.py`
  - **Agent**: Ripley
  - **Done when**: Model includes ordered items with videoId, rationale, evidence
  - **Verify**: `uv run python -c "from api.models.synthesis import LearningPath"`
  - _Requirements: FR-016_

- [x] T148 [US6] Implement synthesis service
  - **Files**: `services/api/src/api/services/synthesis_service.py`
  - **Agent**: Ripley
  - **Done when**: Generates ordered learning paths; respects difficulty levels
  - **Verify**: `cd services/api && uv run pytest tests/test_synthesis.py`
  - _Requirements: FR-016_

- [x] T150 [US6] Implement POST /api/v1/copilot/synthesize
  - **Files**: `services/api/src/api/routes/copilot.py`
  - **Agent**: Ripley
  - **Done when**: Returns LearningPath or WatchList with citations
  - **Verify**: `cd services/api && uv run pytest tests/test_synthesis.py`
  - _Requirements: FR-016_

- [x] T151 [US6] Create learning path renderer
  - **Files**: `apps/web/src/components/copilot/LearningPathView.tsx`
  - **Agent**: Lambert
  - **Done when**: Ordered video list with rationale; "what's missing" message when insufficient
  - **Verify**: `cd apps/web && npm test -- LearningPathView`
  - _Requirements: FR-016_

- [x] T157 [P] [US6] Add test video fixture with curated series
  - **Files**: `apps/web/e2e/global-setup.ts`
  - **Agent**: Kane
  - **Done when**: Fixture provides videos with known correct order
  - **Verify**: `cd apps/web && npx playwright test --global-setup`
  - _Requirements: FR-016_

- [x] T158 [P] [US6] Create ordering verification tests
  - **Files**: `apps/web/e2e/synthesis-api.spec.ts`
  - **Agent**: Kane
  - **Done when**: Tests verify beginner-before-advanced ordering; shorts excluded
  - **Verify**: `cd apps/web && npx playwright test e2e/synthesis-api.spec.ts`
  - _Requirements: FR-016_

---

## Phase 9: Worker Resilience & Content Validation ✅

**Goal**: Workers handle transient failures and validate external content reliably.

- [x] T175 [US1] Add content validation to transcribe worker (HTML error pages vs valid VTT/SRT)
  - **Files**: `services/workers/transcribe/worker.py`
  - **Agent**: Ripley
  - **Done when**: Invalid responses detected; treated as transient failure
  - **Verify**: `cd services/workers && uv run pytest tests/test_transcribe_resilience.py`
  - _Requirements: FR-026_

- [x] T176 [US1] Implement retry with exponential backoff for YouTube rate-limit errors
  - **Files**: `services/workers/transcribe/worker.py`
  - **Agent**: Ripley
  - **Done when**: 429 responses trigger backoff; rate_limit_detected span event emitted
  - **Verify**: `cd services/workers && uv run pytest tests/test_transcribe_resilience.py`
  - _Requirements: FR-021, FR-027_

- [x] T178a [US1] Refactor transcribe worker to use yt-dlp exclusively
  - **Files**: `services/workers/transcribe/worker.py`, `services/workers/transcribe/pyproject.toml`
  - **Agent**: Ripley
  - **Done when**: youtube-transcript-api removed; yt-dlp only; VTT parsed with timestamps
  - **Verify**: `cd services/workers && uv run pytest tests/`
  - _Requirements: FR-026, FR-027_

- [x] T179 [US1] Add POST /api/v1/videos/{videoId}/reprocess (re-queue failed videos)
  - **Files**: `services/api/src/api/routes/videos.py`
  - **Agent**: Ripley
  - **Done when**: Endpoint exists and re-queues failed/empty transcript videos
  - **Verify**: `cd services/api && uv run pytest tests/test_videos.py`
  - _Requirements: FR-004_

- [x] T180 [US1] Add "Reprocess" button to video detail page for failed/empty transcripts
  - **Files**: `apps/web/src/app/videos/[videoId]/page.tsx`
  - **Agent**: Lambert
  - **Done when**: Button visible for failed videos; triggers reprocess endpoint
  - **Verify**: `cd apps/web && npm test -- VideoDetail`
  - _Requirements: FR-004_

---

## Phase 10: Polish & Cross-Cutting Concerns ✅

**Goal**: Production readiness — observability, error handling, loading states, documentation.

### Serverless DB Wake-up Handling

- [x] T181a Add uptime_seconds and started_at to HealthStatus response
  - **Files**: `services/api/src/api/routes/health.py`
  - **Agent**: Ripley
  - **Done when**: /health returns uptime_seconds and started_at
  - **Verify**: `cd services/api && uv run pytest tests/test_health.py`
  - _Requirements: FR-020a_

- [x] T181e Create useHealthCheck hook
  - **Files**: `apps/web/src/hooks/useHealthCheck.ts`
  - **Agent**: Lambert
  - **Done when**: Hook polls /health; exposes isWarming, isDegraded status
  - **Verify**: `cd apps/web && npm test -- useHealthCheck`
  - _Requirements: FR-020b_

- [x] T181g Create WarmingUpIndicator component
  - **Files**: `apps/web/src/components/common/WarmingUpIndicator.tsx`
  - **Agent**: Lambert
  - **Done when**: Banner displays when status is degraded
  - **Verify**: `cd apps/web && npm test -- WarmingUpIndicator`
  - _Requirements: FR-020b_

- [x] T181i Add retry logic to API client fetch wrapper (auto-retry 503/degraded with backoff)
  - **Files**: `apps/web/src/services/api.ts`
  - **Agent**: Lambert
  - **Done when**: Failed requests retry with exponential backoff while degraded
  - **Verify**: `cd apps/web && npm test -- api`
  - _Requirements: FR-020c_

- [x] T183 [P] Create global error boundary
  - **Files**: `apps/web/src/app/error.tsx`
  - **Agent**: Lambert
  - **Done when**: Handles API unreachable, 503, 500, offline with user-friendly messages
  - **Verify**: `cd apps/web && npm run build`
  - _Requirements: FR-020_

- [x] T184 Add loading skeletons for async data fetches
  - **Files**: `apps/web/src/components/library/VideoCardSkeleton.tsx`, `apps/web/src/components/jobs/JobProgressSkeleton.tsx`, `apps/web/src/components/copilot/MessageSkeleton.tsx`
  - **Agent**: Lambert
  - **Done when**: Skeleton loaders appear on library, video detail, batch status, copilot
  - **Verify**: `cd apps/web && npm run build`
  - _Requirements: —_

### OpenTelemetry & Distributed Tracing

- [x] T185 [P] Add OpenTelemetry SDK to Python API
  - **Files**: `services/api/pyproject.toml`, `services/api/src/api/main.py`
  - **Agent**: Ripley
  - **Done when**: FastAPI, SQLAlchemy, httpx auto-instrumented; OTLP exporter configured
  - **Verify**: `cd services/api && uv run pytest tests/`
  - _Requirements: FR-023, FR-025_

- [x] T186a Create shared OpenTelemetry configuration
  - **Files**: `services/shared/shared/telemetry/config.py`
  - **Agent**: Ripley
  - **Done when**: configure_telemetry(service_name) reusable by API and workers
  - **Verify**: `uv run python -c "from shared.telemetry.config import configure_telemetry"`
  - _Requirements: FR-023_

- [x] T185b Add trace spans to video submission flow
  - **Files**: `services/api/src/api/services/video_service.py`
  - **Agent**: Ripley
  - **Done when**: Spans: video.submit, video.metadata.fetch, video.persist, job.queue
  - **Verify**: `cd services/api && uv run pytest tests/test_video_service.py`
  - _Requirements: FR-023, FR-024_

- [x] T186b Add trace spans to transcribe worker
  - **Files**: `services/workers/transcribe/worker.py`
  - **Agent**: Ripley
  - **Done when**: Spans: transcribe.process, transcribe.youtube.fetch, transcribe.blob.store
  - **Verify**: `cd services/workers && uv run pytest tests/`
  - _Requirements: FR-023, FR-024_

- [x] T187 Verify correlation ID propagation from UI → API → workers
  - **Files**: `services/api/src/api/middleware/correlation.py`, `services/shared/shared/queue/client.py`
  - **Agent**: Ripley
  - **Done when**: X-Correlation-ID flows to span attributes and queue messages
  - **Verify**: `cd services/api && uv run pytest tests/test_middleware.py`
  - _Requirements: FR-023_

- [x] T187a Update queue message schema to include trace context
  - **Files**: `services/shared/shared/queue/client.py`
  - **Agent**: Ripley
  - **Done when**: inject_trace_context() and extract_trace_context() helpers present
  - **Verify**: `uv run python -c "from shared.queue.client import inject_trace_context"`
  - _Requirements: FR-023_

### Documentation & Runbooks

- [x] T188b [P] Create runbook: Investigating failed video ingestion
  - **Files**: `docs/runbooks/video-ingestion-troubleshooting.md`
  - **Agent**: Dallas
  - **Done when**: Runbook covers: trace lookup, common failures, retry steps, stage identification
  - **Verify**: File exists with required sections
  - _Requirements: FR-022, FR-024_

- [x] T196 [P] Create architecture overview in docs/architecture.md
  - **Files**: `docs/architecture.md`
  - **Agent**: Dallas
  - **Done when**: Covers system context, component diagram, data flows, tech stack, key decisions
  - **Verify**: File exists
  - _Requirements: —_

- [x] T198 Run quickstart.md validation and update
  - **Files**: `specs/001-product-spec/quickstart.md`
  - **Agent**: Dallas
  - **Done when**: All commands verified on clean checkout; troubleshooting section present
  - **Verify**: Follow quickstart steps on clean environment
  - _Requirements: —_

- [x] T198a [P] Create developer onboarding guide
  - **Files**: `docs/developer-guide.md`
  - **Agent**: Dallas
  - **Done when**: Covers prerequisites, repo structure, local run, tests, adding worker/endpoint
  - **Verify**: File exists with required sections
  - _Requirements: —_

---

## [VERIFY] V-FINAL — All User Stories Complete

- [x] Run: `cd services/api && uv run pytest`
- [x] Run: `cd services/workers && uv run pytest`
- [x] Run: `cd apps/web && npm test`
- [x] Run: `cd apps/web && npx playwright test`
- [x] Check: All 220 tasks marked `[x]`
- [x] Check: All 6 user stories have passing acceptance criteria
