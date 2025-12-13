# Implementation Plan: YT Summarizer

**Branch**: `001-product-spec` | **Date**: 2025-12-13 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/001-product-spec/spec.md`

## Summary

YT Summarizer transforms YouTube videos into a searchable knowledge library. Users ingest videos (single or batch), which are processed through a pipeline (transcribe → summarize → embed → extract relationships). A read-only copilot enables cross-video queries with citation-grounded answers, scope visibility, and structured outputs (learning paths, watch lists).

**Technical approach**: Mono-repo with Next.js frontend (SWA), Python API + Python workers (ACA via Aspire), Azure SQL for all data (operational, vectors, relationships), Blob for large artifacts, Storage Queue for async jobs.

## Technical Context

**Languages/Versions**:
- Frontend: TypeScript 5.x, Next.js 14+
- Backend: Python 3.11+ (API + Workers)
- Orchestration: .NET Aspire (orchestrates Python containers)

**Primary Dependencies**:
- Frontend: Next.js, CopilotKit (for chat UI), TailwindCSS
- API: FastAPI, SQLAlchemy, azure-identity, pydantic
- Workers: OpenAI SDK, yt-dlp, youtube-transcript-api, azure-storage-queue
- Shared: structlog, tenacity (retry), pytest
- Infra: Azure SQL, Blob Storage, Storage Queue, Azure Container Apps

**Storage**: Azure SQL Database (serverless) — operational data, vector embeddings (VECTOR columns), graph relationships  
**Testing**: pytest (Python), Playwright (E2E)  
**Target Platform**: Azure (SWA + ACA + SQL + Storage)  
**Project Type**: Web application (frontend + backend + workers)  
**Performance Goals**: <3s query response (excluding cold start), <5min video ingestion  
**Constraints**: <1s library browse, bounded queries (top-K, pagination)  
**Scale/Scope**: ~1,500 videos, ~15,000 segments, 1-5 users (hobby-appropriate)

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|-----------|--------|-------|
| **I. Product & UX** | ✅ Pass | Cross-content queries, citations, scope visibility, graceful degradation all addressed in spec |
| **II. AI/Copilot Boundaries** | ✅ Pass | Read-only copilot enforced; no write operations; library-scoped only |
| **III. Data & Provenance** | ✅ Pass | Azure SQL as source of truth; one artifact per source; relationships with evidence pointers; traceability metadata |
| **IV. Reliability & Operations** | ✅ Pass | Async processing with retry/dead-letter; serverless wake-up handling; observability with correlation IDs |
| **V. Security** | ✅ Pass | Managed Identity; no secrets in repo; Key Vault for API keys |
| **VI. Engineering Quality** | ✅ Pass | Simplicity first; bounded queries; migrations; testing strategy |
| **VII. Change Management** | ✅ Pass | Plan references constitution; spec-driven development |

**Gate Result**: PASS — No violations detected. Proceed to Phase 0.

## Project Structure

### Documentation (this feature)

```text
specs/001-product-spec/
├── plan.md              # This file
├── research.md          # Phase 0: Technology decisions and patterns
├── data-model.md        # Phase 1: SQL schema and entity design
├── quickstart.md        # Phase 1: Local dev setup guide
├── contracts/           # Phase 1: OpenAPI specifications
│   ├── ingestion-api.yaml
│   ├── library-api.yaml
│   ├── copilot-api.yaml
│   └── jobs-api.yaml
└── tasks.md             # Phase 2: Ordered implementation tasks
```

### Source Code (repository root)

```text
yt-summarizer/
├── apps/
│   └── web/                    # Next.js frontend
│       ├── src/
│       │   ├── app/            # App router pages
│       │   ├── components/     # React components
│       │   │   ├── library/    # Browse/filter components
│       │   │   ├── copilot/    # Chat UI with CopilotKit
│       │   │   └── jobs/       # Job status components
│       │   ├── hooks/          # Custom React hooks
│       │   └── services/       # API client
│       ├── public/
│       ├── package.json
│       └── next.config.js
│
├── services/
│   ├── api/                    # Python FastAPI
│   │   ├── src/
│   │   │   ├── api/
│   │   │   │   ├── routes/     # REST endpoints
│   │   │   │   ├── services/   # Business logic
│   │   │   │   ├── models/     # Pydantic models
│   │   │   │   └── main.py     # FastAPI app
│   │   │   └── shared/         # Shared code (DB, utils)
│   │   ├── tests/              # pytest tests
│   │   ├── requirements.txt
│   │   ├── pyproject.toml
│   │   └── Dockerfile
│   │
│   ├── workers/                # Python workers
│   │   ├── transcribe/         # Transcript acquisition
│   │   ├── summarize/          # LLM summarization
│   │   ├── embed/              # Embedding generation
│   │   ├── relationships/      # Graph extraction
│   │   ├── tests/              # pytest tests
│   │   ├── requirements.txt
│   │   ├── pyproject.toml
│   │   └── Dockerfile
│   │
│   ├── shared/                 # Shared Python package
│   │   ├── db/                 # SQLAlchemy models
│   │   ├── queue/              # Queue client
│   │   ├── blob/               # Blob client
│   │   └── logging/            # Structured logging
│   │
│   └── aspire/                 # .NET Aspire AppHost
│       ├── AppHost/
│       │   └── Program.cs      # Composition root (orchestrates Python containers)
│       └── ServiceDefaults/    # Shared Aspire defaults
│
├── db/
│   └── seed/                   # Test data scripts (migrations in services/shared/alembic/)
│
├── infra/
│   ├── bicep/                  # Azure Bicep templates
│   │   ├── main.bicep
│   │   ├── modules/
│   │   └── parameters/
│   └── scripts/                # Deployment scripts
│
├── docs/
│   ├── architecture.md         # System overview
│   ├── runbooks/               # Operational guides
│   └── adr/                    # Architecture decision records
│
├── .specify/                   # Speckit configuration
├── .github/
│   ├── workflows/              # CI/CD pipelines
│   └── prompts/                # Speckit prompts
│
├── .gitignore
└── README.md
```

**Structure Decision**: Web application with unified Python backend. Frontend in `/apps/web`, Python API and workers in `/services` with shared code, Aspire orchestrates all Python containers for local dev and deployment shape.

## Complexity Tracking

> No constitution violations detected. All design decisions follow simplicity-first principles.

---

## Runtime Architecture

### Local Development (Aspire)

```text
┌─────────────────────────────────────────────────────────────────┐
│                    .NET Aspire AppHost                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌──────────────────────────┐│
│  │  Next.js    │  │ Python API  │  │    Python Workers        ││
│  │  (web)      │  │  (FastAPI)  │  │  (transcribe, summarize, ││
│  │  :3000      │  │  :8000      │  │   embed, relationships)  ││
│  └──────┬──────┘  └──────┬──────┘  └────────────┬─────────────┘│
│         │                │                      │               │
│         └────────────────┼──────────────────────┘               │
│                          │                                      │
│  ┌───────────────────────┴───────────────────────────────────┐ │
│  │                    Azure SQL (local or Azure)             │ │
│  │     Operational + Vectors + Relationships                 │ │
│  └───────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌──────────────────┐    ┌──────────────────┐                  │
│  │    Azurite       │    │   Storage Queue  │                  │
│  │    (Blob)        │    │   (Jobs)         │                  │
│  └──────────────────┘    └──────────────────┘                  │
└─────────────────────────────────────────────────────────────────┘
```

**Aspire Composition** (AppHost/Program.cs):
- References `web` (Next.js via npm/container)
- References `api` (Python FastAPI container)
- References `workers` (Python containers)
- All Python services share connection strings via environment
- Provisions Azurite for local blob/queue emulation

### Production (Azure)

```text
┌─────────────────────────────────────────────────────────────────┐
│                         Azure                                   │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌─────────────────┐                                           │
│  │  Azure Static   │                                           │
│  │  Web Apps       │  ← Next.js frontend                       │
│  │  (web)          │                                           │
│  └────────┬────────┘                                           │
│           │ HTTPS                                              │
│           ▼                                                    │
│  ┌─────────────────────────────────────────────────────────┐   │
│  │               Azure Container Apps                       │   │
│  │  ┌───────────┐  ┌────────────┐  ┌─────────────────────┐ │   │
│  │  │  API      │  │ transcribe │  │ summarize, embed,   │ │   │
│  │  │ (FastAPI) │  │ (Python)   │  │ relationships       │ │   │
│  │  └─────┬─────┘  └─────┬──────┘  └──────────┬──────────┘ │   │
│  └────────┼──────────────┼─────────────────────┼───────────┘   │
│           │              │                     │                │
│           ▼              ▼                     ▼                │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │              Azure SQL Database (Serverless)              │ │
│  │     Channels, Videos, Jobs, Segments, Relationships       │ │
│  │                    + VECTOR columns                       │ │
│  └───────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌──────────────────┐    ┌──────────────────┐                  │
│  │  Blob Storage    │    │  Storage Queue   │                  │
│  │  (Transcripts)   │    │  (Job messages)  │                  │
│  └──────────────────┘    └──────────────────┘                  │
│                                                                 │
│  ┌──────────────────┐    ┌──────────────────┐                  │
│  │  Azure Key Vault │    │  Managed Identity│                  │
│  │  (API Keys)      │    │  (Auth)          │                  │
│  └──────────────────┘    └──────────────────┘                  │
└─────────────────────────────────────────────────────────────────┘
```

**Networking**: Start simple with public endpoints. Add private endpoints later if needed.

---

## Background Pipeline Design

### Job Flow

```text
User submits URL → API creates Video + Job → Queue message

Queue Listener picks up job:
  1. TranscribeStage → fetch/generate transcript → store Artifact (blob) → update Job
  2. SummarizeStage → LLM summarization → store Artifact → update Job
  3. ChunkEmbedStage → split into segments → generate embeddings → upsert Segments → update Job
  4. RelationshipStage → extract connections → upsert Relationships → complete Job
```

### Job Entity States

| Status | Description |
|--------|-------------|
| `pending` | Queued, not yet picked up |
| `running` | In progress (includes current stage) |
| `succeeded` | All stages complete |
| `failed` | Error occurred (includes error message) |
| `dead-lettered` | Max retries exhausted |

### Idempotency Strategy

| Entity | Uniqueness Key | On Conflict |
|--------|---------------|-------------|
| Video | `YouTubeVideoId` | Update metadata |
| Artifact | `VideoId + Type` | Overwrite (upsert) |
| Segment | `VideoId + StartTime + ContentHash` | Overwrite embedding |
| Relationship | `SourceVideoId + TargetVideoId + Type` | Update confidence/rationale |
| Job | `VideoId + BatchId + CreatedAt` | Reject duplicate |

### Retry & Dead-Letter

- **Transient failures**: Retry up to 5 times with exponential backoff (1s, 2s, 4s, 8s, 16s)
- **Permanent failures**: Dead-letter immediately (e.g., video not found, invalid URL)
- **Dead-letter queue**: Separate queue for manual inspection; visible in UI
- **Reprocessing**: User can trigger from UI; creates new job with fresh timestamps

### Worker Concurrency

- Each worker type runs as separate container/process
- Workers poll queue with visibility timeout (5 min)
- Single worker per job (no parallel stages for same video)
- Rate limiting: configurable delay between YouTube/OpenAI API calls

---

## Copilot Query Architecture

### Scope Object

Every copilot query includes a scope object:

```typescript
interface QueryScope {
  channels?: string[];       // Filter to specific channels
  videoIds?: string[];       // Filter to specific videos
  dateRange?: {
    from?: string;           // ISO date
    to?: string;
  };
  facets?: string[];         // Topic/tag filters
  contentTypes?: string[];   // 'summary' | 'segment' | 'relationship'
}
```

### Tool Contract (Read-Only)

The copilot has access to these read-only tools:

| Tool | Description | Returns |
|------|-------------|---------|
| `search_segments` | Semantic search over segments | Ranked segments with scores |
| `search_videos` | Search videos by metadata/summary | Video cards |
| `get_video` | Get video details | Video with summary, metadata |
| `get_segments` | Get segments for a video | Segment list with timestamps |
| `get_neighbors` | Get related videos (graph) | Related videos with relationship type |
| `list_topics_in_scope` | Facet counts for current scope | Topic/count pairs |
| `get_coverage` | Library stats for scope | Video count, segment count, date range |

### Response Schema

```typescript
interface CopilotResponse {
  answer: string;              // Short response text
  videoCards: VideoCard[];     // Recommended videos
  evidence: Evidence[];        // Citations with timestamps
  scopeEcho: QueryScope;       // What was actually searched
  followups: string[];         // Suggested follow-up actions
  uncertainty?: string;        // If content insufficient
}

interface Evidence {
  videoId: string;
  videoTitle: string;
  segmentText: string;
  startTime: number;          // Seconds
  endTime: number;
  confidence: number;
}
```

### Guardrails

- **Grounding required**: Every claim must cite evidence or state uncertainty
- **No writes**: Tool contract has no write operations
- **No external access**: Tools only query ingested content
- **Scope enforcement**: All queries filtered by current scope object

### CopilotKit Integration

Frontend uses CopilotKit for:
- Chat UI rendering
- Scope chips bound to React state
- Tool execution via API proxy
- Citation rendering with clickable timestamps

---

## Query Strategy

### Vector Search (Start Simple)

For ~15,000 segments, use exact cosine distance:

```sql
-- Semantic search with scope filter
SELECT TOP 10
    s.SegmentId,
    s.VideoId,
    s.Text,
    s.StartTime,
    s.EndTime,
    VECTOR_DISTANCE('cosine', s.Embedding, @queryEmbedding) AS Distance
FROM Segments s
INNER JOIN Videos v ON s.VideoId = v.VideoId
WHERE (@channelId IS NULL OR v.ChannelId = @channelId)
  AND (@fromDate IS NULL OR v.PublishDate >= @fromDate)
  AND (@toDate IS NULL OR v.PublishDate <= @toDate)
ORDER BY Distance ASC;
```

**Future optimization**: Add HNSW index if query latency exceeds 500ms at scale.

### Graph Queries

```sql
-- Related videos (1-hop)
SELECT 
    r.TargetVideoId,
    r.RelationshipType,
    r.Confidence,
    r.Rationale,
    v.Title
FROM Relationships r
INNER JOIN Videos v ON r.TargetVideoId = v.VideoId
WHERE r.SourceVideoId = @videoId
ORDER BY r.Confidence DESC;

-- Topics in scope (facet counts)
SELECT 
    f.Name AS Topic,
    COUNT(DISTINCT vf.VideoId) AS VideoCount
FROM Facets f
INNER JOIN VideoFacets vf ON f.FacetId = vf.FacetId
INNER JOIN Videos v ON vf.VideoId = v.VideoId
WHERE (@channelId IS NULL OR v.ChannelId = @channelId)
GROUP BY f.FacetId, f.Name
ORDER BY VideoCount DESC;
```

---

## Reliability & Security

### Serverless SQL Wake-Up Handling

```python
# Database engine with retry
from tenacity import retry, stop_after_attempt, wait_exponential
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError

engine = create_engine(
    connection_string,
    pool_pre_ping=True,  # Test connections before use
    pool_recycle=300,    # Recycle connections every 5 min
)

# Route-level handling with retry decorator
@retry(
    stop=stop_after_attempt(5),
    wait=wait_exponential(multiplier=1, max=30),
    retry=lambda e: isinstance(e, OperationalError)
)
async def get_videos(db: Session):
    return db.query(Video).all()

# FastAPI exception handler
@app.exception_handler(OperationalError)
async def db_exception_handler(request, exc):
    return JSONResponse(
        status_code=503,
        content={"message": "Database warming up, please retry"}
    )
```

Frontend shows "Warming up..." toast on 503 and auto-retries.

### Security Configuration

| Resource | Auth Method |
|----------|-------------|
| SQL Database | Managed Identity (DefaultAzureCredential) |
| Blob Storage | Managed Identity |
| Storage Queue | Managed Identity |
| OpenAI API | Key Vault secret |
| YouTube API | Key Vault secret (if needed) |

### Logging Policy

- **DO log**: Correlation IDs, video IDs, job stages, error codes, latencies
- **DO NOT log**: Transcript text, embedding vectors, user queries (privacy)
- **Format**: JSON structured logs with consistent field names
- **Retention**: 30 days in Log Analytics (hobby budget)

---

## Milestones

### M1: Foundation & Single Video Ingestion

**Objective**: Ingest one video end-to-end and view its summary.

**Key Tasks**:
- [ ] Set up mono-repo structure
- [ ] Create Aspire AppHost with API and SQL connection
- [ ] Implement Video/Job/Artifact tables and migrations
- [ ] Build transcribe worker (YouTube captions or yt-dlp)
- [ ] Build summarize worker (OpenAI)
- [ ] Build API endpoints: POST /videos, GET /videos/{id}, GET /jobs/{id}
- [ ] Basic Next.js UI: submit URL, view status, display summary

**Definition of Done**: User submits a URL, sees job progress, views completed summary.

**Risks**: YouTube caption access may require fallback to audio transcription.

---

### M2: Chunking, Embedding & Library Browse

**Objective**: Generate searchable segments and browse the library.

**Key Tasks**:
- [ ] Implement Segments table with VECTOR column
- [ ] Build embed worker (OpenAI embeddings)
- [ ] Build chunk+embed stage in pipeline
- [ ] Implement library browse API with filters
- [ ] Build library UI with channel/date filters
- [ ] Video detail page with segments + timestamps

**Definition of Done**: User ingests 5+ videos, browses library, clicks through to segments.

**Risks**: Azure SQL VECTOR column performance at scale (monitor early).

---

### M3: Batch Ingestion from Channel

**Objective**: Batch-ingest multiple videos with status tracking.

**Key Tasks**:
- [ ] Implement Batch/BatchItem tables
- [ ] Channel video fetch (YouTube API or scraping)
- [ ] Batch creation UI with video selection
- [ ] Per-video status tracking in batch view
- [ ] Retry failed videos in batch

**Definition of Done**: User ingests 10 videos from a channel, sees all complete.

**Risks**: YouTube API quotas; may need to throttle.

---

### M4: Copilot Query (Core)

**Objective**: Ask questions and receive cited answers.

**Key Tasks**:
- [ ] Implement vector search endpoint
- [ ] Define copilot tool contract
- [ ] Integrate CopilotKit with scope chips
- [ ] Build response schema with citations
- [ ] Implement "Topics in Scope" panel
- [ ] Uncertainty messaging when content insufficient

**Definition of Done**: User asks a question, receives answer with video cards and clickable citations.

**Risks**: LLM grounding may require prompt engineering iteration.

---

### M5: Relationships & "Why This?"

**Objective**: Extract and display video relationships.

**Key Tasks**:
- [ ] Implement Relationships table
- [ ] Build relationship extraction worker
- [ ] Graph query endpoints
- [ ] "Why this?" panel in UI
- [ ] Evidence segment links

**Definition of Done**: User clicks "Why this?" on a recommendation and sees evidence.

**Risks**: Relationship extraction quality; may need supervised examples.

---

### M6: Structured Outputs & Polish

**Objective**: Generate learning paths and polish UX.

**Key Tasks**:
- [ ] Copilot tool for synthesized outputs
- [ ] Learning path/watch list rendering
- [ ] Follow-up suggestion buttons
- [ ] Error handling polish (dead-letter visibility, retry UX)
- [ ] Performance optimization if needed

**Definition of Done**: User requests a "learning path" and receives ordered videos with rationale.

**Risks**: Complex synthesis may require multi-step prompting.

---

### M7: Production Deployment

**Objective**: Deploy to Azure and validate end-to-end.

**Key Tasks**:
- [ ] Bicep templates for all resources
- [ ] CI/CD pipeline (GitHub Actions)
- [ ] Managed Identity configuration
- [ ] Key Vault integration
- [ ] Smoke tests in production
- [ ] Runbook documentation

**Definition of Done**: Full workflow works in production; observability verified.

**Risks**: Serverless cold start UX; may need warm-up strategy.

---

### M8: Observability & Hardening

**Objective**: Production-ready monitoring and resilience.

**Key Tasks**:
- [ ] OpenTelemetry integration
- [ ] Correlation ID propagation verified
- [ ] Log Analytics queries for common issues
- [ ] Rate limiting on workers
- [ ] Dead-letter queue monitoring
- [ ] Cost monitoring alerts

**Definition of Done**: Can trace a request from UI to worker to DB; alerts work.

**Risks**: Observability overhead on hobby budget.
