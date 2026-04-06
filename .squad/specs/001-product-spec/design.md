# Design: YT Summarizer Product Foundation

**Status**: Implementing
**Milestone**: M1
**Spec Phase**: execution
**Created**: 2025-12-13
**Updated**: 2026-04-04

---

## Architecture Overview

YT Summarizer is a **mono-repo web application** with a Next.js frontend, Python FastAPI backend,
Python background workers, and a shared Python package. Locally orchestrated via .NET Aspire;
deployed to Azure (SWA + ACA + SQL + Storage).

### Component Diagram

```mermaid
graph TB
    User(["Library Owner"])

    subgraph "Frontend (Azure SWA)"
        Web["Next.js Web App\n:3000"]
    end

    subgraph "Backend (Azure Container Apps)"
        API["FastAPI API\n:8000"]
        TW["Transcribe Worker\n:8091"]
        SW["Summarize Worker\n:8092"]
        EW["Embed Worker\n:8093"]
        RW["Relationships Worker\n:8094"]
    end

    subgraph "Storage"
        SQL["Azure SQL Database\n(Serverless)\nOperational + VECTOR\n+ Relationships"]
        BLOB["Azure Blob Storage\nTranscripts, Summaries"]
        QUEUE["Azure Storage Queue\nJob Messages"]
    end

    subgraph "External"
        YT["YouTube\n(yt-dlp)"]
        OAI["OpenAI API\nGPT-4o + Embeddings"]
        KV["Azure Key Vault\nAPI Keys"]
    end

    User --> Web
    Web --> API
    API --> SQL
    API --> BLOB
    API --> QUEUE
    API --> YT
    API --> OAI
    QUEUE --> TW
    QUEUE --> SW
    QUEUE --> EW
    QUEUE --> RW
    TW --> SQL
    TW --> BLOB
    TW --> YT
    SW --> SQL
    SW --> BLOB
    SW --> OAI
    EW --> SQL
    EW --> OAI
    RW --> SQL
    RW --> OAI
    API --> KV
```

---

## Background Pipeline Data Flow

```mermaid
sequenceDiagram
    participant UI as Next.js UI
    participant API as FastAPI API
    participant Q as Storage Queue
    participant TW as Transcribe Worker
    participant SW as Summarize Worker
    participant EW as Embed Worker
    participant RW as Relationships Worker
    participant DB as Azure SQL
    participant BLOB as Blob Storage

    UI->>API: POST /api/v1/videos {url}
    API->>DB: Insert Video + Job (pending)
    API->>Q: Enqueue transcribe message
    API-->>UI: {videoId, jobId}

    Q->>TW: Receive transcribe job
    TW->>DB: Update Job (running, stage=transcribe)
    TW->>BLOB: Store transcript VTT
    TW->>DB: Insert Artifact (transcript)
    TW->>Q: Enqueue summarize message

    Q->>SW: Receive summarize job
    SW->>BLOB: Load transcript
    SW->>SW: GPT-4o summarize
    SW->>BLOB: Store summary
    SW->>DB: Insert Artifact (summary)
    SW->>Q: Enqueue embed message

    Q->>EW: Receive embed job
    EW->>EW: Chunk transcript into segments
    EW->>EW: Generate embeddings (batch)
    EW->>DB: Upsert Segments with vectors
    EW->>Q: Enqueue relationships message

    Q->>RW: Receive relationships job
    RW->>DB: Load video summary + existing videos
    RW->>RW: LLM relationship extraction
    RW->>DB: Upsert Relationships
    RW->>DB: Update Video (completed), Job (succeeded)
```

---

## Copilot Query Data Flow

```mermaid
sequenceDiagram
    participant UI as Next.js UI
    participant CK as CopilotKit (AG-UI)
    participant API as FastAPI API
    participant VEC as Vector Search
    participant LLM as LLM Service
    participant DB as Azure SQL

    UI->>CK: User types question + scope
    CK->>API: POST /api/v1/copilot/query
    API->>VEC: Embed query + search segments (cosine)
    VEC->>DB: VECTOR_DISTANCE() top-K segments
    DB-->>VEC: Scored segments
    VEC-->>API: Relevant segments
    API->>DB: Load relationship graph for videos
    API->>LLM: Prompt with segments + relationships
    LLM-->>API: Answer + video cards + explanations + follow-ups
    API-->>CK: CopilotQueryResponse
    CK-->>UI: Render answer + citations + scope chips
```

---

## File Structure

| Path | Create/Modify | Purpose |
|------|--------------|---------|
| `apps/web/src/app/` | Exists | Next.js App Router pages |
| `apps/web/src/components/` | Exists | React components by domain |
| `apps/web/src/components/copilot/` | Exists | CopilotKit chat components |
| `apps/web/src/components/library/` | Exists | Browse/filter components |
| `apps/web/src/components/jobs/` | Exists | Job status/progress components |
| `apps/web/src/hooks/` | Exists | Custom React hooks |
| `apps/web/src/services/api.ts` | Exists | Fetch wrapper + type-safe API client |
| `services/api/src/api/routes/` | Exists | FastAPI route handlers |
| `services/api/src/api/services/` | Exists | Business logic layer |
| `services/api/src/api/models/` | Exists | Pydantic request/response models |
| `services/api/src/api/agents/` | Exists | AG-UI agent definitions |
| `services/workers/transcribe/` | Exists | Transcript acquisition worker |
| `services/workers/summarize/` | Exists | LLM summarisation worker |
| `services/workers/embed/` | Exists | Chunking + embedding worker |
| `services/workers/relationships/` | Exists | Relationship extraction worker |
| `services/shared/shared/db/` | Exists | SQLAlchemy models + connection |
| `services/shared/shared/queue/` | Exists | Storage Queue client |
| `services/shared/shared/blob/` | Exists | Blob Storage client |
| `services/shared/shared/telemetry/` | Exists | OpenTelemetry configuration |
| `services/aspire/AppHost/AppHost.cs` | Exists | Aspire composition root |
| `infra/` | Exists | Azure infrastructure (Terraform/Bicep) |

---

## Technical Decisions

| Decision | Options Considered | Choice | Rationale |
|----------|-------------------|--------|-----------|
| Vector storage | pgvector, Pinecone, Azure SQL VECTOR | Azure SQL VECTOR | Single database; no extra service; sufficient at hobby scale |
| Queue system | Service Bus, Hangfire, SQL polling, Storage Queue | Azure Storage Queue | Serverless, cheap, simple; visibility timeout = implicit locking |
| Chat UI | Custom, LangChain, CopilotKit | CopilotKit (AG-UI) | Production-ready chat components; scope chips; citation rendering |
| Transcript acquisition | YouTube Data API, audio+Whisper, yt-dlp | yt-dlp only | Better rate-limit handling; single library; VTT with timestamps |
| Graph storage | SQL Graph, Neo4j, JSON, explicit table | Explicit Relationships table | Simplest; standard SQL queries; 1-2 hop traversals sufficient |
| Observability | Custom logging only, Datadog, OpenTelemetry | OpenTelemetry + Aspire | First-class Aspire integration; no extra cost; distributed traces |
| Explanation delivery | Separate `/explain` endpoint, inline in query | Inline in query response | Eliminates redundant embedding calls; instant UI response |

---

## API Endpoints

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/api/v1/videos` | Submit a video URL for ingestion |
| GET | `/api/v1/videos/{videoId}` | Get video details |
| POST | `/api/v1/videos/{videoId}/reprocess` | Re-queue a video for processing |
| GET | `/api/v1/jobs` | List jobs with filters |
| GET | `/api/v1/jobs/{jobId}` | Get job details |
| POST | `/api/v1/jobs/{jobId}/retry` | Retry a failed job |
| POST | `/api/v1/channels` | Fetch channel video list |
| POST | `/api/v1/batches` | Create a batch ingestion |
| GET | `/api/v1/batches` | List batches |
| GET | `/api/v1/batches/{batchId}` | Get batch detail with items |
| POST | `/api/v1/batches/{batchId}/retry` | Retry all failed in batch |
| GET | `/api/v1/library/videos` | Browse library with filters |
| GET | `/api/v1/library/channels` | List channels |
| GET | `/api/v1/library/facets` | Get facets/tags |
| GET | `/api/v1/library/videos/{videoId}/segments` | Get segments for a video |
| POST | `/api/v1/copilot/query` | Copilot query with scope |
| POST | `/api/v1/copilot/search/segments` | Semantic segment search |
| POST | `/api/v1/copilot/search/videos` | Semantic video search |
| POST | `/api/v1/copilot/topics` | Topics in scope |
| POST | `/api/v1/copilot/coverage` | Library coverage metrics |
| GET | `/api/v1/copilot/neighbors/{videoId}` | Related videos |
| POST | `/api/v1/copilot/synthesize` | Synthesize learning path / watch list |
| GET | `/health` | Health check with uptime |

---

## Data Model Summary

```mermaid
erDiagram
    Channel ||--o{ Video : "contains"
    Video ||--o{ Job : "has"
    Video ||--o{ Artifact : "has"
    Video ||--o{ Segment : "has"
    Video ||--o{ VideoFacet : "tagged"
    Video ||--o{ Relationship : "source of"
    Video ||--o{ Relationship : "target of"
    Video ||--o{ BatchItem : "in"
    Batch ||--o{ BatchItem : "contains"
    Facet ||--o{ VideoFacet : "used in"
    Segment {
        uuid SegmentId PK
        uuid VideoId FK
        float StartTime
        float EndTime
        text Text
        vector_1536 Embedding
    }
    Relationship {
        uuid RelationshipId PK
        uuid SourceVideoId FK
        uuid TargetVideoId FK
        varchar Type
        float Confidence
        nvarchar Rationale
        uuid EvidenceSegmentId FK
    }
```

---

## Error Handling Strategy

| Error Type | Handling |
|-----------|---------|
| YouTube rate limit | Detect 429 response; retry with exponential backoff |
| Invalid transcript content | Content validation before storing; treat as transient failure |
| OpenAI API error | Retry with backoff; dead-letter after max retries |
| DB cold start (serverless) | Health endpoint reports degraded; UI shows "Warming up..." banner |
| Worker crash | Message becomes visible in queue again (visibility timeout); automatic retry |
| Duplicate URL | Detect on submission; offer skip or reprocess |
| Empty scope | Explain to user and suggest broadening |

---

## Test Strategy

| Level | Tooling | Scope |
|-------|---------|-------|
| Unit (Python) | pytest | Services, workers, models, utilities |
| Integration | pytest | Database operations, queue client, blob client |
| Unit (TypeScript) | Vitest | React components, hooks, utilities |
| E2E | Playwright | Full user flows (ingest, browse, copilot, explain, synthesis) |

---

## Security

- **Network boundary trust** — no per-request API authentication between internal services
- **Managed Identity** — API and workers use Azure Managed Identity to access SQL, Blob, Queue
- **Key Vault** — OpenAI API key stored in Key Vault, accessed via Managed Identity
- **No secrets in repo** — all secrets via Aspire user-secrets or Key Vault references
- **Correlation ID** — every request traceable end-to-end without exposing internal IDs
