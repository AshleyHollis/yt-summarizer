# Research: YT Summarizer

**Feature Branch**: `001-product-spec`  
**Created**: 2025-12-13  
**Status**: Complete

---

## Overview

This document captures technology decisions, best practices, and resolved unknowns for the YT Summarizer implementation plan.

---

## Technology Decisions

### 1. Transcript Acquisition Strategy

**Decision**: Use YouTube's auto-generated captions as primary source; fall back to Whisper transcription if unavailable.

**Rationale**:
- YouTube provides free captions for most videos (auto-generated or uploaded)
- Using `youtube-transcript-api` (Python) avoids API quota costs
- Whisper (via Azure AI or local) as fallback for videos without captions
- Store transcript in Azure Blob; reference URI in SQL

**Alternatives Considered**:
- YouTube Data API v3: Requires quota management, OAuth for some content
- Audio download + Whisper only: More compute cost, slower
- Third-party services: Added cost and dependency

**Implementation Notes**:
```python
# Primary: youtube-transcript-api
from youtube_transcript_api import YouTubeTranscriptApi
transcript = YouTubeTranscriptApi.get_transcript(video_id)

# Fallback: yt-dlp + Whisper
# Download audio, transcribe with openai.audio.transcriptions
```

---

### 2. Embedding Model & Dimensions

**Decision**: Use OpenAI `text-embedding-3-small` with 1536 dimensions.

**Rationale**:
- Cost-effective for hobby project (~$0.02 per 1M tokens)
- 1536 dimensions balances quality and storage
- Well-supported by Azure SQL VECTOR type
- Can switch to `text-embedding-3-large` later if quality issues

**Alternatives Considered**:
- `text-embedding-ada-002`: Legacy, similar cost, slightly lower quality
- Local models (sentence-transformers): Requires GPU, more complexity
- Azure OpenAI: Same models, adds Azure dependency

**Storage**:
```sql
-- Azure SQL VECTOR column
Embedding VECTOR(1536) NOT NULL
```

---

### 3. Azure SQL VECTOR Support

**Decision**: Use native VECTOR type with exact cosine distance initially; add HNSW index if latency exceeds 500ms.

**Rationale**:
- Azure SQL Database now supports VECTOR type (2024)
- `VECTOR_DISTANCE()` function for cosine/L2/dot product
- At ~15,000 segments, exact search is likely fast enough
- HNSW index available if needed: `CREATE VECTOR INDEX`

**Best Practices**:
- Use `VECTOR(1536)` for fixed-dimension columns
- Index on VideoId + StartTime for segment lookups
- Batch insert segments for performance

**Latency Expectations**:
- Exact search on 15k vectors: ~50-200ms (acceptable)
- If >500ms, create HNSW index for ANN search

---

### 4. Relationship Extraction Approach

**Decision**: LLM-based extraction using structured output (JSON) with evidence pointers.

**Rationale**:
- Relationships are semantic (series, progression, same-topic)
- LLM can identify from titles, descriptions, and transcript content
- Structured output ensures parseable results
- Evidence pointer (segment ID or metadata field) enables "Why this?" feature

**Extraction Pipeline**:
1. After video embedding, compare against existing videos
2. High similarity triggers relationship candidate
3. LLM prompt: "Given these two videos, identify relationship type and evidence"
4. Store with confidence score and rationale

**Relationship Types**:
| Type | Detection Method | Example |
|------|-----------------|---------|
| `series` | Title pattern ("Part 1/2/3", episode numbers) | "Kettlebell Series Part 3" |
| `progression` | Metadata (beginner/intermediate/advanced) | Same topic, different skill levels |
| `same-topic` | High segment similarity | Both discuss Turkish get-ups |
| `references` | Explicit mention in transcript | "As I explained in my previous video..." |
| `related` | General semantic similarity | Same domain, different focus |

---

### 5. Graph Storage Strategy

**Decision**: Use explicit Relationships table (not SQL Graph) for simplicity.

**Rationale**:
- SQL Graph (node/edge tables) adds complexity
- Relationships are simple: Video → Video or Video → Concept
- 1-2 hop traversals sufficient; no need for recursive CTEs
- Easier to query and index with standard SQL

**Schema Approach**:
```sql
CREATE TABLE Relationships (
    RelationshipId UNIQUEIDENTIFIER PRIMARY KEY,
    SourceVideoId UNIQUEIDENTIFIER NOT NULL,
    TargetVideoId UNIQUEIDENTIFIER NOT NULL,
    RelationshipType VARCHAR(50) NOT NULL,
    Confidence FLOAT NOT NULL,
    Rationale NVARCHAR(500),
    EvidenceSegmentId UNIQUEIDENTIFIER NULL,
    CreatedAt DATETIME2 NOT NULL,
    CONSTRAINT FK_Source FOREIGN KEY (SourceVideoId) REFERENCES Videos(VideoId),
    CONSTRAINT FK_Target FOREIGN KEY (TargetVideoId) REFERENCES Videos(VideoId),
    CONSTRAINT UQ_Relationship UNIQUE (SourceVideoId, TargetVideoId, RelationshipType)
);
```

**Alternatives Considered**:
- SQL Graph: More complex syntax, marginal benefit at scale
- Separate graph database (Neo4j): Over-engineering for hobby project
- JSON column for relationships: Harder to query

---

### 6. CopilotKit Integration

**Decision**: Use CopilotKit for frontend chat UI with custom backend tools.

**Rationale**:
- CopilotKit provides production-ready chat components
- Supports tool definitions that map to API calls
- Scope chips integrate with React state
- Citation rendering built-in

**Integration Pattern**:
```typescript
// Frontend: CopilotKit provider
<CopilotKit runtimeUrl="/api/copilot">
  <CopilotSidebar>
    <ScopeChips scope={currentScope} onChange={setScope} />
    <ChatMessages />
  </CopilotSidebar>
</CopilotKit>

// Backend: Tool definitions
const tools = [
  { name: "search_segments", handler: searchSegmentsHandler },
  { name: "get_neighbors", handler: getNeighborsHandler },
  // ...
];
```

---

### 7. Queue & Job Coordination

**Decision**: Azure Storage Queue with SQL job status tracking.

**Rationale**:
- Storage Queue is serverless, cheap, and simple
- Queue message triggers worker; SQL tracks detailed status
- Visibility timeout provides implicit locking
- Dead-letter queue for failed messages

**Pattern**:
1. API creates Job record (pending) + queue message
2. Worker receives message, updates Job to running
3. Worker processes stages, updates Job after each
4. Worker completes Job (succeeded/failed), deletes message
5. If worker crashes, message becomes visible again (retry)

**Alternatives Considered**:
- Azure Service Bus: More features, more cost
- Hangfire/Quartz: In-process, less resilient
- SQL-only polling: Higher DB load

---

### 8. .NET Aspire Composition

**Decision**: Use Aspire AppHost for local orchestration and as deployment manifest source.

**Rationale**:
- Aspire provides service discovery and connection string injection
- Works with containers (Python API and workers)
- Azure Developer CLI can deploy from Aspire manifest
- Dashboard for local observability
- All Python services receive configuration via environment variables

**Composition**:
```csharp
var builder = DistributedApplication.CreateBuilder(args);

var sql = builder.AddSqlServer("sql")
    .AddDatabase("ytsummarizer");

var storage = builder.AddAzureStorage("storage")
    .AddBlobs("blobs")
    .AddQueues("queues");

// Python API container
var api = builder.AddContainer("api", "ytsummarizer-api")
    .WithReference(sql)
    .WithReference(storage)
    .WithHttpEndpoint(port: 8000, targetPort: 8000);

var web = builder.AddNpmApp("web", "../apps/web")
    .WithReference(api)
    .WithHttpEndpoint(port: 3000);

// Python worker containers
var transcribeWorker = builder.AddContainer("transcribe", "ytsummarizer-transcribe")
    .WithReference(sql)
    .WithReference(storage);

var summarizeWorker = builder.AddContainer("summarize", "ytsummarizer-summarize")
    .WithReference(sql)
    .WithReference(storage);

// Similar for embed, relationships workers...

builder.Build().Run();
```

---

### 9. Migration Strategy

**Decision**: Use Alembic for SQL migrations (Python ecosystem).

**Rationale**:
- Alembic is the standard migration tool for SQLAlchemy
- Works seamlessly with Python API codebase
- Auto-generates migrations from model changes
- Version tracking in `alembic_version` table
- Integrates with shared Python models
- Can run from CLI or integrate into deployment

**Alternatives Considered**:
- EF Core Migrations: Tied to .NET, complex for polyglot
- Flyway: Java dependency
- Manual scripts: No version tracking

**Workflow**:
```bash
# Run migrations
dotnet run --project db/Migrator -- --connection "..."

# Migration naming: V001__description.sql
```

---

### 10. Frontend Deployment (SWA)

**Decision**: Deploy Next.js to Azure Static Web Apps with API proxying.

**Rationale**:
- SWA supports Next.js (hybrid rendering)
- Built-in CDN and SSL
- API routes can proxy to backend ACA
- GitHub Actions integration

**Configuration**:
```json
// staticwebapp.config.json
{
  "routes": [
    {
      "route": "/api/*",
      "allowedRoles": ["authenticated"],
      "rewrite": "https://api.{azure-container-app-url}/api/*"
    }
  ]
}
```

---

## Resolved Unknowns

| Unknown | Resolution |
|---------|------------|
| Transcript source priority | YouTube captions first, Whisper fallback |
| Embedding model choice | OpenAI text-embedding-3-small (1536 dim) |
| Vector index strategy | Exact search first; HNSW if needed |
| Graph storage | Explicit Relationships table (not SQL Graph) |
| Relationship extraction | LLM-based with structured output |
| Queue technology | Azure Storage Queue |
| Migration tool | Alembic (Python) |
| Copilot UI framework | CopilotKit |

---

## Best Practices Adopted

### Python API

- FastAPI for REST endpoints with automatic OpenAPI docs
- SQLAlchemy for ORM with Azure SQL
- Pydantic for request/response validation
- azure-identity for Managed Identity (DefaultAzureCredential)
- tenacity for retry policies
- Structured logging (structlog)
- pytest + httpx for testing

### Python Workers

- Shared code from `/services/shared` package
- Environment-based configuration (pydantic-settings)
- Type hints throughout
- pytest with fixtures for integration tests

### Next.js Frontend

- App Router (Next.js 14+)
- Server components for library pages
- Client components for chat UI
- TailwindCSS for styling
- React Query for data fetching

### Observability

- OpenTelemetry SDK in all services
- Correlation ID in HTTP headers (`X-Correlation-Id`)
- Azure Application Insights export
- Structured JSON logs with common schema

---

## Dependencies Summary

| Component | Key Packages |
|-----------|-------------|
| API (Python) | `fastapi`, `sqlalchemy`, `pydantic`, `azure-identity`, `azure-storage-queue`, `tenacity`, `structlog` |
| Workers (Python) | `youtube-transcript-api`, `openai`, `azure-storage-queue`, `pydantic`, `structlog` |
| Shared (Python) | `sqlalchemy`, `azure-identity`, `pydantic-settings`, `structlog` |
| Frontend (Next.js) | `next`, `react`, `@copilotkit/react-core`, `tailwindcss`, `@tanstack/react-query` |
| Migrations | `alembic` |
| Testing | `pytest`, `httpx`, `playwright` |

---

**Phase 0 Complete**: All research questions resolved. Proceed to Phase 1 (data model and contracts).
