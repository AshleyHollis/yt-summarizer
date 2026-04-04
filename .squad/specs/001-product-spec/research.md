# Research: YT Summarizer Product Foundation

**Status**: Complete
**Milestone**: M1
**Spec Phase**: execution
**Created**: 2025-12-13
**Updated**: 2026-04-04

---

## Overview

Technology decisions, best practices, and resolved unknowns for the YT Summarizer implementation.
This document captures the decisions made during the research phase and is preserved as-is from
the original `specs/001-product-spec/research.md`.

---

## Technology Decisions

### 1. Transcript Acquisition Strategy

**Decision**: Use yt-dlp exclusively (refactored from youtube-transcript-api + yt-dlp dual approach).

**Rationale**:
- yt-dlp has better rate-limit handling: cookie support, client spoofing, frequent updates
- youtube-transcript-api was making duplicate requests, triggering rate limits faster
- Single library = simpler codebase, fewer requests per video
- VTT subtitles parsed with timestamps for semantic search (start_time, duration, text)

**Fallback**: Whisper transcription for videos without captions.

**Alternatives Considered**:
- YouTube Data API v3: Requires quota management, OAuth for some content
- Audio download + Whisper only: More compute cost, slower
- Third-party services: Added cost and dependency

---

### 2. Embedding Model & Dimensions

**Decision**: Use OpenAI `text-embedding-3-small` with 1,536 dimensions.

**Rationale**:
- Cost-effective for hobby project (~$0.02 per 1M tokens)
- 1,536 dimensions balances quality and storage
- Well-supported by Azure SQL VECTOR type
- Can switch to `text-embedding-3-large` later if quality issues

**Storage**:
```sql
Embedding VECTOR(1536) NOT NULL
```

---

### 3. Azure SQL VECTOR Support

**Decision**: Use native VECTOR type with exact cosine distance initially; add HNSW index if latency
exceeds 500ms.

**Rationale**:
- Azure SQL Database supports VECTOR type (2024)
- `VECTOR_DISTANCE()` function for cosine/L2/dot product
- At ~15,000 segments, exact search is likely fast enough

**Latency Expectations**:
- Exact search on 15k vectors: ~50-200ms (acceptable)
- If >500ms, create HNSW index for ANN search

---

### 4. Relationship Extraction Approach

**Decision**: LLM-based extraction using structured output (JSON) with evidence pointers.

**Relationship Types**:
| Type | Detection Method | Example |
|------|-----------------|---------|
| `series` | Title pattern ("Part 1/2/3") | "Kettlebell Series Part 3" |
| `progression` | Metadata (beginner/intermediate/advanced) | Same topic, different skill levels |
| `same-topic` | High segment similarity | Both discuss Turkish get-ups |
| `references` | Explicit mention in transcript | "As I explained in my previous video..." |
| `related` | General semantic similarity | Same domain, different focus |

---

### 5. Graph Storage Strategy

**Decision**: Use explicit Relationships table (not SQL Graph) for simplicity.

**Rationale**:
- SQL Graph adds complexity with marginal benefit at hobby scale
- Relationships are simple: Video → Video
- 1-2 hop traversals sufficient; no recursive CTEs needed

---

### 6. CopilotKit Integration

**Decision**: Use CopilotKit for frontend chat UI with custom backend tools.

**Integration Pattern**:
- Frontend: CopilotKit provider with custom scope chips, citation rendering
- Backend: AG-UI protocol endpoint with tool definitions mapping to API calls
- Knowledge source toggles: Your Videos, AI Knowledge, Web Search

---

### 7. Queue & Job Coordination

**Decision**: Azure Storage Queue with SQL job status tracking.

**Pattern**:
1. API creates Job record (pending) + queue message
2. Worker receives message, updates Job to running
3. Worker processes stages, updates Job after each stage
4. Worker completes Job (succeeded/failed), deletes message
5. If worker crashes, message becomes visible again (retry via visibility timeout)

---

### 8. OpenTelemetry & Observability

**Decision**: Full OpenTelemetry instrumentation with Aspire dashboard integration.

**Stack**:
- opentelemetry-sdk, opentelemetry-exporter-otlp for Python services
- opentelemetry-instrumentation-fastapi, -sqlalchemy, -httpx for auto-instrumentation
- Trace context propagated via queue message body (traceparent/tracestate)
- Structured logs include trace_id and span_id for log-to-trace linking

---

## Quality Commands

| Command | Purpose |
|---------|---------|
| `cd services/api && uv run pytest` | API tests |
| `cd services/workers && uv run pytest` | Worker tests |
| `cd apps/web && npm test` | Frontend unit tests |
| `cd apps/web && npx playwright test` | E2E tests |
| `cd services/api && uv run ruff check .` | Python linting |
| `cd apps/web && npm run lint` | Frontend linting |

---

## Architecture Patterns Discovered

- **Mono-repo** with `apps/`, `services/`, `infra/`, `docs/` top-level dirs
- **Shared Python package** at `services/shared/` consumed by API and all workers
- **Worker base class** at `services/workers/worker_utils/base_worker.py` with queue polling
- **Aspire AppHost** at `services/aspire/AppHost/AppHost.cs` orchestrates all services locally
- **Correlation ID** flows from UI → API middleware → queue messages → worker logs
- **Upsert semantics** for all derived data (segments, embeddings, relationships)
