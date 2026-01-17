# Architecture Overview

**YT Summarizer** transforms YouTube videos into a searchable knowledge library with AI-powered summarization and a read-only copilot for cross-video queries.

## System Context

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              YT Summarizer                                   │
│                                                                             │
│  ┌─────────┐     ┌─────────────┐     ┌────────────────────────────────┐    │
│  │   Web   │────▶│     API     │────▶│           Workers              │    │
│  │ (Next.js)│    │  (FastAPI)  │     │  (Transcribe/Summarize/Embed)  │    │
│  └─────────┘     └──────┬──────┘     └───────────────┬────────────────┘    │
│                         │                            │                      │
│                         ▼                            ▼                      │
│              ┌──────────────────┐          ┌──────────────────┐            │
│              │    Azure SQL     │          │  Azure Blob/Queue │            │
│              │  (Data + Vectors)│          │    (Artifacts)    │            │
│              └──────────────────┘          └──────────────────┘            │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
                            ┌──────────────────┐
                            │     YouTube      │
                            │  (Transcripts)   │
                            └──────────────────┘
```

## Component Diagram

### Frontend (apps/web)
- **Technology**: Next.js 14+ with TypeScript, TailwindCSS
- **Responsibilities**:
  - Video submission forms (single and batch)
  - Library browsing with filters
  - Job/batch progress tracking
  - Copilot chat interface (CopilotKit)
- **Key Features**:
  - Server-side rendering for SEO
  - Real-time polling for job status
  - Scope-aware copilot queries

### API (services/api)
- **Technology**: Python FastAPI
- **Responsibilities**:
  - REST API endpoints for all operations
  - Video/batch submission and status
  - Library browsing and filtering
  - Copilot query orchestration
  - Vector search via pgvector
- **Key Features**:
  - Correlation ID tracking
  - Structured logging
  - OpenTelemetry tracing
  - Microsoft Agent Framework integration

### Workers (services/workers)
- **Technology**: Python with Azure Storage Queue
- **Responsibilities**:
  - Asynchronous video processing pipeline
  - YouTube transcript extraction
  - AI summarization (OpenAI)
  - Embedding generation
  - Relationship extraction
- **Worker Stages**:
  1. **Transcribe**: Fetch YouTube captions via yt-dlp
  2. **Summarize**: Generate summary with OpenAI
  3. **Embed**: Create segment embeddings
  4. **Relationships**: Extract video relationships

### Shared (services/shared)
- **Technology**: Python package
- **Responsibilities**:
  - Database models (SQLAlchemy)
  - Alembic migrations
  - Azure Blob/Queue clients
  - Logging configuration
  - OpenTelemetry setup

## Data Flow

### Video Ingestion Pipeline

```
User Submits URL
       │
       ▼
┌──────────────┐
│   API        │ POST /api/v1/videos
│  (FastAPI)   │ Creates Video record + Job
└──────┬───────┘
       │ Queue: transcribe-jobs
       ▼
┌──────────────┐
│  Transcribe  │ Fetches YouTube captions
│    Worker    │ Stores transcript in Blob
└──────┬───────┘
       │ Queue: summarize-jobs
       ▼
┌──────────────┐
│  Summarize   │ Generates AI summary
│    Worker    │ Stores summary in Blob + DB
└──────┬───────┘
       │ Queue: embed-jobs
       ▼
┌──────────────┐
│    Embed     │ Creates segment embeddings
│    Worker    │ Stores vectors in Azure SQL
└──────┬───────┘
       │ Queue: relationship-jobs
       ▼
┌──────────────┐
│ Relationships│ Extracts video relationships
│    Worker    │ Updates Relationships table
└──────────────┘
       │
       ▼
Video Status: COMPLETED
```

### Copilot Query Flow

```
User Query + Scope
       │
       ▼
┌──────────────┐
│   API        │ POST /api/v1/copilot/query
│  (FastAPI)   │
└──────┬───────┘
       │
       ▼
┌──────────────┐
│ Vector Search│ Cosine similarity on embeddings
│  (pgvector)  │ Filtered by scope (channels, videos, dates)
└──────┬───────┘
       │
       ▼
┌──────────────┐
│    LLM       │ Generate grounded answer
│  (OpenAI)    │ With citations and evidence
└──────┬───────┘
       │
       ▼
Response: Answer + Citations + Video Cards
```

## Technology Stack

| Layer | Technology | Purpose |
|-------|------------|---------|
| Frontend | Next.js 14+, TypeScript | Server-rendered React app |
| UI Framework | TailwindCSS | Styling |
| Chat UI | CopilotKit | Copilot interface |
| API | FastAPI (Python 3.11+) | REST endpoints |
| Orchestration | .NET Aspire | Local dev orchestration |
| Edge Routing | NGINX Gateway Fabric + Gateway API | TLS termination and HTTP routing |
| DNS Automation | ExternalDNS + Cloudflare | Preview and production DNS management |
| Certificates | cert-manager (DNS-01) | Wildcard TLS certificates |
| Database | Azure SQL (serverless) | Operational data + vectors |

| Vector Search | VECTOR columns (SQL Server 2025) | Semantic search |
| Queue | Azure Storage Queue | Async job processing |
| Blob Storage | Azure Blob Storage | Large artifacts (transcripts, summaries) |
| AI | OpenAI GPT-4, Ada embeddings | Summarization, embeddings |
| YouTube | yt-dlp | Transcript extraction |
| Testing | pytest, Playwright | Unit + E2E tests |
| Observability | OpenTelemetry, Aspire | Distributed tracing with span links/events |

## Key Design Decisions

### 1. Azure SQL for Vectors
**Decision**: Use Azure SQL Server 2025 with native VECTOR column support instead of a separate vector database.

**Rationale**:
- Single database for all data (operational, vectors, relationships)
- Simpler architecture, fewer moving parts
- Transactional consistency between operations
- Sufficient for hobby scale (~1,500 videos)

### 2. Queue-Based Worker Pipeline
**Decision**: Use Azure Storage Queues with independent workers per stage.

**Rationale**:
- Decoupled processing stages
- Easy retry and dead-letter handling
- Can scale workers independently
- Resilient to transient failures

### 3. CopilotKit for Chat UI
**Decision**: Use CopilotKit with Microsoft Agent Framework backend.

**Rationale**:
- Rich chat UI out of the box
- Thread persistence support
- Tool integration for structured responses
- Active development and good documentation

### 4. Read-Only Copilot
**Decision**: Copilot can only query, never modify data.

**Rationale**:
- Safety boundary prevents accidental data changes
- Clear user mental model
- Simpler permission model
- All writes go through explicit UI actions

### 5. Scope Visibility
**Decision**: Always show what content the copilot is searching.

**Rationale**:
- Transparency builds trust
- Users understand query limitations
- Easy to adjust scope for better results
- Follows AI transparency best practices
