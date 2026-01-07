<!--
===============================================================================
SYNC IMPACT REPORT
===============================================================================
Version: 1.0.1 (Development environment clarification)

Core capabilities this constitution supports:
  - Cross-video and cross-channel queries
  - Video relationships (series, progression, related topics)
  - Synthesized outputs (programs, learning paths, watch lists)
  - Citation-grounded answers from ingested library
  - Read-only copilot (no side effects)

Principles:
  I.   Product & UX (cross-content queries, citations, graceful degradation)
  II.  AI/Copilot Boundaries (read-only, grounded, library-scoped)
  III. Data & Provenance (SQL as source of truth, relationships, traceability)
  IV.  Reliability & Operations (async processing, observability)
  V.   Security (no secrets, least-privilege)
  VI.  Engineering Quality (simplicity, testing, migrations)
  VII. Change Management (amendments, compliance, pre-merge checks)

Changes in 1.0.1:
  - Clarified VI.4 to explicitly warn against 'aspire run' in addition to 'dotnet run'
  - Updated PowerShell example to use full project path argument
===============================================================================
-->

# YT Summarizer Constitution

> **Mission**: Ask questions, extract insights, and discover connections across your YouTube library—whether within a single video or spanning multiple videos and channels.

---

## Architecture Constraints

*These are guardrails, not suggestions. All implementation decisions MUST comply.*

| Layer | Technology | Notes |
|-------|-----------|-------|
| Frontend | Next.js | Deployed to Azure Static Web Apps |
| Backend | Azure Container Apps | .NET Aspire for orchestration (dev + deploy composition) |
| Services | Python (API + Workers) | Unified Python backend for code sharing |
| Database | Azure SQL (serverless) | Entities, relationships, and vector embeddings |
| Storage | Azure Blob Storage | Large artifacts (transcripts, media references) |
| Queue | Azure Storage Queue | Background job coordination |
| Identity | Azure Entra ID | Managed Identity in Azure; no secrets in code/config |

---

## Core Principles

### I. Product & UX Principles

1. **Simplicity over magic**: The UI MUST prefer explicit, predictable interactions over opaque "agent magic." Users control what gets ingested and when.

2. **Cross-content queries**: Questions MAY span multiple videos, channels, or the entire library. The system MUST support:
   - **Narrow**: "What weight does he recommend starting with?" / "Find where he demonstrates the Turkish get-up"
   - **Broad**: "List all squat variations covered in Athlean-X videos" / "How do these two channels differ on training frequency?"
   - **Synthesized**: "Build a 6-week mace progression from this channel's beginner-to-advanced videos"

3. **Transparent scope**: Every query result MUST clearly show what was searched (which videos, channels, date range) and why an answer was produced (evidence trail with citations).

4. **Citation-first answers**: All responses MUST include citations pointing to specific source segments (video + timestamp or transcript snippet). When answers draw from multiple videos, each source MUST be individually cited.

5. **Graceful degradation**: When content is missing or not yet ingested, the UI MUST:
   - Clearly state what is unavailable.
   - Suggest actionable next steps (e.g., "Add this video to your library").
   - Never hallucinate or fabricate content.

**Rationale**: A personal knowledge library is only valuable if the user trusts it. Trust requires transparency about what the system knows and doesn't know.

---

### II. AI/Copilot Boundaries (Hard Rules)

1. **Read-only chat (NON-NEGOTIABLE)**: The in-app copilot MUST be strictly read-only. It may:
   - ✅ Query across videos, channels, or the entire library.
   - ✅ Return search results with citations to specific segments.
   - ✅ Suggest related videos or viewing sequences based on stored relationships.
   - ✅ Generate structured outputs (programs, learning paths, watch lists) synthesized from library content.
   - ❌ NEVER trigger ingestion, reprocessing, or any background job.
   - ❌ NEVER modify state or write to the database.

2. **Grounded claims only**: Every factual statement MUST be grounded in stored evidence. If grounding is not possible:
   - State uncertainty explicitly ("I don't have information on this in your library").
   - Provide the nearest supported information with confidence caveats.

3. **Library-scoped knowledge**: The copilot operates exclusively on the user's ingested library. It MUST NOT imply access to external web content, real-time data, or content not yet ingested.

**Rationale**: Side effects from chat create unpredictable behavior and user confusion. Read-only guarantees make the copilot safe to use without fear of unintended consequences.

---

### III. Data & Provenance

1. **Azure SQL as source of truth**: All entities (videos, channels, segments) and relationships MUST be persisted in Azure SQL. Blob Storage is for large artifacts (full transcripts) referenced by the database.

2. **One artifact per source**: Each video has exactly one summary, one set of embeddings, etc. Processing uses upsert semantics—reprocessing overwrites, never creates duplicates.

3. **Video relationships**: Videos MAY be linked to each other. Relationships SHOULD store:
   - Relationship type (e.g., `series`, `progression`, `related`, `references`, `same-topic`)
   - Evidence pointer (which segment or metadata suggested the connection)
   
   Examples:
   - Series: "Part 1 of 5" → enables watch order
   - Progression: "Beginner → Intermediate → Advanced" → enables learning paths
   - Same-topic: "Both cover kettlebell swings" → enables cross-video answers

4. **Traceability metadata**: Derived artifacts (summaries, embeddings) SHOULD store what produced them (timestamp, model, parameters) for debugging.

**Rationale**: Cross-video connections are core to the product value. Provenance helps debugging and builds user trust.

---

### IV. Reliability & Operations

1. **Async-first background processing**: All ingestion and processing MUST be asynchronous. Jobs MUST:
   - Implement retry with exponential backoff.
   - Dead-letter failed jobs after max retries with diagnostic context.
   - Expose clear job status (pending, running, succeeded, failed) via API.

2. **Serverless wake-up resilience**: Azure SQL serverless auto-pause MUST NOT break UX. The API layer MUST:
   - Detect transient connection failures (DB waking up).
   - Retry with appropriate timeouts (up to 60s for cold start).
   - Return user-friendly "warming up" messaging rather than cryptic errors.

3. **Observability**: All components MUST emit:
   - **Structured logs** (JSON, queryable fields).
   - **Distributed traces** with correlation IDs propagated from UI → API → workers.
   
   Metrics (request counts, latencies, queue depth) are recommended but not required initially.

**Rationale**: Async processing across multiple services is painful to debug without end-to-end tracing. Invest in observability early.

---

### V. Security

1. **No secrets in repo**: Secrets MUST NOT be committed to source control. Use:
   - Azure Managed Identity for service-to-service auth.
   - Azure Key Vault for any external API keys (e.g., OpenAI).
   - Environment variables populated from secure configuration at deploy time.

2. **Least-privilege access**: Each service SHOULD have minimal permissions required.

**Rationale**: Good security hygiene is easier to maintain from the start than to retrofit.

---

### VI. Engineering Quality

1. **Simplicity first**: Optimize for maintainability and clarity. Add complexity (specialized vector indexes, caching layers) ONLY when measured need exists.

2. **Bounded queries**: All queries MUST have sensible limits:
   - Top-K retrieval with configurable but capped limits.
   - Pagination for list endpoints.
   - Sensible defaults (e.g., 10 results per page, 50 max per request).

3. **Cost-aware defaults**: Prefer serverless tiers with auto-pause, batched processing over real-time where latency tolerance exists, and cached results over recomputation.

4. **Development environment**:
   - **.NET Aspire MUST run as a detached background process** when running tests or subsequent terminal commands. Launching Aspire as a blocking foreground process will cause it to exit when the next terminal command is entered.
   - **PowerShell pattern for background Aspire**:
     ```powershell
     # Start Aspire in background (detached) - REQUIRED for non-blocking execution
     Start-Process -FilePath "dotnet" -ArgumentList "run", "--project", "services\aspire\AppHost\AppHost.csproj" -WindowStyle Hidden
     Start-Sleep -Seconds 30  # Wait for services to initialize
     ```
   - **⚠️ NEVER use `aspire run` or `dotnet run` directly** when you need to execute follow-up commands in the same session—they block the terminal and will be killed when the next command runs.
   - **Fixed ports**: API runs on `http://localhost:8000`, Web runs on `http://localhost:3000`. These are configured with `isProxied: false` in AppHost.cs.

5. **Testing**:
   - **Unit tests**: MUST cover business logic and transformation functions.
   - **Integration tests**: SHOULD cover database access and job processing.
   - **Smoke tests**: SHOULD verify deployment succeeded and critical paths work.

6. **Migration-driven schema changes**: Database schema changes MUST be defined as versioned migrations, source-controlled, and idempotent where possible.

7. **Small, reviewable PRs**: Prefer incremental changes. Each PR SHOULD address a single concern and include relevant tests.

8. **Dependency discipline**: Keep dependencies minimal and versions pinned.

9. **Documentation separation**:
   - **Specs** describe WHAT and WHY (user-visible behavior).
   - **Plans** describe HOW (architecture, stack choices).
   - **Tasks** are concrete, ordered, and testable.

**Rationale**: Clear standards help AI agents and future-you maintain the codebase. Measure before optimizing.

---

### VII. Change Management

1. **Constitution amendments**: Changes to this constitution MUST:
   - Increment the version following semantic versioning (see Governance).
   - Document the rationale ("why now").
   - Update the Sync Impact Report at the top of this file.

2. **Feature compliance**: New features MUST:
   - Reference relevant constitution principles in their spec/plan.
   - Include a Constitution Check section in the plan document.
   - Justify any complexity additions or principle deviations.

3. **Pre-merge checks**: Before merging, ask: Do tests pass? Are there secrets in code? Are DB changes in a migration? Does this violate any constitutional principle?

**Rationale**: Explicit change management prevents drift. Keep checks lightweight for a solo project.

---

## Governance

1. **Constitution authority**: This constitution supersedes all other practices. Conflicts MUST be resolved in favor of constitutional principles.

2. **Amendment process**:
   - Propose change with rationale.
   - Update version number:
     - **MAJOR**: Backward-incompatible governance/principle removals or redefinitions.
     - **MINOR**: New principle/section added or materially expanded guidance.
     - **PATCH**: Clarifications, wording, typo fixes, non-semantic refinements.
   - Update Sync Impact Report.
   - Propagate changes to dependent templates.

3. **Compliance verification**: All PRs/code reviews SHOULD verify alignment with constitutional principles. Violations MUST be justified or rejected.

4. **Runtime guidance**: For day-to-day development decisions not covered here, consult project documentation in `/docs/` or `.specify/` templates.

---

**Version**: 1.0.1 | **Ratified**: 2025-12-13 | **Last Amended**: 2025-12-14
