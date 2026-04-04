<!--
===============================================================================
SYNC IMPACT REPORT
===============================================================================
Version change: 1.2.0 → 1.3.0

Core capabilities this constitution supports:
  - Cross-video and cross-channel queries
  - Video relationships (series, progression, related topics)
  - Synthesized outputs (programs, learning paths, watch lists)
  - Citation-grounded answers from ingested library
  - Read-only copilot (no side effects)
  - Auth0-backed user identity with social login and RBAC
  - YouTube access resilience via Webshare rotating proxy service
  - Zero-latency HTTPS previews via per-app Cloudflare wildcard certs

Principles:
  I.   Product & UX (cross-content queries, citations, graceful degradation, scale target)
  II.  AI/Copilot Boundaries (read-only, grounded, library-scoped)
  III. Data & Provenance (SQL as source of truth, relationships, traceability)
  IV.  Reliability & Operations (automated service mgmt, async, YouTube resilience,
       serverless wake-up, observability, GitOps)
  V.   Security (no secrets, least-privilege, Auth0 user auth, RBAC, test accounts)
  VI.  Engineering Quality (maintainability, testability, extensibility, modularity,
       onboarding, testing NON-NEGOTIABLE, migrations, dev environment)
  VII. Change Management (amendments, compliance, pre-merge checks)

Changes in 1.3.0:
  - Fixed version-line discrepancy: comment showed 1.2.0 but version line showed 1.1.0;
    all 1.2.0 engineering-quality additions preserved; baseline set to 1.2.0 → 1.3.0
  - Architecture table: added LLM row (Azure OpenAI), updated Identity to Auth0 + Azure
    Entra ID (dual purpose), added DNS/TLS row (Cloudflare + cert-manager + ExternalDNS)
  - I.6 (new): Added explicit hobby-scale target (~1,500 videos, ~15,000 segments)
  - IV: Fixed duplicate "3." numbering (was 1, 2, 3, 3, 4 → now 1, 2, 3, 4, 5, 6)
  - IV.3 (new): Added YouTube Access Resilience sub-principle (Webshare proxy service,
    feature flag per component, metrics tracking, retry/dead-letter integration)
  - IV.6 (expanded): GitOps now covers PR preview namespace lifecycle, image-digest
    promotion, Argo CD rollback, and max-3-concurrent-preview resource limit
  - V: Materially expanded Security with three new sub-rules:
      V.3 User Authentication (Auth0, social login, BFF pattern, cookie requirements)
      V.4 Role-Based Access Control (admin/normal roles, IaC-only config)
      V.5 Authentication Test Accounts (Key Vault, Terraform provisioning, CI retrieval)
  - VI: Fixed anomalous "4." heading (Development Environment now correctly VI.9)
  - VI.11–14: Renumbered from previous out-of-sequence items
  - VII.3: Pre-merge check expanded to include Auth0/infrastructure Terraform requirement

Modified principles (old title → new title):
  - V. Security: 2 sub-rules → 5 sub-rules (V.3, V.4, V.5 added)
  - IV. Reliability & Operations: 4 sub-rules → 6 sub-rules (IV.3 added, IV.6 expanded)
  - I. Product & UX: 5 items → 6 items (I.6 scale target added)

Added sections:
  - Architecture table: LLM row, DNS/TLS row, updated Identity row
  - IV.3: YouTube Access Resilience
  - V.3: User Authentication (Auth0 / BFF)
  - V.4: Role-Based Access Control
  - V.5: Authentication Test Accounts

Removed sections:
  - None

Templates requiring updates:
  ✅ .specify/templates/plan-template.md — Constitution Check gate references V.3–V.5
     Auth0 principles; no structural change required (gates are constitution-derived)
  ✅ .specify/templates/spec-template.md — No structural changes required
  ✅ .specify/templates/tasks-template.md — No structural changes required; testing
     NON-NEGOTIABLE language already present
  ✅ AGENTS.md — Auth0 BFF pattern and Key Vault credential retrieval consistent
     with V.3, V.5; aspire startup rule consistent with VI.9

Follow-up TODOs:
  - TODO(PROXY_COST): Webshare bandwidth budget ($/month) not yet codified as an
    Architecture Constraint; add when subscription tier is confirmed.
  - TODO(AUTH0_TIER): Auth0 Free tier assumed (25k MAU); revisit if team grows.
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
| Backend | AKS (Kubernetes) | Single-node, cost-optimized cluster |
| Delivery | Argo CD + Kustomize | GitOps: Argo syncs from `k8s/overlays/*` |
| Services | Python (API + Workers) | FastAPI + 4 workers: transcribe, summarize, embed, relationships |
| LLM | Azure OpenAI | GPT-4o for chat/summarization; text-embedding-3-small for embeddings |
| Database | Azure SQL (serverless) | Entities, relationships, vector embeddings (~1,500 videos / ~15,000 segments) |
| Storage | Azure Blob Storage | Large artifacts (transcripts, media references) |
| Queue | Azure Storage Queue | Background job coordination |
| Identity | Auth0 + Azure Entra ID | Auth0 for user auth (social login, RBAC); Managed Identity for service-to-service |
| DNS / TLS | Cloudflare + cert-manager | One wildcard cert per app (`*.yt-summarizer.apps.ashleyhollis.com`); ExternalDNS manages preview DNS records |

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

6. **Hobby-appropriate scale**: The system is designed for a single power user with
   approximately **1,500 videos** and **15,000 segments**. Optimizations for scale beyond
   these bounds MUST NOT be introduced without measured evidence of need (see VI.6).

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

1. **Automated service management**: ALL background services MUST use official background process pattern:
   ```powershell
   # Start Aspire in background (detached) - REQUIRED for non-blocking execution
   Start-Process -FilePath "dotnet" -ArgumentList "run", "--project", "services\aspire\AppHost\AppHost.csproj" -WindowStyle Hidden
   Start-Sleep -Seconds 30  # Wait for services to initialize
   ```
   - **⚠️ PROHIBITED**: Never use `aspire run` or `dotnet run` directly when follow-up commands are needed
   - **Verification agents MUST** use existing background processes or start them via PowerShell Start-Process
   - **Fixed ports**: API runs on `http://localhost:8000`, Web runs on `http://localhost:3000`

2. **Async-first background processing**: All ingestion and processing MUST be asynchronous. Jobs MUST:
   - Implement retry with exponential backoff.
   - Dead-letter failed jobs after max retries with diagnostic context.
   - Expose clear job status (pending, running, succeeded, failed) via API.

3. **YouTube access resilience**: YouTube-facing components MUST support routing through the shared
   proxy service to protect against IP-based rate limiting:
   - The proxy client MUST be implemented as a shared service (common library), usable by any
     component that communicates with YouTube.
   - Feature flags MUST be independently configurable per component (transcribe worker, API service).
     When disabled, components MUST fall back to the native IP with no behavioral change.
   - When proxy is enabled, workers MUST process all available queued jobs concurrently; no
     artificial concurrency cap applies.
   - Proxy metrics (total requests, success/failure counts, estimated bandwidth) MUST be tracked
     in Azure SQL and exposed via the health endpoint.
   - Retry logic MUST handle proxy failures (gateway timeouts, 429s) with backoff; after max
     retries, the job follows the existing dead-letter path.

4. **Serverless wake-up resilience**: Azure SQL serverless auto-pause MUST NOT break UX. The API layer MUST:
   - Detect transient connection failures (DB waking up).
   - Retry with appropriate timeouts (up to 60s for cold start).
   - Return user-friendly "warming up" messaging rather than cryptic errors.

5. **Observability**: All components MUST emit:
   - **Structured logs** (JSON, queryable fields).
   - **Distributed traces** with correlation IDs propagated from UI → API → workers.

   Metrics (request counts, latencies, queue depth) are recommended but not required initially.

6. **GitOps deployments**:
   - Production deployments are driven by commits to `k8s/overlays/*`; Argo CD syncs to the AKS cluster.
   - PR preview environments are deployed to isolated namespaces (`preview-pr-<N>`); they MUST be
     cleaned up automatically within 5 minutes of PR close/merge.
   - The **same Docker image digests** validated in preview MUST be promoted to production (no rebuild).
     The Kustomize overlay is updated with the pinned digest to trigger Argo CD sync.
   - Argo CD automatically rolls back to the previous healthy revision when post-deployment health
     checks fail; developers MAY also trigger rollback by reverting the merge commit.
   - Max **3 concurrent preview namespaces** enforced via resource quotas to protect production
     stability on the single-node cluster.
   - Preview DNS records (`api-pr-<N>.yt-summarizer.apps.ashleyhollis.com`) are created by
     ExternalDNS when an HTTPRoute is created and removed when the namespace is deleted.
     All previews use the shared per-app wildcard certificate; no per-PR cert provisioning.

**Rationale**: Async processing across multiple services is painful to debug without end-to-end
tracing. YouTube access resilience ensures transcript fetching is not blocked by IP-based rate
limiting. Invest in observability early.

---

### V. Security

1. **No secrets in repo**: Secrets MUST NOT be committed to source control. Use:
   - Azure Managed Identity for service-to-service auth.
   - Azure Key Vault for any external API keys (e.g., OpenAI, Webshare credentials, Auth0 secrets).
   - Environment variables populated from secure configuration at deploy time.
   - All Key Vault secret provisioning MUST be managed via Terraform (zero manual Azure Portal steps).

2. **Least-privilege access**: Each service SHOULD have minimal permissions required for its function.

3. **User authentication (Auth0)**: All user-facing authentication MUST be delegated to Auth0:
   - **Social login**: Google and GitHub MUST be supported as the primary end-user auth methods.
     No user passwords are stored in the application database.
   - **Username/password**: Available exclusively for test accounts and initial admin users
     (provisioned via Terraform; NOT self-service registration).
   - **Backend-for-Frontend (BFF) pattern**: The API handles the full Auth0 flow:
     - `GET /api/auth/login?returnTo=<web-url>` — initiates Auth0 authorization flow.
     - `GET /api/auth/callback/auth0` — handles callback; sets `HttpOnly; Secure; SameSite=None`
       session cookie. Cookie MUST NOT set a `Domain` attribute (host-only).
     - `POST /api/auth/logout` — clears the session cookie (local logout).
   - **CORS**: The API MUST enforce a strict origin allowlist for credentialed requests.
     `Access-Control-Allow-Origin: *` combined with credentials is PROHIBITED.
   - **IaC-only**: All Auth0 tenant/application configuration (connections, callback URLs,
     roles, users) MUST be provisioned via Terraform (Auth0 provider). Zero manual
     dashboard operations are permitted.

4. **Role-based access control (RBAC)**: Two roles exist: `admin` and `normal`.
   - **Admin**: full access to all features including administrative dashboards.
   - **Normal**: access to standard user features (video submission, library, copilot).
   - Role information MUST be stored in Auth0 user metadata and validated on the API for
     every protected request.
   - RBAC logic MUST be configuration-driven: adding a new role MUST require only
     configuration changes, not modifications to core auth logic (see VI.3 Extensibility).

5. **Authentication test accounts**:
   - Test accounts (one admin, one normal) MUST be provisioned via Terraform.
   - Test credentials MUST be stored in Azure Key Vault with appropriate access policies.
   - CI/CD pipelines MUST retrieve test credentials from Key Vault automatically—no
     manual credential configuration is permitted in pipelines.
   - Credentials MUST be recreatable via `terraform destroy && terraform apply` without
     data loss or manual steps.

**Rationale**: Good security hygiene is easier to maintain from the start than to retrofit.
Auth0 delegates credential management and social-login complexity; the BFF pattern keeps
tokens server-side, preventing token leakage to the browser. IaC provisioning eliminates
configuration drift and ensures reproducible environments.

---

### VI. Engineering Quality

1. **Maintainability (NON-NEGOTIABLE)**: Optimize for clarity and longevity of code changes.
   - **Module isolation**: Changes to one module MUST NOT affect others (clear module boundaries).
   - **Self-documenting code**: Names, functions, and classes MUST be self-explanatory; comments only explain WHY.
   - **Single responsibility**: Each function/class MUST have ONE clear purpose.
   - **DRY principle**: Remove duplication; extract to shared utilities when reuse >2x.
   - **Error handling**: Every function MUST handle errors appropriately (fail fast or recover gracefully).

2. **Testability (NON-NEGOTIABLE)**: Every function/component MUST be testable in isolation.
   - **Pure functions**: Where possible, functions MUST have deterministic inputs/outputs (no hidden dependencies).
   - **Dependency injection**: Service dependencies MUST be injectable to enable mocking in tests.
   - **Testable interfaces**: All external dependencies MUST have interfaces that can be mocked.
   - **No hidden state**: Functions MUST NOT rely on global or singleton state unless documented.
   - **Facilities available**: Test fixtures and helpers MUST exist for complex setup scenarios.

3. **Extensibility (NON-NEGOTIABLE)**: Easy to add new formatters, validators, or features.
   - **Plugin-like architecture**: New formatters/validators MUST be addable without modifying core logic.
   - **Strategy pattern**: Pluggable algorithms (e.g., different embedding strategies) via interface implementations.
   - **Configuration-driven**: Feature toggles or behavior changes via config, NOT if/else blocks.
   - **Open-closed principle**: Open for extension (new formatters) but closed for modification (core logic stable).
   - **Extension points clearly documented**: Where and how to extend the system MUST be obvious.

4. **Modularity (NON-NEGOTIABLE)**: Clear module boundaries make bugs easier to locate.
   - **Package/module boundaries**: Each service or domain MUST have clear interface contracts.
   - **Internal vs public API**: Internal implementation details MUST NOT leak to public interfaces.
   - **Import dependency graph**: Modules MUST be arranged in layers (no circular dependencies).
   - **Single entry point**: Each module MUST have ONE primary entry/export for consumers.
   - **Cross-cutting concerns** (logging, metrics, auth) MUST be handled via middleware/pipes, not scattered.

5. **Onboarding (CLARITY TARGET)**: New developers can understand module by module.
   - **README per module**: Each major component/service MUST have a README explaining purpose and usage.
   - **Clear examples**: Public interfaces MUST include usage examples in docstrings or README.
   - **Architecture diagrams**: Complex interactions MUST be documented with diagrams.
   - **Walkthrough comments**: Complex flows MUST have inline walkthrough comments for new devs.
   - **Naming conventions**: Consistent naming across the codebase to learn pattern once and apply everywhere.

6. **Simplicity first**: Optimize for maintainability and clarity. Add complexity (specialized
   vector indexes, caching layers) ONLY when measured need exists.

7. **Bounded queries**: All queries MUST have sensible limits:
   - Top-K retrieval with configurable but capped limits.
   - Pagination for list endpoints.
   - Sensible defaults (e.g., 10 results per page, 50 max per request).

8. **Cost-aware defaults**: Prefer serverless tiers with auto-pause, batched processing over
   real-time where latency tolerance exists, and cached results over recomputation.

9. **Development environment**:
   - **.NET Aspire is for local/dev orchestration only**. It MUST NOT be used for production deployments.
   - **Production deployments** are performed via AKS + Argo CD GitOps (see IV.6).
   - **.NET Aspire MUST run as a detached background process**. Launching Aspire as a blocking foreground process will cause it to exit when next terminal command is entered.
   - **PowerShell pattern for background Aspire**:
     ```powershell
     # Start Aspire in background (detached) - REQUIRED for non-blocking execution
     Start-Process -FilePath "dotnet" -ArgumentList "run", "--project", "services\aspire\AppHost\AppHost.csproj" -WindowStyle Hidden
     Start-Sleep -Seconds 30  # Wait for services to initialize
     ```
   - **⚠️ NEVER use `aspire run` or `dotnet run` directly** when you need to execute follow-up commands in the same session—they block the terminal and will be killed when the next command runs.
   - **Background process checks REQUIRED**: All agents MUST verify services are running via background processes and provide startup help ONLY if needed (using Start-Process pattern).

10. **Testing (NON-NEGOTIABLE)**:
   - **Unit tests**: MUST cover business logic, transformation functions, data models, and service methods.
   - **Integration tests**: MUST cover database access, message contracts, and cross-service communication.
   - **E2E tests**: MUST cover all user story acceptance criteria and critical user journeys.
   - **Test-driven development**: Tests MUST be written before implementation and fail initially.
   - **100% pass rate required**: NO task may be marked complete until ALL automated tests pass.
   - **No skipping allowed**: `-SkipE2E` or any partial test skipping is prohibited for task completion.
   - **Smoke tests**: SHOULD verify deployment succeeded and critical paths work.

11. **Migration-driven schema changes**: Database schema changes MUST be defined as versioned
    migrations (Alembic), source-controlled, and idempotent where possible.

12. **Small, reviewable PRs**: Prefer incremental changes. Each PR SHOULD address a single
    concern and include relevant tests.

13. **Dependency discipline**: Keep dependencies minimal and versions pinned.

14. **Documentation separation**:
    - **Specs** describe WHAT and WHY (user-visible behavior).
    - **Plans** describe HOW (architecture, stack choices).
    - **Tasks** are concrete, ordered, and testable.

**Rationale**: These engineering quality principles ensure the codebase is **maintainable**, **testable**, **extensible**, and **easy to understand**. Clear module boundaries and self-documenting code reduce debugging time. Testable interfaces and dependency injection enable comprehensive test coverage. Extensible architecture allows adding features without breaking existing code. Good onboarding reduces time for new developers to become productive. Measure before optimizing complexity.

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

3. **Pre-merge checks**: Before merging, verify:
   - Do all automated tests pass (unit, integration, E2E)?
   - Are there secrets in code or logs?
   - Are DB schema changes expressed as Alembic migrations?
   - Are Auth0 and infrastructure changes managed exclusively via Terraform?
   - Does this change violate any constitutional principle? If so, is the deviation justified?

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
   - **ALL dependent agents MUST be checked and updated** to reflect new principles

3. **Compliance verification**: All PRs/code reviews SHOULD verify alignment with constitutional principles. Violations MUST be justified or rejected.

4. **Runtime guidance**: For day-to-day development decisions not covered here, consult project documentation in `/docs/` or `.specify/` templates.

---

**Version**: 1.3.0 | **Ratified**: 2025-12-13 | **Last Amended**: 2026-04-04
