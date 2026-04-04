# YT Summarizer — Constitution

**Created**: 2026-04-04
**Project**: YT Summarizer — personal YouTube knowledge library

---

## Vision

Transform selected YouTube videos and channels into a personal, searchable knowledge library where the owner can ask questions, extract insights, and discover connections across their YouTube content — grounded in timestamped, verifiable evidence.

---

## Architecture Principles

1. **Single-owner, hobby-scale** — designed for ~1,500 videos and ~15,000 segments. No multi-tenant, no multi-user.
2. **Frontend / Backend separation** — Next.js (Azure SWA) for UI; Python/FastAPI for API and background workers.
3. **Queue-driven background processing** — Azure Storage Queue drives ingestion pipeline (transcribe → summarize → embed → relationships).
4. **Copilot is read-only** — the AI copilot MUST NOT trigger ingestion or modify any data. Strictly query-and-answer.
5. **Orchestration via .NET Aspire** — local development and deployment coordination via Aspire; AKS/ArgoCD for production.
6. **Infrastructure as Code** — all Azure resources managed via Terraform.

---

## Technology Decisions

| Concern | Decision | Rationale |
|---------|----------|-----------|
| Frontend | Next.js on Azure Static Web Apps | SSR + static export on managed Azure hosting |
| Backend API | Python/FastAPI | Async, lightweight, fast iteration |
| Background Workers | Python workers on AKS | Containerised, scalable, ArgoCD-managed |
| Database | Azure SQL (serverless) | Operational data + vectors + relationships in one place |
| AI: Chat + Summary | GPT-4o | Highest quality for summaries and grounded answers |
| AI: Embeddings | text-embedding-3-small (1,536 dims) | Cost-effective semantic search |
| Transcripts | yt-dlp (auto-captions) + Whisper (fallback) | No YouTube API key required |
| Auth | Auth0 | Managed auth, JWT, minimal maintenance |
| Local Dev Orchestration | .NET Aspire | Multi-service startup, health checks, observability |
| IaC | Terraform | Full Azure resource lifecycle |

---

## Coding Standards

### Python (Backend/Workers)
- Python 3.11+
- FastAPI for all HTTP endpoints; Pydantic v2 for validation
- SQLAlchemy 2.x async ORM; Alembic for migrations
- Type hints on all public functions
- `ruff` for linting and formatting
- Tests via pytest; E2E via Playwright

### TypeScript/Next.js (Frontend)
- TypeScript strict mode
- App Router (Next.js 14+)
- Component tests via Playwright
- `eslint` + `prettier` for formatting

### Infrastructure
- Terraform modules per concern (networking, compute, storage, ai)
- `terraform fmt` and `tflint` before every commit
- ArgoCD GitOps — all Kubernetes manifests in `gitops/` directory

---

## MUST Rules

- **MUST NOT** add multi-user or multi-tenant features without a constitution amendment
- **MUST NOT** let the AI copilot write, delete, or modify data
- **MUST NOT** require a YouTube Data API key (use yt-dlp)
- **MUST NOT** scale beyond hobby tier without explicit decision
- **MUST** include timestamped citations in every copilot answer
- **MUST** queue all ingestion via Azure Storage Queue (no synchronous ingestion in API)
- **MUST** use Infrastructure as Code for all Azure resources

---

## Commit Conventions

```
feat(scope): description
fix(scope): description
chore(scope): description
docs(scope): description
infra(scope): description
spec: description
```

Scopes: `frontend`, `backend`, `workers`, `infra`, `auth`, `db`, `ci`, `spec`

---

## Branching

- `main` — production
- `dev` — integration branch; all PRs target `dev`
- Feature branches: `squad/{issue}-{slug}` or `feat/{slug}`
