# Implementation Plan: Webshare Rotating Proxy Service

**Feature**: 005-webshare-proxy-pool
**Branch**: `005-webshare-proxy-pool`
**Spec**: [spec.md](./spec.md)
**Status**: Planning

---

## Summary

**Primary requirement**: Route all YouTube-bound requests (transcription, channel browsing, video metadata) through Webshare rotating residential proxies to eliminate IP-based rate limiting and enable concurrent processing.

**Technical approach**: Implement a shared proxy service module in the common `shared` library that provides a configured proxy URL to any component making yt-dlp calls. The service uses Webshare's rotating residential gateway (`p.webshare.io:80`), where each connection automatically receives a different residential IP from a pool of 30M+ addresses. Concurrency is managed at the worker level using asyncio semaphore-bounded parallel message processing. The feature is controlled by per-component feature flags configurable via environment variables.

---

## Technical Context

| Aspect | Details |
| ------ | ------- |
| Language | Python >=3.11 (workers, shared, API) |
| Dependencies | yt-dlp (YouTube interaction), Pydantic Settings (config), structlog (logging), SQLAlchemy async (DB), azure-storage-queue, azure-storage-blob, tenacity (retry), OpenTelemetry (tracing) |
| Storage | SQL Server (async via SQLAlchemy), Azure Blob Storage, Azure Storage Queues |
| Testing | pytest (unit + integration), Playwright (E2E), PowerShell test runner (`scripts/run-tests.ps1`) |
| Platform | .NET Aspire orchestration (local dev), Kubernetes (production), Windows local dev |
| Project type | Multi-service Python workers + FastAPI API orchestrated by .NET Aspire |
| Performance | yt-dlp has built-in 60-70s sleep per subtitle download; proxy gateway adds negligible latency; concurrent processing limited by queue batch size (32) |
| Constraints | Webshare rotating residential pricing is bandwidth-based; yt-dlp subtitle downloads are ~50-200KB each; all secrets must go through Azure Key Vault via Terraform |
| Scale | Current: 1 instance per worker, sequential processing. Target: same instance count, concurrent processing within each worker (bounded by asyncio semaphore) |

---

## Constitution Check

No project-specific constitution is defined (`.specify/memory/constitution.md` contains only the blank template). No gates to evaluate or violations to track.

---

## Project Structure

### Documentation Tree

```
specs/005-webshare-proxy-pool/
├── spec.md                  # Feature specification (complete)
├── plan.md                  # This implementation plan
├── research.md              # Technical research findings
├── data-model.md            # Data model for proxy request tracking
├── contracts/
│   └── proxy-service.md     # Shared proxy service interface contract
├── quickstart.md            # Developer quickstart guide
├── checklists/
│   └── requirements.md      # Quality checklist (complete)
└── tasks.md                 # Implementation tasks (future)
```

### Source Code Changes (Planned)

```
services/shared/shared/
├── proxy/                   # NEW: Shared proxy service module
│   ├── __init__.py
│   ├── service.py           # ProxyService class (gateway URL builder, feature flag check)
│   └── models.py            # ProxyRequestLog model, ProxySettings dataclass
├── config.py                # MODIFY: Add ProxySettings, FeatureFlagSettings
├── worker/
│   └── base_worker.py       # MODIFY: Add concurrent processing support (semaphore, gather)
└── db/
    └── models.py            # MODIFY: Add ProxyRequestLog table (or new migration)

services/workers/transcribe/
└── worker.py                # MODIFY: Integrate proxy service, enable concurrency

services/api/src/api/services/
├── youtube_service.py       # MODIFY: Integrate proxy service for channel browsing
├── video_service.py         # MODIFY: Integrate proxy service for video metadata
└── batch_service.py         # MODIFY: Integrate proxy service for batch operations

services/aspire/AppHost/
└── AppHost.cs               # MODIFY: Wire proxy env vars to workers + API

infra/
└── terraform/               # MODIFY: Add Webshare secrets to Key Vault
```

---

## Phase 0: Research Summary

See [research.md](./research.md) for full findings. Key decisions:

1. **Proxy type**: Rotating residential (bandwidth-based, 30M+ IPs, auto-rotation per connection)
2. **Gateway**: `http://{username}-{backbone}:{password}@p.webshare.io:80` — yt-dlp `proxy` option
3. **Concurrency model**: `asyncio.gather(return_exceptions=True)` with semaphore; NOT `TaskGroup` (error isolation needed)
4. **Thread pool**: Dedicated `ThreadPoolExecutor` per worker, sized to match max_concurrency
5. **Graceful shutdown**: Drain in-flight tasks with timeout before cancellation
6. **Error isolation**: Per-task exception handling; structlog contextvars for logging isolation
7. **Feature flags**: Environment variable based via Pydantic Settings (consistent with existing config patterns)

---

## Phase 1: Design Artifacts

- [data-model.md](./data-model.md) — Proxy request log schema, feature flag configuration
- [contracts/proxy-service.md](./contracts/proxy-service.md) — Shared proxy service interface
- [quickstart.md](./quickstart.md) — Developer setup guide
