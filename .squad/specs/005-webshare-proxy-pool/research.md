# Research: Webshare Rotating Proxy Pool

**Feature ID**: F005
**Feature**: Webshare Rotating Proxy Pool
**Imported**: 2026-04-04 from `specs/005-webshare-proxy-pool/research.md`
**Original Date**: 2026-02-22

---

## Executive Summary

Webshare rotating residential proxies provide a single gateway endpoint that automatically delivers a different residential IP per connection from a 30M+ pool — eliminating the need for fixed IP lists, per-IP lease coordination, or cooldown management. yt-dlp natively supports proxy injection via a single `proxy` key in `ydl_opts`. Concurrent processing via `asyncio.gather(return_exceptions=True)` with an `asyncio.Semaphore` provides error-isolated parallelism. Feature flags are implemented as Pydantic Settings env vars, consistent with the project's existing config patterns.

---

## External Research

### Best Practices

- **Webshare rotating residential gateway**: `p.webshare.io:80` (HTTP) or `p.webshare.io:1080` (SOCKS5). Authentication via `http://{username}-backbone:{password}@p.webshare.io:80`. Each new TCP connection gets a different residential IP automatically.
- **yt-dlp proxy option**: Pass `{'proxy': '<url>'}` in `ydl_opts` — all network traffic (subtitle downloads, metadata, etc.) routes through the proxy. Standard, documented approach.
- **asyncio error isolation**: `asyncio.gather(return_exceptions=True)` allows independent task failure without cancelling siblings. `asyncio.TaskGroup` (Python 3.11+) cancels ALL tasks on any failure — wrong for independent message processing.
- **Structlog contextvars**: Per-task log context isolation in async code uses `contextvars`, not thread-locals.

### Prior Art

- **Environment variable proxies (`HTTP_PROXY`/`HTTPS_PROXY`)**: Rejected — affect ALL HTTP traffic including Azure SDK calls, not just YouTube.
- **ScraperAPI / BrightData**: Higher cost, vendor lock-in, unnecessary when Webshare provides built-in rotation.

### Pitfalls to Avoid

- **asyncio.TaskGroup for multi-message concurrency**: Cancels all sibling tasks when one fails — only appropriate for sub-tasks within a single message.
- **Module-level mutable state in async workers**: `_last_youtube_request_time` and `_youtube_request_count` as globals break under concurrency. Must be instance variables with `asyncio.Lock`.
- **Unbounded concurrency**: No semaphore risks exhausting thread pool, DB connections, and bandwidth simultaneously.
- **Hard bandwidth caps**: Can cause silent mid-batch job failures. Deferred to v2; rely on monitoring + Webshare plan limits in v1.

---

## Codebase Analysis

### Existing Patterns

- **Configuration**: Pydantic Settings with environment variable prefix — all services use this pattern. New `ProxySettings` nested in existing `Settings` class follows the same convention.
- **Worker base class**: `services/shared/shared/worker/base_worker.py` — `poll_once()` runs a sequential `for` loop. Target: `asyncio.gather()` over batch with semaphore bound.
- **yt-dlp call sites** (5 across 4 files):
  1. `services/workers/transcribe/worker.py` — subtitle download (primary, highest volume)
  2. `services/api/src/api/services/youtube_service.py` — channel video listing
  3. `services/api/src/api/services/video_service.py` — video metadata + transcript availability
  4. `services/api/src/api/services/batch_service.py` — batch video metadata
- **Thread pool**: `ThreadPoolExecutor` per worker — yt-dlp runs in executor. Must be sized to `max_concurrency`.
- **Health server**: `services/shared/shared/worker/health_server.py` — exposes `/debug/connectivity`. New `/debug/proxy` endpoint follows same pattern.
- **Retry logic**: `tenacity` used across workers. Proxy failures feed into existing retry-with-backoff — no new retry mechanism needed.
- **Logging**: `structlog` with `contextvars` — safe for per-task context isolation under `asyncio.gather`.

### Dependencies

- `httpx` — needed for proxy gateway connectivity check (HEAD request to `p.webshare.io`). Must be added to `services/shared/pyproject.toml`.
- `yt-dlp` — already present; `proxy` option natively supported.
- `tenacity` — already present; handles proxy transient failures via existing retry wrappers.
- `pydantic-settings` — already present; `ProxySettings` adds new fields.
- `sqlalchemy[asyncio]` — already present; `ProxyRequestLog` model adds new table.
- `alembic` — already present in `services/shared`; new migration required for `proxy_request_logs`.

### Constraints

- Python >=3.11 confirmed across all services (`asyncio.TaskGroup` available but rejected for reasons above)
- yt-dlp sleep intervals must not be modified: `sleep_interval_subtitles=60+random(0,10)`, `sleep_interval_requests=1.0`
- Queue batch size: 32 messages max — drives practical concurrency ceiling
- Webshare bandwidth: `GET /api/v2/subscription/` provides actual usage for reconciliation

---

## Quality Commands

| Type | Command | Source |
|------|---------|--------|
| Test (all) | `pwsh scripts/run-tests.ps1` | `scripts/run-tests.ps1` |
| Test (Python) | `uv run pytest` (per service dir) | pyproject.toml |
| Lint | `uv run ruff check .` | pyproject.toml |
| Format | `uv run ruff format .` | pyproject.toml |

**Local CI**: `uv run ruff check . && uv run pytest`

---

## Verification Tooling

| Tool | Command/Value | Detected From |
|------|--------------|---------------|
| Dev Server | `dotnet run --no-dashboard` in `services/aspire/AppHost/` | AppHost.cs |
| Worker Health | `http://localhost:809{x}/health` | worker health_server.py |
| Debug Connectivity | `http://localhost:809{x}/debug/connectivity` | health_server.py |
| Proxy Debug | `http://localhost:809{x}/debug/proxy` | (new endpoint, T025) |
| API Health | `http://localhost:8000/health/live` | FastAPI app |

**Project Type**: Multi-service Python workers + FastAPI API + Next.js frontend
**Verification Strategy**: Unit tests for ProxyService + BaseWorker; integration tests for yt-dlp proxy injection; health endpoint checks for monitoring; regression run with `PROXY_ENABLED=false`

---

## Related Specs

| Spec | Relationship | May Need Update |
|------|-------------|----------------|
| F001 (Transcription) | High — transcribe worker is primary consumer | No spec change; implementation extended |
| F002 (Channel Import) | High — API service channel-browsing is second consumer | No spec change; implementation extended |
| Shared Worker Base | Medium — `BaseWorker` gains concurrent processing | No separate spec |

---

## Feasibility Assessment

| Aspect | Assessment | Notes |
|--------|-----------|-------|
| Technical Viability | High | yt-dlp proxy option is standard; asyncio patterns are well-understood |
| Effort Estimate | L | 27 tasks across 7 phases; Phase 5 (concurrency) is highest complexity |
| Risk Level | Medium | Concurrency introduces race conditions in shared state; mitigated by asyncio.Lock and instance variables |

---

## Key Technical Decisions

| Decision | Options Considered | Choice | Rationale |
|----------|-------------------|--------|-----------|
| Proxy type | Datacenter static, residential static, rotating residential | Rotating residential (Webshare) | Auto IP rotation per connection; no lease management; residential harder for YouTube to detect |
| Concurrency model | asyncio.TaskGroup, asyncio.gather, horizontal scaling | `asyncio.gather(return_exceptions=True)` + Semaphore | Error isolation — sibling tasks survive one task failure |
| Feature flags | LaunchDarkly, DB-backed, env vars | Env vars via Pydantic Settings | Consistent with existing config patterns; hot-reload per poll cycle |
| Bandwidth tracking | Webshare API only, no tracking, local DB logging | Local DB logging + Webshare API for reconciliation | Immediate visibility; not dependent on external API availability |
| Credentials | Config files, .env files, Azure Key Vault | Azure Key Vault via Terraform | Security requirement; consistent with project secrets management |

---

## Sources

- `specs/005-webshare-proxy-pool/research.md` — original research document
- `specs/005-webshare-proxy-pool/contracts/proxy-service.md` — interface contract
- `specs/005-webshare-proxy-pool/data-model.md` — data model
- `services/shared/shared/worker/base_worker.py` — existing worker base
- `services/shared/shared/worker/health_server.py` — existing health server
- Webshare API docs: `proxy.webshare.io/api/v2/`
