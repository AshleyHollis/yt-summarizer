# Implementation Tasks: Webshare Rotating Proxy Service

**Feature**: 005-webshare-proxy-pool
**Branch**: `005-webshare-proxy-pool`
**Generated**: 2026-02-22
**Total Tasks**: 25

---

## Phase 1: Setup

**Goal**: Add dependencies and create project structure for the proxy service module.

- [x] T001 Add `httpx` dependency to `services/shared/pyproject.toml` for proxy connectivity checks
- [x] T002 Create proxy module directory structure: `services/shared/shared/proxy/__init__.py`, `services/shared/shared/proxy/service.py`, `services/shared/shared/proxy/models.py`

## Phase 2: Foundational — Shared Proxy Service (US-005)

**Goal**: Build the shared proxy service module that all consumers depend on. This maps to US-005 (Shared Proxy Service) but is architecturally foundational — US-001, US-002, US-003, and US-004 all depend on it.

**Independent Test**: Proxy service can be instantiated, returns correct proxy URL when enabled, returns None/empty when disabled, raises `ProxyConfigurationError` when enabled with missing credentials.

- [x] T003 Add `ProxySettings` and `FeatureFlagSettings` to `services/shared/shared/config.py` with env vars: `PROXY_ENABLED`, `PROXY_GATEWAY_HOST`, `PROXY_GATEWAY_PORT`, `PROXY_USERNAME`, `PROXY_PASSWORD` (SecretStr), `PROXY_USE_BACKBONE`, `PROXY_MAX_CONCURRENCY`
- [x] T004 Implement `ProxyRequestEntry` dataclass and `ProxyUsageSummary` dataclass in `services/shared/shared/proxy/models.py`
- [x] T005 [P] Implement `ProxyConfigurationError` exception in `services/shared/shared/proxy/models.py`
- [x] T006 Implement `ProxyService` class in `services/shared/shared/proxy/service.py` with methods: `is_enabled()`, `get_proxy_url()`, `get_ydl_proxy_opts()`, `log_request()`, `get_usage_summary()`
- [x] T007 Add `ProxyRequestLog` SQLAlchemy model in `services/shared/shared/db/models.py` with fields: id, timestamp, component, operation, video_id, channel_name, job_id, correlation_id, success, error_type, estimated_bytes, duration_ms, created_at
- [x] T008 Generate Alembic migration for `proxy_request_logs` table by running `uv run alembic revision --autogenerate -m "add proxy_request_logs table"` in `services/shared/`
- [x] T009 Export public API from `services/shared/shared/proxy/__init__.py`: ProxyService, ProxySettings, ProxyRequestEntry, ProxyUsageSummary, ProxyConfigurationError
- [x] T010 Add Webshare proxy environment variables to `services/aspire/AppHost/AppHost.cs` for transcribe worker and API service resources: `PROXY_ENABLED`, `PROXY_GATEWAY_HOST`, `PROXY_GATEWAY_PORT`, `PROXY_USERNAME`, `PROXY_PASSWORD`, `PROXY_USE_BACKBONE`
- [x] T011 Add Webshare secrets (`webshare-proxy-username`, `webshare-proxy-password`) to Azure Key Vault via Terraform in `infra/terraform/`
- [x] T012 Update `services/workers/.env.example` and `services/api/.env.example` with PROXY_* environment variable templates

## Phase 3: US-001 — Proxy-Backed Transcription (P1)

**Goal**: The transcribe worker routes all YouTube (yt-dlp) requests through the Webshare rotating proxy gateway when the feature flag is enabled.

**Independent Test**: Submit a transcription job with `PROXY_ENABLED=true` and valid credentials. Verify the yt-dlp call includes the proxy configuration. When disabled, verify yt-dlp uses no proxy (existing behavior).

- [x] T013 [US1] Inject `ProxyService` into `TranscribeWorker.__init__()` and merge `proxy_service.get_ydl_proxy_opts()` into yt-dlp options in `services/workers/transcribe/worker.py`
- [x] T014 [US1] Wrap yt-dlp subtitle download with `proxy_service.log_request()` to record success/failure, duration, and estimated bytes in `services/workers/transcribe/worker.py`
- [x] T015 [US1] Update rate-limit error handling in `services/workers/transcribe/worker.py` to log proxy-specific context (component="transcribe-worker", operation="subtitle_download") when proxy is active

## Phase 4: US-002 — Proxy-Backed Channel Browsing (P1)

**Goal**: The API service routes YouTube channel/video listing requests through the proxy gateway when enabled.

**Independent Test**: Call the channel browsing API endpoint with `PROXY_ENABLED=true`. Verify yt-dlp calls in the API include proxy configuration.

- [x] T016 [P] [US2] Inject `ProxyService` and merge `get_ydl_proxy_opts()` into yt-dlp options in `services/api/src/api/services/youtube_service.py` (fetch_channel_videos, fetch_all_channel_video_ids)
- [x] T017 [P] [US2] Inject `ProxyService` and merge `get_ydl_proxy_opts()` into yt-dlp options in `services/api/src/api/services/video_service.py` (video metadata + transcript availability)
- [x] T018 [P] [US2] Inject `ProxyService` and merge `get_ydl_proxy_opts()` into yt-dlp options in `services/api/src/api/services/batch_service.py` (batch video metadata)

## Phase 5: US-003 — Concurrent Job Processing (P1)

**Goal**: When the proxy feature is enabled, the transcribe worker processes multiple queue messages concurrently using `asyncio.gather(return_exceptions=True)` with semaphore-bounded parallelism.

**Independent Test**: Queue 5 transcription jobs with proxy enabled. Verify all 5 begin processing concurrently (not sequentially). Verify one failing job does not affect the others.

- [x] T019 [US3] Add `_semaphore` (asyncio.Semaphore) and `_in_flight` task tracking set to `BaseWorker.__init__()` in `services/shared/shared/worker/base_worker.py`, gated on a `max_concurrency` parameter
- [x] T020 [US3] Implement `_process_with_semaphore()` method in `services/shared/shared/worker/base_worker.py` wrapping `_process_single_message()` with semaphore acquisition and in-flight tracking
- [x] T021 [US3] Modify `poll_once()` in `services/shared/shared/worker/base_worker.py` to use `asyncio.gather(*tasks, return_exceptions=True)` for concurrent processing when `max_concurrency > 1`, preserving sequential behavior when `max_concurrency == 1`
- [x] T022 [US3] Add graceful shutdown drain logic to `BaseWorker.run()` in `services/shared/shared/worker/base_worker.py`: wait for in-flight tasks with timeout, then cancel remaining
- [x] T023 [US3] Move `_last_youtube_request_time` and `_youtube_request_count` from module-level globals to instance variables with `asyncio.Lock` protection in `services/workers/transcribe/worker.py`

## Phase 6: US-004 — Proxy Health & Cost Monitoring (P2)

**Goal**: Operators can see proxy pool status and bandwidth usage through existing health/debug endpoints.

**Independent Test**: Query `/debug/connectivity` and verify it includes a "proxy" section with gateway reachability. Query a new `/debug/proxy` endpoint to see usage summary.

- [x] T024 [US4] Add proxy connectivity check to `get_additional_connectivity_checks()` in `services/workers/transcribe/worker.py` and API health endpoints: verify gateway reachability via `httpx` HEAD request to `p.webshare.io`
- [x] T025 [US4] Add `/debug/proxy` endpoint to `WorkerHealthServer` in `services/shared/shared/worker/health_server.py` that calls `proxy_service.get_usage_summary()` and returns total requests, success rate, estimated bandwidth, and per-component breakdown

## Phase 7: Polish & Cross-Cutting Concerns

- [x] T026 Update `services/workers/.env.example` and `services/api/.env.example` with complete PROXY_* variable documentation and example values
- [x] T027 Verify all existing tests pass with `PROXY_ENABLED=false` (default) — no regressions from proxy code paths by running `./scripts/run-tests.ps1`

---

## Dependencies

```text
Phase 1 (Setup)
  └── Phase 2 (Foundational / US-005: Shared Proxy Service)
        ├── Phase 3 (US-001: Proxy-Backed Transcription)
        ├── Phase 4 (US-002: Proxy-Backed Channel Browsing)  [parallel with Phase 3]
        ├── Phase 5 (US-003: Concurrent Processing)          [parallel with Phase 3 & 4]
        └── Phase 6 (US-004: Health & Monitoring)             [after Phase 3, needs log data]
              └── Phase 7 (Polish)
```

## Parallel Execution Opportunities

### Within Phase 2 (Foundational)
- T004 and T005 can run in parallel (separate concerns in models.py)
- T010, T011, T012 can run in parallel with T006-T009 (infrastructure vs. code)

### Phase 3, 4, and 5 are largely independent
- **Phase 3 (US-001)** and **Phase 4 (US-002)** modify different files entirely — fully parallelizable
- **Phase 5 (US-003)** modifies `base_worker.py` (shared) and `transcribe/worker.py` (shared with Phase 3) — run after Phase 3
- **Within Phase 4**: T016, T017, T018 are fully parallel (3 different API service files)

### Phase 6 depends on Phase 3
- US-004 (monitoring) needs proxy requests to have been logged — run after Phase 3

## Implementation Strategy

### MVP Scope (Recommended First Delivery)
**Phase 1 + Phase 2 + Phase 3 (US-001)**: Setup + Shared Proxy Service + Transcribe Worker Integration

This delivers the highest-value use case (proxy-backed transcription) with the shared service foundation. The transcribe worker is the primary consumer and the most impacted by YouTube rate limiting.

**MVP Task Count**: 15 tasks (T001–T015)

### Incremental Delivery After MVP
1. **Phase 4 (US-002)**: Quick win — 3 parallel tasks to add proxy to API service
2. **Phase 5 (US-003)**: Concurrency — biggest complexity, transforms throughput
3. **Phase 6 (US-004)**: Monitoring — operational visibility
4. **Phase 7**: Polish — regression verification
