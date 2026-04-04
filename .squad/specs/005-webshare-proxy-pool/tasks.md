# Tasks: Webshare Rotating Proxy Pool

**Feature ID**: F005
**Imported**: 2026-04-04 from `specs/005-webshare-proxy-pool/tasks.md`
**Original Generated**: 2026-02-22

## Overview
- **Total Tasks**: 27
- **Completed**: 15
- **Remaining**: 12
- **Workflow**: POC-first
- **Intent**: GREENFIELD

### Phase Distribution
| Phase | Tasks | Completed | Status |
|-------|-------|-----------|--------|
| 1 — Setup | 2 | 2 | ✅ Done |
| 2 — Shared Proxy Service (US-5) | 10 | 10 | ✅ Done |
| 3 — Proxy-Backed Transcription (US-1) | 3 | 3 | ✅ Done |
| 4 — Proxy-Backed Channel Browsing (US-2) | 3 | 0 | 🔄 In Progress |
| 5 — Concurrent Job Processing (US-3) | 5 | 0 | ⏳ Pending |
| 6 — Proxy Health & Cost Monitoring (US-4) | 2 | 0 | ⏳ Pending |
| 7 — Polish & Cross-Cutting | 2 | 0 | ⏳ Pending |

## Completion Criteria
- [ ] All tasks checked off
- [ ] All tests passing (zero regressions)
- [ ] CI green
- [ ] PR created and reviewed
- [ ] All review comments resolved

---

## Phase 1: Setup

**Goal**: Add dependencies and create project structure for the proxy service module.

- [x] T001 Add `httpx` dependency [P]
  - **Agent**: Ripley
  - **Do**:
    1. Add `httpx` to `services/shared/pyproject.toml` dependencies
    2. Run `uv sync --prerelease=allow` in `services/shared/`
  - **Files**: `services/shared/pyproject.toml`
  - **Done when**: `httpx` is importable in the shared package venv
  - **Verify**: `uv run python -c "import httpx; print('ok')"` in `services/shared/`
  - **Commit**: `chore(shared): add httpx dependency for proxy connectivity checks`

- [x] T002 Create proxy module directory structure [P]
  - **Agent**: Ripley
  - **Do**:
    1. Create `services/shared/shared/proxy/__init__.py` (empty)
    2. Create `services/shared/shared/proxy/service.py` (placeholder)
    3. Create `services/shared/shared/proxy/models.py` (placeholder)
  - **Files**: `services/shared/shared/proxy/__init__.py`, `services/shared/shared/proxy/service.py`, `services/shared/shared/proxy/models.py`
  - **Done when**: Module directory exists and is importable as `shared.proxy`
  - **Verify**: `uv run python -c "import shared.proxy"` succeeds
  - **Commit**: `feat(shared): scaffold proxy module directory`

---

## Phase 2: Foundational — Shared Proxy Service (US-5)

**Goal**: Build the shared proxy service module that all consumers depend on.

- [x] T003 Add `ProxySettings` to config [P]
  - **Agent**: Ripley
  - **Do**:
    1. Add `ProxySettings(BaseSettings)` with fields: `enabled`, `gateway_host`, `gateway_port`, `username`, `password` (SecretStr), `use_backbone`, `max_concurrency` to `services/shared/shared/config.py`
    2. Nest `ProxySettings` in main `Settings` class as `proxy: ProxySettings = ProxySettings()`
  - **Files**: `services/shared/shared/config.py`
  - **Done when**: `Settings().proxy.enabled` returns `False` by default; `PROXY_ENABLED=true` sets it to `True`
  - **Verify**: `uv run pytest tests/test_config.py -k proxy`
  - **Commit**: `feat(shared): add ProxySettings to config`
  - _Requirements: FR-001, FR-010, FR-011_

- [x] T004 Implement `ProxyRequestEntry` and `ProxyUsageSummary` dataclasses [P]
  - **Agent**: Ripley
  - **Do**:
    1. Implement `ProxyRequestEntry` dataclass in `services/shared/shared/proxy/models.py`
    2. Implement `ProxyUsageSummary` dataclass in `services/shared/shared/proxy/models.py`
  - **Files**: `services/shared/shared/proxy/models.py`
  - **Done when**: Both dataclasses can be instantiated with all documented fields
  - **Verify**: `uv run pytest tests/proxy/test_models.py`
  - **Commit**: `feat(shared): add ProxyRequestEntry and ProxyUsageSummary dataclasses`

- [x] T005 Implement `ProxyConfigurationError` [P]
  - **Agent**: Ripley
  - **Do**:
    1. Add `ProxyConfigurationError(Exception)` to `services/shared/shared/proxy/models.py`
  - **Files**: `services/shared/shared/proxy/models.py`
  - **Done when**: `ProxyConfigurationError` is a subclass of `Exception` and importable from `shared.proxy`
  - **Verify**: `uv run python -c "from shared.proxy import ProxyConfigurationError"`
  - **Commit**: `feat(shared): add ProxyConfigurationError`

- [x] T006 Implement `ProxyService` class
  - **Agent**: Ripley
  - **Do**:
    1. Implement `ProxyService` in `services/shared/shared/proxy/service.py` with methods: `is_enabled()`, `get_proxy_url()`, `get_ydl_proxy_opts()`, `log_request()`, `get_usage_summary()`
    2. `get_proxy_url()` returns `None` when disabled, raises `ProxyConfigurationError` when enabled with missing credentials
  - **Files**: `services/shared/shared/proxy/service.py`
  - **Done when**: Unit tests for all 5 methods pass with mocked settings and DB
  - **Verify**: `uv run pytest tests/proxy/test_service.py`
  - **Commit**: `feat(shared): implement ProxyService`
  - _Requirements: FR-001, FR-002, FR-003, FR-008_

- [x] T007 Add `ProxyRequestLog` SQLAlchemy model [P]
  - **Agent**: Ripley
  - **Do**:
    1. Add `ProxyRequestLog` model to `services/shared/shared/db/models.py` with all documented fields and indexes
  - **Files**: `services/shared/shared/db/models.py`
  - **Done when**: Model is importable; all fields and indexes match `data-model.md`
  - **Verify**: `uv run python -c "from shared.db.models import ProxyRequestLog"`
  - **Commit**: `feat(shared): add ProxyRequestLog SQLAlchemy model`
  - _Requirements: FR-008_

- [x] T008 Generate Alembic migration for `proxy_request_logs`
  - **Agent**: Ripley
  - **Do**:
    1. Run `uv run alembic revision --autogenerate -m "add proxy_request_logs table"` in `services/shared/`
    2. Review generated migration — verify all fields and indexes are present
    3. Run `uv run alembic upgrade head` to apply
  - **Files**: `services/shared/alembic/versions/<hash>_add_proxy_request_logs_table.py`
  - **Done when**: `proxy_request_logs` table exists in the local dev DB; migration applies cleanly from scratch
  - **Verify**: `uv run alembic current` shows head; `SELECT count(*) FROM proxy_request_logs` succeeds
  - **Commit**: `feat(shared): migration — add proxy_request_logs table`
  - _Requirements: FR-008_

- [x] T009 Export public API from `shared.proxy.__init__`
  - **Agent**: Ripley
  - **Do**:
    1. Add exports to `services/shared/shared/proxy/__init__.py`: `ProxyService`, `ProxySettings`, `ProxyRequestEntry`, `ProxyUsageSummary`, `ProxyConfigurationError`
  - **Files**: `services/shared/shared/proxy/__init__.py`
  - **Done when**: All 5 symbols importable via `from shared.proxy import X`
  - **Verify**: `uv run python -c "from shared.proxy import ProxyService, ProxySettings, ProxyRequestEntry, ProxyUsageSummary, ProxyConfigurationError"`
  - **Commit**: `feat(shared): export public proxy API`

- [x] T010 Wire `PROXY_*` env vars in Aspire AppHost [P]
  - **Agent**: Parker
  - **Do**:
    1. Add `PROXY_ENABLED`, `PROXY_GATEWAY_HOST`, `PROXY_GATEWAY_PORT`, `PROXY_USERNAME`, `PROXY_PASSWORD`, `PROXY_USE_BACKBONE` env vars to transcribe worker resource in `services/aspire/AppHost/AppHost.cs`
    2. Add same vars to API service resource
    3. Wire `PROXY_USERNAME` and `PROXY_PASSWORD` from Key Vault parameter references
  - **Files**: `services/aspire/AppHost/AppHost.cs`
  - **Done when**: Aspire starts without errors; env vars are visible in worker and API service processes
  - **Verify**: `dotnet run --no-dashboard` + check process env
  - **Commit**: `feat(aspire): wire PROXY_* env vars to transcribe worker and API service`
  - _Requirements: FR-010, FR-011_

- [x] T011 Add Webshare secrets to Azure Key Vault via Terraform [P]
  - **Agent**: Parker
  - **Do**:
    1. Add `webshare-proxy-username` and `webshare-proxy-password` secrets to Key Vault resource in `infra/terraform/`
    2. Apply terraform plan in non-prod environment
  - **Files**: `infra/terraform/` (relevant secrets file)
  - **Done when**: Both secrets exist in Key Vault; Terraform plan shows no unexpected changes
  - **Verify**: `az keyvault secret show --name webshare-proxy-username --vault-name <vault>`
  - **Commit**: `feat(infra): add Webshare proxy credentials to Key Vault`
  - _Requirements: FR-010_

- [x] T012 Update `.env.example` files [P]
  - **Agent**: Ripley
  - **Do**:
    1. Add `PROXY_*` variable templates to `services/workers/.env.example`
    2. Add `PROXY_*` variable templates to `services/api/.env.example`
  - **Files**: `services/workers/.env.example`, `services/api/.env.example`
  - **Done when**: Both files document all `PROXY_*` variables with example values and comments
  - **Verify**: `grep -c "PROXY_" services/workers/.env.example` ≥ 6
  - **Commit**: `docs(env): document PROXY_* env var templates`

---

## Phase 3: US-1 — Proxy-Backed Transcription

**Goal**: Transcribe worker routes all yt-dlp requests through the Webshare proxy when flag is enabled.

- [x] T013 Inject `ProxyService` into `TranscribeWorker` [P]
  - **Agent**: Ripley
  - **Do**:
    1. Inject `ProxyService` into `TranscribeWorker.__init__()` in `services/workers/transcribe/worker.py`
    2. Merge `proxy_service.get_ydl_proxy_opts()` into yt-dlp options dict for subtitle download
  - **Files**: `services/workers/transcribe/worker.py`
  - **Done when**: Unit test with `PROXY_ENABLED=true` → yt-dlp opts contain `proxy` key; with `false` → no `proxy` key
  - **Verify**: `uv run pytest tests/test_transcribe_worker.py -k proxy`
  - **Commit**: `feat(transcribe): inject ProxyService and merge proxy opts into yt-dlp`
  - _Requirements: FR-001, FR-002, AC-1.1, AC-1.2_

- [x] T014 Wrap yt-dlp download with `log_request()` [P]
  - **Agent**: Ripley
  - **Do**:
    1. Wrap subtitle download in `services/workers/transcribe/worker.py` with `proxy_service.log_request()` recording success/failure, duration, and estimated bytes
  - **Files**: `services/workers/transcribe/worker.py`
  - **Done when**: After a proxied download, a row exists in `proxy_request_logs` with correct `component="transcribe-worker"` and `operation="subtitle-download"`
  - **Verify**: `uv run pytest tests/test_transcribe_worker.py -k log_request`
  - **Commit**: `feat(transcribe): log proxy requests for monitoring`
  - _Requirements: FR-008_

- [x] T015 Update rate-limit error handling for proxy context [P]
  - **Agent**: Ripley
  - **Do**:
    1. Update rate-limit error handling in `services/workers/transcribe/worker.py` to log proxy-specific context (`component="transcribe-worker"`, `operation="subtitle_download"`) when proxy is active
  - **Files**: `services/workers/transcribe/worker.py`
  - **Done when**: 429 error with proxy active → log entry includes proxy component and operation fields
  - **Verify**: `uv run pytest tests/test_transcribe_worker.py -k rate_limit`
  - **Commit**: `feat(transcribe): add proxy context to rate-limit error logs`
  - _Requirements: FR-006, FR-007, AC-1.3_

---

## Phase 4: US-2 — Proxy-Backed Channel Browsing

**Goal**: API service routes YouTube channel/video listing requests through the proxy gateway.

- [ ] T016 Inject `ProxyService` into `youtube_service.py` [P]
  - **Agent**: Ripley
  - **Do**:
    1. Inject `ProxyService` into `youtube_service.py` in `services/api/src/api/services/`
    2. Merge `get_ydl_proxy_opts()` into yt-dlp opts for `fetch_channel_videos` and `fetch_all_channel_video_ids`
  - **Files**: `services/api/src/api/services/youtube_service.py`
  - **Done when**: Unit tests with proxy enabled → yt-dlp opts contain `proxy` key for both functions
  - **Verify**: `uv run pytest tests/api/services/test_youtube_service.py -k proxy`
  - **Commit**: `feat(api): inject ProxyService into youtube_service`
  - _Requirements: FR-002, FR-012, AC-2.1, AC-2.2_

- [ ] T017 Inject `ProxyService` into `video_service.py` [P]
  - **Agent**: Ripley
  - **Do**:
    1. Inject `ProxyService` into `video_service.py` in `services/api/src/api/services/`
    2. Merge `get_ydl_proxy_opts()` into yt-dlp opts for video metadata + transcript availability calls
  - **Files**: `services/api/src/api/services/video_service.py`
  - **Done when**: Unit tests with proxy enabled → yt-dlp opts contain `proxy` key
  - **Verify**: `uv run pytest tests/api/services/test_video_service.py -k proxy`
  - **Commit**: `feat(api): inject ProxyService into video_service`
  - _Requirements: FR-002, FR-012_

- [ ] T018 Inject `ProxyService` into `batch_service.py` [P]
  - **Agent**: Ripley
  - **Do**:
    1. Inject `ProxyService` into `batch_service.py` in `services/api/src/api/services/`
    2. Merge `get_ydl_proxy_opts()` into yt-dlp opts for batch video metadata calls
  - **Files**: `services/api/src/api/services/batch_service.py`
  - **Done when**: Unit tests with proxy enabled → yt-dlp opts contain `proxy` key
  - **Verify**: `uv run pytest tests/api/services/test_batch_service.py -k proxy`
  - **Commit**: `feat(api): inject ProxyService into batch_service`
  - _Requirements: FR-002, FR-012_

---

## Phase 5: US-3 — Concurrent Job Processing

**Goal**: Transcribe worker processes multiple queue messages concurrently using `asyncio.gather` + semaphore.

- [ ] T019 Add semaphore + in-flight tracking to `BaseWorker`
  - **Agent**: Ripley
  - **Do**:
    1. Add `_semaphore: asyncio.Semaphore | None` and `_in_flight: set[asyncio.Task]` to `BaseWorker.__init__()` in `services/shared/shared/worker/base_worker.py`
    2. Gate creation of semaphore on `max_concurrency` parameter (≤1 = skip semaphore / sequential)
  - **Files**: `services/shared/shared/worker/base_worker.py`
  - **Done when**: `BaseWorker(max_concurrency=5)` creates semaphore with value 5; `BaseWorker(max_concurrency=1)` skips semaphore
  - **Verify**: `uv run pytest tests/shared/test_base_worker.py -k semaphore`
  - **Commit**: `feat(shared): add semaphore and in-flight tracking to BaseWorker`
  - _Requirements: FR-005_

- [ ] T020 Implement `_process_with_semaphore()` in `BaseWorker`
  - **Agent**: Ripley
  - **Do**:
    1. Add `_process_with_semaphore(msg)` method to `BaseWorker` in `services/shared/shared/worker/base_worker.py`
    2. Acquires semaphore, calls `_process_single_message(msg)`, releases semaphore, removes from `_in_flight`
    3. Catch and log exceptions without propagating (error isolation)
  - **Files**: `services/shared/shared/worker/base_worker.py`
  - **Done when**: One task raising an exception does not affect other concurrent tasks
  - **Verify**: `uv run pytest tests/shared/test_base_worker.py -k process_with_semaphore`
  - **Commit**: `feat(shared): implement _process_with_semaphore for error-isolated concurrency`
  - _Requirements: FR-005, AC-3.3_

- [ ] T021 Modify `poll_once()` to use `asyncio.gather` for concurrent processing
  - **Agent**: Ripley
  - **Do**:
    1. Modify `poll_once()` in `services/shared/shared/worker/base_worker.py` to use `asyncio.gather(*tasks, return_exceptions=True)` when `max_concurrency > 1`
    2. Preserve existing sequential `for` loop when `max_concurrency == 1`
  - **Files**: `services/shared/shared/worker/base_worker.py`
  - **Done when**: With 10 messages and `max_concurrency=10`, all 10 begin processing without sequential blocking; with `max_concurrency=1`, sequential behaviour preserved
  - **Verify**: `uv run pytest tests/shared/test_base_worker.py -k poll_once_concurrent`
  - **Commit**: `feat(shared): concurrent poll_once via asyncio.gather + semaphore`
  - _Requirements: FR-005, AC-3.1, AC-3.2_

- [ ] T022 Add graceful shutdown drain to `BaseWorker.run()`
  - **Agent**: Ripley
  - **Do**:
    1. Add shutdown drain logic to `BaseWorker.run()` in `services/shared/shared/worker/base_worker.py`: wait for `_in_flight` tasks with configurable timeout, then cancel remaining
  - **Files**: `services/shared/shared/worker/base_worker.py`
  - **Done when**: On `SIGTERM`, in-flight tasks are awaited before exit; tasks not completing within timeout are cancelled
  - **Verify**: `uv run pytest tests/shared/test_base_worker.py -k graceful_shutdown`
  - **Commit**: `feat(shared): graceful shutdown drain for in-flight tasks`
  - _Requirements: FR-006_

- [ ] T023 Move rate-limit globals to instance variables with `asyncio.Lock`
  - **Agent**: Ripley
  - **Do**:
    1. Move `_last_youtube_request_time` and `_youtube_request_count` from module-level globals to instance variables in `TranscribeWorker.__init__()` in `services/workers/transcribe/worker.py`
    2. Protect mutations with `asyncio.Lock`
  - **Files**: `services/workers/transcribe/worker.py`
  - **Done when**: No module-level mutable state for rate-limit tracking; concurrent tasks share instance lock without data races
  - **Verify**: `uv run pytest tests/test_transcribe_worker.py -k rate_limit_concurrent`
  - **Commit**: `fix(transcribe): convert rate-limit globals to instance vars with asyncio.Lock`
  - _Requirements: FR-005_

---

## Phase 6: US-4 — Proxy Health & Cost Monitoring

**Goal**: Operators can see proxy pool status and bandwidth usage through health/debug endpoints.

- [ ] T024 Add proxy connectivity check to health endpoints
  - **Agent**: Ripley
  - **Do**:
    1. Add proxy connectivity check to `get_additional_connectivity_checks()` in `services/workers/transcribe/worker.py`: verify gateway reachability via `httpx` HEAD request to `p.webshare.io`
    2. Add same check to API service health endpoints
    3. Response shape: `{"status": "ok"|"disabled"|"error", "enabled": bool, "gateway": "host:port", "error": null|"..."}`
  - **Files**: `services/workers/transcribe/worker.py`, API health module
  - **Done when**: `GET /debug/connectivity` response contains `proxy` key with correct shape when proxy is enabled and disabled
  - **Verify**: `curl http://localhost:8091/debug/connectivity | python -m json.tool | grep -A5 proxy`
  - **Commit**: `feat(monitoring): add proxy gateway connectivity check to health endpoint`
  - _Requirements: FR-009, AC-4.1, AC-4.2_

- [ ] T025 Add `/debug/proxy` endpoint to `WorkerHealthServer`
  - **Agent**: Ripley
  - **Do**:
    1. Add `/debug/proxy` route to `WorkerHealthServer` in `services/shared/shared/worker/health_server.py`
    2. Route calls `proxy_service.get_usage_summary(since=now-24h)` and returns total requests, success rate, estimated bandwidth, and per-component breakdown
  - **Files**: `services/shared/shared/worker/health_server.py`
  - **Done when**: `GET /debug/proxy` returns JSON matching `ProxyUsageSummary` fields
  - **Verify**: `curl http://localhost:8091/debug/proxy | python -m json.tool`
  - **Commit**: `feat(monitoring): add /debug/proxy usage summary endpoint`
  - _Requirements: FR-009, AC-4.3_

---

## Phase 7: Polish & Cross-Cutting Concerns

- [ ] T026 Finalise `.env.example` documentation [P]
  - **Agent**: Ripley
  - **Do**:
    1. Update `services/workers/.env.example` and `services/api/.env.example` with complete `PROXY_*` variable documentation, descriptions, and example values
  - **Files**: `services/workers/.env.example`, `services/api/.env.example`
  - **Done when**: All `PROXY_*` variables documented with descriptions and example values
  - **Verify**: `grep -A1 "PROXY_" services/workers/.env.example` shows descriptions
  - **Commit**: `docs(env): complete PROXY_* env var documentation`

- [ ] T027 Regression verification — all existing tests pass with proxy disabled [VERIFY]
  - **Agent**: Kane
  - **Do**:
    1. Run `pwsh scripts/run-tests.ps1` with `PROXY_ENABLED=false` (default)
    2. Verify zero regressions from proxy code paths
  - **Files**: none (verification only)
  - **Done when**: All existing tests pass; no new failures introduced by proxy code paths
  - **Verify**: `pwsh scripts/run-tests.ps1`
  - **Commit**: none (verification checkpoint)
  - _Requirements: FR-001_

---

## Final Verification

- [ ] VF1 [VERIFY] Full local CI
  - **Agent**: Kane
  - **Do**: Run complete local CI pipeline with proxy disabled
  - **Verify**: `pwsh scripts/run-tests.ps1`
  - **Done when**: All commands exit 0

- [ ] VF2 [VERIFY] CI pipeline passes
  - **Agent**: Kane
  - **Do**: Verify GitHub Actions checks are green on feature branch PR
  - **Verify**: `gh pr checks --watch`
  - **Done when**: All CI checks pass

- [ ] VF3 [VERIFY] Acceptance criteria checklist
  - **Agent**: Kane
  - **Do**: Verify each AC-* from requirements.md is satisfied
  - **Verify**: See `checklists/requirements.md` — all boxes checked
  - **Done when**: All acceptance criteria confirmed
