# Tasks: OpenClaw Integration

**Status**: Draft
**Milestone**: M6
**Spec Phase**: tasks
**Created**: 2026-04-06
**Updated**: 2026-04-06

---

## Phase 1: Make It Work (POC)

**Goal**: End-to-end working prototype — every agent tool callable via HTTP and wired to MCP.

---

### T01 — DB Migration: Add `Segments.label` column [P]

**Agent**: Ripley
**Requires**: FR-18
**Parallel-eligible**: Yes (no dependencies on other Phase 1 tasks)

- [ ] Do: Create `services/shared/alembic/versions/015_add_segment_label.py`
  - `revision = "015"`, `down_revision = "014"`
  - Upgrade: `op.execute("ALTER TABLE Segments ADD label NVARCHAR(200) NULL")`
  - Downgrade: `op.execute("ALTER TABLE Segments DROP COLUMN label")`
- [ ] Do: Add `label: Mapped[str | None] = mapped_column(String(200), nullable=True)` to `Segment` ORM model in `services/shared/shared/db/models/segment.py`
- [ ] Verify: `cd services/api && uv run alembic upgrade head` exits 0
- [ ] Verify: `cd services/api && uv run alembic downgrade -1 && uv run alembic upgrade head` exits 0 (round-trip clean)

---

### T02 — Auth dependency: `require_api_key` [P]

**Agent**: Ripley
**Requires**: FR-14, FR-15
**Parallel-eligible**: Yes (no dependencies on other Phase 1 tasks)

- [ ] Do: Add `require_api_key` function to `services/api/src/api/dependencies/auth.py`
  - Call `_check_api_key(request)` — this already reads `API_KEY` env var and checks `X-API-Key` header
  - If result is `None`, raise `HTTPException(status_code=401, detail={"error": {"code": "UNAUTHORIZED", "message": "Valid X-API-Key header required"}})`
  - If result is an `AuthenticatedUser`, return it
  - This is strictly API-key-only — does NOT fall back to session cookie (unlike `require_auth`)
- [ ] Verify: `cd services/api && uv run pytest tests/test_auth.py -x -q` exits 0

---

### T03 — Agent API models: Pydantic models [P]

**Agent**: Ripley
**Requires**: FR-2, FR-5, FR-6, FR-9, FR-10, FR-13
**Parallel-eligible**: Yes (no dependencies on other Phase 1 tasks)

- [ ] Do: Create `services/api/src/api/models/agent.py` with all agent-layer Pydantic v2 models:
  - `SemanticSearchRequest`: `query: str`, `limit: int = Field(default=10, ge=1, le=50)`
  - `SemanticSearchResult`: `video_id: UUID`, `title: str`, `snippet: str`, `start_time: float`, `end_time: float`, `youtube_url: str`, `score: float`
  - `SemanticSearchResponse`: `results: list[SemanticSearchResult]`, `total: int`, `estimated_tokens: int`
  - `YouTubeSearchResult`: `youtube_video_id: str`, `title: str`, `channel: str`, `duration_seconds: int | None`, `url: str`, `thumbnail_url: str | None`
  - `YouTubeSearchResponse`: `results: list[YouTubeSearchResult]`, `total: int`
  - `AgentSegmentIndex`: `seq: int`, `start: float`, `end: float`, `label: str | None`
  - `AgentVideoResponse`: `video_id: UUID`, `youtube_video_id: str | None`, `title: str`, `channel_name: str | None`, `youtube_url: str | None`, `duration: int | None`, `summary: str | None`, `processing_status: str`, `segment_count: int`, `estimated_tokens: int`, `segments_index: list[AgentSegmentIndex]`
  - `SegmentDetail`: `seq: int`, `text: str`, `start_time: float`, `end_time: float`, `youtube_url: str | None`
  - `SegmentRangeResponse`: `video_id: UUID`, `segments: list[SegmentDetail]`, `total: int`, `estimated_tokens: int`
  - `AskRequest`: `query: str`, `scope: list[str] | None = None`, `max_evidence_segments: int = Field(default=5, ge=1, le=20)`
  - `AskCitation`: `video_id: UUID`, `video_title: str`, `start_time: float`, `end_time: float`, `youtube_url: str | None`, `snippet: str`, `confidence: float`
  - `AskResponse`: `answer: str`, `citations: list[AskCitation]`, `estimated_tokens: int`
  - `IngestRequest`: `url: str`
  - `IngestResponse`: `job_id: UUID`, `video_id: UUID`, `status: str`
  - `JobStatusResponse`: `job_id: UUID`, `video_id: UUID | None`, `status: str`, `progress_pct: int`, `stages: list[dict]`, `created_at: str`, `updated_at: str`
  - All models use `model_config = ConfigDict(from_attributes=True)`
- [ ] Verify: `cd services/api && uv run python -c "from api.models.agent import AgentVideoResponse, AskResponse, JobStatusResponse; print('OK')"` exits 0

---

### T04 — Agent router: `search` endpoints (semantic + YouTube)

**Agent**: Ripley
**Requires**: FR-1, FR-2, FR-3, FR-4, FR-5, FR-14
**Depends on**: T02, T03

- [ ] Do: Create `services/api/src/api/routes/agent.py` with router `APIRouter(prefix="/api/v1/agent", tags=["Agent"])`
  - Import `require_api_key` from `..dependencies.auth`
  - Implement `POST /search/semantic`: accept `SemanticSearchRequest`, `user = Depends(require_api_key)`, call `LLMService.get_embedding` then `SearchService.search_segments` (fall back to `fallback_text_search_segments` on embed error), map results to `SemanticSearchResponse`, set `estimated_tokens = sum(len(r.snippet) for r in results) // 4`
- [ ] Do: Add `YouTubeService.search_videos(query: str, limit: int) -> list[dict]` to `services/api/src/api/services/youtube_service.py`
  - Use `yt-dlp` with `ytsearch{limit}:{query}` prefix via `YoutubeDL({"quiet": True, "extract_flat": True})` and existing proxy config
  - Return list of dicts with `youtube_video_id`, `title`, `channel`, `duration_seconds`, `url`, `thumbnail_url`
  - Handle `DownloadError`, timeout, and empty results — return `[]` on error (log warning)
- [ ] Do: Implement `GET /youtube/search?q=...&limit=10` in `routes/agent.py`
  - `user = Depends(require_api_key)`, call `YouTubeService.search_videos(q, min(limit, 50))`, return `YouTubeSearchResponse`
- [ ] Verify: `cd services/api && uv run python -c "from api.routes.agent import router; print(len(router.routes), 'routes')"` exits 0 and prints ≥2

---

### T05 — Agent router: `get_video` with segment index

**Agent**: Ripley
**Requires**: FR-6, FR-7
**Depends on**: T01, T03

- [ ] Do: Add `GET /videos/{video_id}` to `services/api/src/api/routes/agent.py`
  - `user = Depends(require_api_key)`, load `Video` + `Segment` ORM records via `AsyncSession`
  - Return `AgentVideoResponse`: do NOT include full transcript text
  - Build `segments_index` from `Segment` rows: `[AgentSegmentIndex(seq=s.sequence_number, start=s.start_time, end=s.end_time, label=s.label) for s in segments]`
  - Compute `estimated_tokens` = `len(video.summary or "") // 4`
  - 404 if video not found; 401 from `require_api_key` if no key
- [ ] Verify: `cd services/api && uv run python -c "from api.routes.agent import router; routes=[r.path for r in router.routes]; assert '/api/v1/agent/videos/{video_id}' in routes, routes; print('OK')"` exits 0

---

### T06 — Agent router: `get_segments`, `ask`, `ingest`, `get_job_status`

**Agent**: Ripley
**Requires**: FR-8, FR-9, FR-10, FR-11, FR-12, FR-13, FR-15
**Depends on**: T03, T04

- [ ] Do: Add `GET /videos/{video_id}/segments?start_sec=&end_sec=` to `routes/agent.py`
  - Filter segments: `segment.start_time < end_sec AND segment.end_time > start_sec` (if params provided)
  - Return `SegmentRangeResponse` with `estimated_tokens = total_text_length // 4`
  - Build `youtube_url` per segment: `f"https://www.youtube.com/watch?v={video.youtube_video_id}&t={int(s.start_time)}s"`
- [ ] Do: Add `POST /ask` to `routes/agent.py`
  - Accept `AskRequest`, `user = Depends(require_api_key)`
  - Delegate to `CopilotService.query(CopilotQueryRequest(query=body.query, scope=body.scope))`
  - Cap evidence to `body.max_evidence_segments` citations
  - Map `CopilotQueryResponse` → `AskResponse`: flatten citations, add `estimated_tokens`
- [ ] Do: Add `POST /videos` (ingest) and `GET /jobs/{job_id}` to `routes/agent.py`
  - Ingest: `user = Depends(require_api_key)`, call `VideoService.submit_video(url)`, return `IngestResponse`
  - Job status: `user = Depends(require_api_key)`, call `JobService.get_video_jobs_progress(job_id)`, map to `JobStatusResponse`
- [ ] Verify: `cd services/api && uv run python -c "from api.routes.agent import router; print(len(router.routes), 'routes')"` prints 7 (or ≥7 including sub-paths)

---

### T07 — Register agent router in `main.py`

**Agent**: Ripley
**Requires**: FR-28
**Depends on**: T06

- [ ] Do: Add `from .routes import agent` to the imports block in `services/api/src/api/main.py` (alongside existing `copilot`, `library`, etc.)
- [ ] Do: Add `app.include_router(agent.router)` after `app.include_router(copilot.router)` in `create_app()`
- [ ] Verify: `cd services/api && uv run python -c "from api.main import create_app; app = create_app(); routes = [r.path for r in app.routes]; assert any('/api/v1/agent' in str(r) for r in routes), 'agent router not registered'; print('OK')"` exits 0

---

### [VERIFY] V1 — Smoke test: all 7 agent routes importable and registered

**Agent**: Ripley
**Depends on**: T07

- [ ] Do: Create minimal stub `services/api/tests/test_agent.py` with `@pytest.mark.unit` markers and `pass` bodies for all 7 routes (will be filled in T12)
- [ ] Verify: `cd services/api && uv run pytest tests/test_agent.py -m "unit" -x -q` exits 0
- [ ] Verify: `cd services/api && uv run python -c "from api.main import create_app; app = create_app(); paths = [r.path for r in app.routes]; [print(p) for p in paths if 'agent' in p]"` prints 7 agent paths

---

### T08 — MCP server: rewire all tools to `/api/v1/agent/` routes

**Agent**: Ripley
**Requires**: FR-19 through FR-26
**Depends on**: T07

- [ ] Do: Replace all 7 existing MCP tools in `services/mcp/yt-summarizer-mcp/server.py` with 7 new agent-optimised tools. Keep `_headers()`, `_client()`, `API_URL`, `API_KEY` helpers unchanged.
  - Remove: `submit_video`, `get_video`, `get_video_progress`, `get_transcript`, `get_summary`, `search_library`, `get_library_stats`
  - Add `search_library(query: str, limit: int = 10)` → `POST /api/v1/agent/search/semantic`
  - Add `search_youtube(query: str, limit: int = 10)` → `GET /api/v1/agent/youtube/search?q={query}&limit={limit}`
  - Add `get_video(video_id: str)` → `GET /api/v1/agent/videos/{video_id}`
  - Add `get_segments(video_id: str, start_sec: float | None = None, end_sec: float | None = None)` → `GET /api/v1/agent/videos/{video_id}/segments` (add query params when provided)
  - Add `ask(query: str, max_evidence_segments: int = 5)` → `POST /api/v1/agent/ask` (use 60s timeout for this tool only)
  - Add `ingest(url: str)` → `POST /api/v1/agent/videos`
  - Add `get_job_status(job_id: str)` → `GET /api/v1/agent/jobs/{job_id}`
- [ ] Verify: `cd services/mcp/yt-summarizer-mcp && uv run python -c "from server import mcp; tools = mcp._tool_manager.list_tools(); names = [t.name for t in tools]; print(names); assert len(names) == 7"` exits 0 and lists all 7 new tool names

---

### T09 — Summarize worker: generate segment labels after `_create_artifact`

**Agent**: Ripley
**Requires**: FR-17
**Depends on**: T01

- [ ] Do: In `services/workers/summarize/worker.py`, after the `_create_artifact(...)` call succeeds, add a `_generate_segment_labels(session, video_id, openai_client)` helper
  - Fetch all `Segment` rows for the video
  - For each segment (in order), call OpenAI chat completion: `"Summarize this transcript excerpt in 5-10 words: {segment.text[:500]}"`; use model `gpt-4o-mini` (or `gpt-3.5-turbo` as fallback)
  - Set `segment.label = response` and `await session.flush()`
  - Wrap entire function in `try/except` — label generation failure MUST NOT fail the job
  - Skip entirely if `openai_client is None` (mock mode)
- [ ] Do: Call `await _generate_segment_labels(session, video.video_id, openai_client)` in the main processing flow, guarded with `if not mock_mode`
- [ ] Verify: `cd services/workers/summarize && uv run python -c "from worker import _generate_segment_labels; print('OK')"` exits 0

---

## Phase 2: Refactoring

**Goal**: Consistent error handling, robust edge cases, production-quality code.

---

### T10 — Error handling + response normalisation in agent routes

**Agent**: Ripley
**Requires**: FR-16
**Depends on**: T07

- [ ] Do: Audit all 7 routes in `services/api/src/api/routes/agent.py` — ensure every `except` block raises `HTTPException` with `detail={"error": {"code": ..., "message": ...}}` shape matching the global error handler in `main.py`
- [ ] Do: Add `estimated_tokens` to any route response that is missing it per requirements (FR-27). Ensure `get_video` includes `estimated_tokens` based on summary length + segment index text
- [ ] Verify: `cd services/api && uv run ruff check src/api/routes/agent.py` exits 0

---

### T11 — YouTube search robustness

**Agent**: Ripley
**Requires**: FR-3, FR-4
**Depends on**: T04

- [ ] Do: In `YouTubeService.search_videos()`, wrap the yt-dlp call with an explicit `asyncio.wait_for(...)` timeout of 8 seconds (leave 2s headroom vs NFR-7's 10s target)
- [ ] Do: Handle three explicit cases: `DownloadError` (yt-dlp rate-limit/network failure), `asyncio.TimeoutError`, and no-results (empty `entries` list) — each returns `[]` and logs a structured warning with `query` and error type
- [ ] Verify: `cd services/api && uv run ruff check src/api/services/youtube_service.py` exits 0

---

## Phase 3: Testing

**Goal**: Confidence in correctness via automated tests.

---

### T12 — Unit tests: agent routes [P]

**Agent**: Kane
**Requires**: FR-1 through FR-15
**Parallel-eligible**: Yes
**Depends on**: T10

- [ ] Do: Flesh out (replace stubs from V1) `services/api/tests/test_agent.py` — use `pytest.mark.unit`, `pytest-asyncio`, `TestClient` or `AsyncClient` from `httpx`
  - Mock `require_api_key` to return a fixed `AuthenticatedUser`
  - Test: valid API key accepted (200), missing key rejected (401)
  - Test: `POST /search/semantic` returns `SemanticSearchResponse` shape
  - Test: `GET /youtube/search` returns `YouTubeSearchResponse` shape (mock `YouTubeService.search_videos`)
  - Test: `GET /videos/{id}` returns `AgentVideoResponse` without `transcript` field; 404 for unknown ID
  - Test: `GET /videos/{id}/segments?start_sec=60&end_sec=120` returns only overlapping segments
  - Test: `POST /ask` returns `AskResponse` with `answer` and `citations`; citations capped at `max_evidence_segments`
  - Test: `POST /videos` returns `IngestResponse` immediately
  - Test: `GET /jobs/{id}` returns `JobStatusResponse`
- [ ] Verify: `cd services/api && uv run pytest tests/test_agent.py -m "unit" -x -q` exits 0

---

### T13 — Unit tests: MCP tools [P]

**Agent**: Kane
**Requires**: FR-19 through FR-26
**Parallel-eligible**: Yes
**Depends on**: T08

- [ ] Do: Create `services/mcp/yt-summarizer-mcp/tests/__init__.py` and `tests/test_mcp_tools.py`
  - Mock `httpx.AsyncClient` to intercept calls
  - Test `search_library("RAG")` calls `POST /api/v1/agent/search/semantic` with correct body
  - Test `search_youtube("yt-dlp")` calls `GET /api/v1/agent/youtube/search?q=yt-dlp&limit=10`
  - Test `get_video("abc")` calls `GET /api/v1/agent/videos/abc`
  - Test `get_segments("abc", start_sec=60, end_sec=120)` calls `GET /api/v1/agent/videos/abc/segments?start_sec=60.0&end_sec=120.0`
  - Test `ask("question")` uses 60-second timeout
  - Test `ingest("https://youtube.com/watch?v=x")` calls `POST /api/v1/agent/videos`
  - Test `get_job_status("job-id")` calls `GET /api/v1/agent/jobs/job-id`
  - Test `X-API-Key` header is present on every call when `YT_SUMMARIZER_API_KEY` env var is set
- [ ] Verify: `cd services/mcp/yt-summarizer-mcp && uv run pytest tests/test_mcp_tools.py -x -q` exits 0

---

### T14 — Integration test: ingest → poll → ask flow

**Agent**: Kane
**Requires**: US6, US5
**Depends on**: T12

- [ ] Do: Create `services/api/tests/test_agent_integration.py` with `@pytest.mark.integration`
  - Requires real DB + queue (skip with `pytest.importorskip` if not available)
  - Submit a known YouTube URL via `POST /api/v1/agent/videos`
  - Poll `GET /api/v1/agent/jobs/{job_id}` up to 30 retries (1s sleep) until `status == "completed"` or `"failed"`
  - After completion, call `POST /api/v1/agent/ask` with a query about the video content — assert `answer` is non-empty and `citations` is non-empty
- [ ] Verify: `cd services/api && uv run pytest tests/test_agent_integration.py -m "integration" -x -q` exits 0 (may skip if no DB)

---

## Phase 4: Quality Gates

**Goal**: Pass lint, type checks, and all unit tests locally before pushing.

---

### [VERIFY] V4 — Local CI: lint + unit tests

**Agent**: Ripley
**Depends on**: T12, T13

- [ ] Verify: `cd services/api && uv run ruff check src/` exits 0
- [ ] Verify: `cd services/api && uv run ruff format --check src/` exits 0
- [ ] Verify: `cd services/api && uv run pytest tests/ -m "unit" -q --tb=short` exits 0
- [ ] Verify: `cd services/mcp/yt-summarizer-mcp && uv run ruff check server.py` exits 0
- [ ] Verify: `cd services/mcp/yt-summarizer-mcp && uv run pytest tests/ -q --tb=short` exits 0

---

### T15 — PR creation

**Agent**: Parker
**Depends on**: V4

- [ ] Do: Commit all changes on branch `feature/openclaw-integration` with message `feat(F006): OpenClaw MCP integration — agent API + segment labels`
- [ ] Do: Run `gh pr create --base main --head feature/openclaw-integration --title "feat(F006): OpenClaw MCP integration" --body` with body including:
  - Summary of changes (7 agent routes, 7 MCP tools, segment labels, DB migration 015)
  - Acceptance criteria checklist mirroring US1–US7 from requirements.md
  - Link to spec: `.squad/specs/006-openclaw-integration/`
- [ ] Verify: `gh pr view --json number,title,state` exits 0 and `state == "OPEN"`

---

## Phase 5: PR Lifecycle

**Goal**: Green CI, review resolved, feature merged.

---

### [VERIFY] V5 — CI pipeline passes

**Agent**: Parker
**Depends on**: T15

- [ ] Verify: `gh pr checks --watch` exits 0 (all checks green)
- [ ] Verify: `gh run list --branch feature/openclaw-integration --json status,conclusion --jq '.[] | select(.status=="completed") | .conclusion'` prints only `"success"` lines

---

### [VERIFY] V6 — Acceptance criteria checklist

**Agent**: Parker
**Depends on**: V5

- [ ] Verify: `cd services/api && uv run pytest tests/test_agent.py tests/test_agent_integration.py -q --tb=short` exits 0
- [ ] Verify: `cd services/mcp/yt-summarizer-mcp && uv run pytest tests/test_mcp_tools.py -q` exits 0
- [ ] Verify: AC checklist — run `curl -s -X POST http://localhost:8000/api/v1/agent/search/semantic -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" -d '{"query":"test"}' | python -c "import sys,json; d=json.load(sys.stdin); assert 'results' in d and 'estimated_tokens' in d"` exits 0 (US1)
- [ ] Verify: `curl -s "http://localhost:8000/api/v1/agent/youtube/search?q=yt-dlp&limit=5" -H "X-API-Key: $API_KEY" | python -c "import sys,json; d=json.load(sys.stdin); assert 'results' in d"` exits 0 (US2)
- [ ] Verify: `curl -s http://localhost:8000/api/v1/agent/search/semantic -H "Content-Type: application/json" -d '{"query":"x"}' | python -c "import sys,json; d=json.load(sys.stdin); assert d.get('error',{}).get('code')=='UNAUTHORIZED'"` exits 0 (US7 — 401 without key)
