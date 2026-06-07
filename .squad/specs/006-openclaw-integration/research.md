# Research: OpenClaw Integration

**Status**: Complete
**Milestone**: M6
**Spec Phase**: research
**Created**: 2026-04-06
**Updated**: 2026-04-06

---

## 1. MCP Library Decision

### Finding: Library Already Chosen

The repo already contains a working MCP server at `services/mcp/yt-summarizer-mcp/server.py`. It uses:

```python
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("yt-summarizer")

@mcp.tool()
async def search_library(query: str, limit: int = 10) -> str:
    ...
```

**Library**: `mcp>=1.0.0` (official Anthropic SDK). `FastMCP` is the high-level decorator API shipped inside the `mcp` package — no need to install `fastmcp` separately.

**Recommendation**: Continue with `mcp` + `FastMCP`. No library change needed.

### Architecture Finding: Sidecar, Not In-Process

Goals.md specifies "same process, separate port (:8001)" but the existing MCP server is a **standalone sidecar** process that calls the API over HTTP (`httpx` to `YT_SUMMARIZER_API_URL`). This is actually simpler and already works.

**Revised architecture recommendation**:
1. Add new `/agent/v1/` FastAPI routes to the existing API service (port 8000)
2. Update the existing MCP sidecar (`services/mcp/`) to wrap those new routes instead of the current ad-hoc library endpoints
3. Register the MCP sidecar in AppHost.cs as a separate process (just like the workers)

This avoids the complexity of in-process port multiplexing while meeting all SC criteria. The "same process" constraint in goals.md can be relaxed — the sidecar model is better for separation of concerns and the MCP SDK is designed for this pattern.

If strict in-process is required, `FastMCP` can start an SSE server in a background asyncio task during FastAPI lifespan — but this is an unnecessary complication.

---

## 2. Existing API Reuse Map

| Agent Tool | Existing Route/Service | Reuse Level | New Work Required |
|---|---|---|---|
| `search_library` | `POST /api/v1/copilot/search/segments` → `SearchService.search_segments` | High — vector + text search already work | New `/agent/v1/search` route reshaping output to flat LLM JSON; add `estimated_tokens` |
| `search_youtube` | `YouTubeService` (yt-dlp, channel fetch) — no search method yet | Medium — service exists, proxy support exists | Add `YouTubeService.search_videos()` using yt-dlp `ytsearch{n}:` prefix; new route |
| `get_video` | `GET /api/v1/library/videos/{id}` → `LibraryService.get_video_detail` | Medium — video metadata exists | New route with `segment_index` shape; `label` field requires DB migration + summarize worker change |
| `get_segments` | `GET /api/v1/library/videos/{id}/segments` → `LibraryService.list_segments` | High — pagination already works | New route adding `start_sec`/`end_sec` range filter + `estimated_tokens`; deeplink URL assembly |
| `ask` | `POST /api/v1/copilot/query` → `CopilotService.query` | High — RAG + citations already work | New `/agent/v1/ask` route adapting existing CopilotService; flatten response for LLM consumption |
| `ingest` | `POST /api/v1/videos` → `VideoService.submit_video` | High — queue dispatch already works | New route with API-key auth (no Auth0/quota); return `job_id` in flat format |
| `get_job_status` | `GET /api/v1/jobs/video/{id}/progress` → `JobService.get_video_jobs_progress` | High — 4-stage progress already tracked | New route with consistent error format + simplified status shape |

**Key services powering the agent API**:
- `SearchService` — vector similarity via SQL Server VECTOR_DISTANCE; text fallback
- `CopilotService` — full RAG query orchestration with LLM
- `LibraryService` — video/segment/channel CRUD
- `JobService` — job status tracking with per-stage progress
- `VideoService` — video ingestion queue dispatch
- `YouTubeService` — yt-dlp wrapper (proxy-aware)

---

## 3. Segment Label Migration

### Current Schema (Migration 003)

```sql
Segments (
  segment_id       UNIQUEIDENTIFIER PK,
  video_id         UNIQUEIDENTIFIER FK,
  sequence_number  INT,
  start_time       FLOAT,
  end_time         FLOAT,
  text             NVARCHAR(MAX),
  content_hash     NVARCHAR(64),
  model_name       NVARCHAR(100) NULL,
  created_at       DATETIME,
  Embedding        VECTOR(1536) NULL
)
-- No label column
```

### Migration 015

```python
def upgrade() -> None:
    op.execute(
        "ALTER TABLE Segments ADD label NVARCHAR(200) NULL"
    )

def downgrade() -> None:
    op.execute(
        "ALTER TABLE Segments DROP COLUMN label"
    )
```

Simple nullable column — no index needed (labels are only read, never filtered on).

### SQLAlchemy Model Change

Add to `services/shared/shared/db/models/segment.py`:
```python
label: Mapped[str | None] = mapped_column(String(200), nullable=True)
```

### Label Generation — Summarize Worker

**Correct placement**: The summarize worker (`services/workers/summarize/worker.py`) is the right place. It already:
- Has OpenAI API access configured
- Runs once per video after transcript is available
- Processes at video granularity (not per-segment)

**Change**: After `_create_artifact()` succeeds, add a `_generate_segment_labels()` step that:
1. Fetches all segments for the video from DB
2. For each segment, calls GPT with: `"Summarize this transcript excerpt in 5-10 words: {text}"`
3. Writes `label` back to the Segments row

**Cost estimate**:
- ~30 segments per video avg × 50 tokens per call = 1,500 tokens/video
- `gpt-4o-mini` at $0.15/1M input tokens
- 1,500 videos in library → ~2.25M tokens → **~$0.34 total for full library**
- Per new video: ~$0.0002 — negligible

**Alternative**: Embed worker (runs after summarize) is also viable since it already iterates segments for embedding. However, summarize worker has the OpenAI chat client already wired; embed worker uses the embeddings client. Keeping label generation in summarize keeps the workers' concerns cleaner.

### Backfill Strategy

**Recommendation: Forward-only for MVP**

- Segments ingested before migration 015 will have `label = NULL`
- `get_video` returns `"label": null` for those segments in the index — agents handle this gracefully
- A one-off backfill script can be added post-MVP: iterate `SELECT segment_id, text FROM Segments WHERE label IS NULL`, call GPT in batches, update rows

Backfill is ~$0.34 for all existing content — low cost but not urgent for MVP.

---

## 4. YouTube Search Strategy

### Decision: yt-dlp (No YouTube Data API)

**Constitution rule**: "MUST NOT require a YouTube Data API key (use yt-dlp)"

yt-dlp supports YouTube search natively via the `ytsearch{n}:` prefix:

```python
ydl_opts = {
    "skip_download": True,
    "quiet": True,
    "extract_flat": True,
    "ignoreerrors": True,
}
with yt_dlp.YoutubeDL(ydl_opts) as ydl:
    info = ydl.extract_info("ytsearch10:machine learning RAG", download=False)
# Returns: entries[] with id, title, channel, duration, url, thumbnail
```

**Implementation**: Add `search_videos(query, limit)` method to the existing `YouTubeService` class. The proxy support (`WebShare`) is already wired into `YouTubeService` — search calls will automatically route through the proxy.

**Result shape for `search_youtube` tool**:
```json
[
  {
    "youtube_video_id": "abc123",
    "title": "What is RAG?",
    "channel": "AI Engineer",
    "duration_seconds": 942,
    "url": "https://www.youtube.com/watch?v=abc123",
    "thumbnail_url": "https://img.youtube.com/vi/abc123/mqdefault.jpg"
  }
]
```

No new dependencies. No API key provisioning required.

---

## 5. Quality Commands

From `services/api/pyproject.toml`:

```bash
# Tests (from services/api/)
uv run pytest tests/ -m "unit"            # fast unit tests only
uv run pytest tests/ -m "integration"    # integration tests (mocked deps)
uv run pytest tests/                     # all non-live tests

# Lint
uv run ruff check src/

# Format check
uv run ruff format src/ --check

# Type-check
# Not configured — no mypy or pyright in pyproject.toml
```

Root repo:
```bash
npm run validate        # runs scripts/validate-local.ps1 (PowerShell)
npm run lint:frontend   # cd apps/web && npm run lint
npm run test:frontend   # cd apps/web && npm run test:run
```

Workers (e.g. summarize):
```bash
cd services/workers/summarize
uv run pytest tests/    # if tests exist
```

---

## 6. Open Questions Resolved

### OQ-1: YouTube API Key
**Resolved: Not needed.**
yt-dlp's `ytsearch:` prefix handles YouTube search without an API key. This also satisfies the constitution's hard rule ("MUST NOT require a YouTube Data API key"). No provisioning needed.

### OQ-2: Summarise Worker — Right Place for Labels?
**Resolved: Yes — summarize worker.**
Rationale:
- Already has OpenAI chat client configured
- Runs once per video, after transcript is available
- Fits naturally after the `_create_artifact()` step
- Embed worker is an alternative but uses the embeddings client, not the chat client

One consideration: if OpenAI is not configured (mock mode), labels won't be generated. The worker already handles this gracefully with mock summaries — labels can be skipped in mock mode.

### OQ-3: Port :8001 Conflict?
**Resolved: No conflict.**
Currently used ports:
- `8000` — FastAPI
- `3000` — Next.js frontend
- `8091` — transcribe worker
- `8092` — summarize worker
- `8093` — embed worker
- `8094` — relationships worker
- `1433` — SQL Server
- `10000-10002` — Azurite

**Port 8001 is free.** However, given the recommendation to keep the MCP server as a sidecar, port 8001 would be the MCP SSE endpoint, not a second port on the FastAPI process.

### OQ-4: Backfill Strategy
**Resolved: Forward-only is acceptable for MVP.**
- Cost is negligible (~$0.34 for full library)
- Historical segments return `null` labels gracefully
- Backfill script is straightforward post-MVP work
- No schema risk — column is nullable

---

## 7. Technical Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| **yt-dlp rate limiting in `search_youtube`** | Medium | Route through existing WebShare proxy (already configured in YouTubeService). Add exponential backoff. |
| **Segment label latency** | Low | ~30 LLM calls per video adds ~5-10s to summarize step. Acceptable. If needed, labels can be generated async/fire-and-forget. |
| **In-process MCP vs sidecar** | Low | Goals say "same process" but sidecar is simpler and already exists. Recommend sidecar pattern; note trade-off in requirements. |
| **Auth — no Auth0 for agent routes** | Medium | New `require_api_key` dependency needed. Must not bypass quota by default — agent routes operate at service-level, no per-user quota. |
| **`estimated_tokens` accuracy** | Low | Use `len(text) // 4` approximation (no tiktoken in API deps). Sufficient for context-window guidance; note it's an estimate. |
| **`ask` returning too much context** | Medium | CopilotService.query returns citations + answer text. Need to cap `max_evidence_segments` for agent use. Expose as parameter in `ask` tool. |
| **Null labels in `segment_index`** | Low | Historical segments have null labels. Agents should treat null as "label not available" — documented in tool schema. |
