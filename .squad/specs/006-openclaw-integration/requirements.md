# Requirements: OpenClaw Integration

**Status**: Draft
**Milestone**: M6
**Spec Phase**: requirements
**Created**: 2026-04-06
**Updated**: 2026-04-06

---

## 1. User Stories

> The "user" in these stories is an AI agent (OpenClaw, Claude Code, GitHub Copilot, or any MCP-compatible client).

| ID | Story | Priority | Acceptance Criteria |
|----|-------|----------|---------------------|
| US1 | As an AI agent, I want to search the library using a natural language query so that I can find relevant transcript segments with timestamps and deeplink URLs. | High | AC1: `search_library("what is RAG?")` returns ≥1 result with `video_id`, `title`, `snippet`, `start_time`, `youtube_url`, and `score` fields. AC2: Results are ordered by semantic relevance. AC3: Response includes `estimated_tokens` field. |
| US2 | As an AI agent, I want to search YouTube for new videos matching a query so that I can discover candidate content before deciding whether to ingest it. | High | AC1: `search_youtube("yt-dlp rate limiting")` returns a list with `youtube_video_id`, `title`, `channel`, `duration_seconds`, and `url` for each result. AC2: No YouTube Data API key is required. AC3: Returns up to `limit` results (default 10, max 50). |
| US3 | As an AI agent, I want to get video metadata plus a segment index so that I can understand the structure of a video without consuming the full transcript. | High | AC1: `get_video(video_id)` returns `title`, `summary`, `segment_count`, `estimated_tokens`, and `segments_index` (array of `{ seq, start, end, label }`). AC2: `label` is an AI-generated 5–10 word description of the segment. AC3: Full transcript text is NOT included in this response. |
| US4 | As an AI agent, I want to fetch full transcript text for a specific timestamp range so that I can read only the section I need without loading the whole transcript. | High | AC1: `get_segments(video_id, start_sec=60, end_sec=180)` returns only segments whose time range overlaps `[start_sec, end_sec]`. AC2: Each segment includes `text`, `start_time`, `end_time`, and `youtube_url`. AC3: Response includes `estimated_tokens`. |
| US5 | As an AI agent, I want to ask a natural language question across all ingested transcripts and receive a cited, timestamped answer so that I get grounded answers without manually searching. | High | AC1: `ask("How does yt-dlp handle rate limiting?")` returns an `answer` string and a non-empty `citations` list. AC2: Each citation includes `video_title`, `start_time`, `youtube_url`, and `snippet`. AC3: Response completes in under 15 seconds for typical queries. |
| US6 | As an AI agent, I want to submit a YouTube URL for ingestion and poll for completion so that I can add new content to the library programmatically. | High | AC1: `ingest("https://www.youtube.com/watch?v=...")` returns a `job_id` immediately. AC2: `get_job_status(job_id)` returns `status` (`pending` / `processing` / `completed` / `failed`) and `progress_pct` (0–100). AC3: Ingestion is fully async — the submit call returns in under 2 seconds. |
| US7 | As an AI agent, I want to authenticate via an API key header so that I can make service-to-service calls without user sessions or browser redirects. | High | AC1: All agent API routes accept `X-API-Key` header and reject requests without it with HTTP 401. AC2: A valid key allows access to all agent endpoints without Auth0 tokens. AC3: The MCP server transparently forwards the key on every call to the agent API. |

---

## 2. Functional Requirements

| ID | Requirement | Priority | Notes |
|----|-------------|----------|-------|
| FR-1 | `POST /api/v1/agent/search/semantic` performs vector similarity search across all ingested transcript segments, falling back to full-text search when embeddings are unavailable. | High | Reuses `SearchService.search_segments` + `LLMService.get_embedding`. |
| FR-2 | `POST /api/v1/agent/search/semantic` returns results shaped as flat LLM-optimised JSON: `{ results: [{ video_id, title, snippet, start_time, end_time, youtube_url, score }], total, estimated_tokens }`. | High | No nested UI-shaped wrappers. `score` is cosine distance (lower = more similar). |
| FR-3 | `GET /api/v1/agent/youtube/search?q=...&limit=10` searches YouTube using yt-dlp's `ytsearch{n}:` prefix. No YouTube Data API key is required. | High | Constitution hard rule: MUST NOT require YouTube Data API key. |
| FR-4 | `GET /api/v1/agent/youtube/search` routes search requests through the existing `YouTubeService` proxy (WebShare) to mitigate rate limiting. | Medium | `YouTubeService.search_videos(query, limit)` method to be added. |
| FR-5 | `GET /api/v1/agent/youtube/search` returns: `{ results: [{ youtube_video_id, title, channel, duration_seconds, url, thumbnail_url }], total }`. | High | Does NOT auto-ingest. Returns candidates only. |
| FR-6 | `GET /api/v1/agent/videos/{id}` returns an agent-optimised video detail response: `{ video_id, youtube_video_id, title, channel_name, youtube_url, duration, summary, processing_status, segment_count, estimated_tokens, segments_index: [{ seq, start, end, label }] }`. | High | `label` may be `null` for segments ingested before migration 015. |
| FR-7 | `GET /api/v1/agent/videos/{id}` MUST NOT include full transcript text. Full text is available only via `GET /api/v1/agent/videos/{id}/segments`. | High | Context window discipline: force agents to use `get_segments` for full text. |
| FR-8 | `GET /api/v1/agent/videos/{id}/segments?start_sec=X&end_sec=Y` returns all segments whose time range overlaps `[start_sec, end_sec]`, inclusive. If neither param is provided, returns all segments for the video. | High | Range filter: segment overlaps window if `start_time < end_sec AND end_time > start_sec`. |
| FR-9 | `GET /api/v1/agent/videos/{id}/segments` response includes `estimated_tokens` computed as `total_text_length // 4`. | Medium | Approximation only — no tiktoken dependency. Accuracy target: within ±20% of `cl100k_base` tokeniser count. |
| FR-10 | `POST /api/v1/agent/ask` accepts `{ query, scope?, max_evidence_segments? }` and returns `{ answer, citations: [{ video_id, video_title, start_time, end_time, youtube_url, snippet, confidence }], estimated_tokens }`. | High | Delegates to existing `CopilotService.query`. Flattens `CopilotQueryResponse` to remove UI-only fields. |
| FR-11 | `POST /api/v1/agent/ask` caps evidence at `max_evidence_segments` (default 5, max 20) to prevent context overflow. | Medium | Prevents unbounded token consumption on `ask` calls. |
| FR-12 | `POST /api/v1/agent/videos` (ingest) accepts `{ url: string }` and returns `{ job_id, video_id, status: "pending" }` immediately. All ingestion is async via Azure Storage Queue. | High | Reuses `VideoService.submit_video`. Constitution: MUST queue all ingestion. |
| FR-13 | `GET /api/v1/agent/jobs/{job_id}` returns `{ job_id, video_id, status, progress_pct, stages: [{ name, status }], created_at, updated_at }`. | High | Reuses `JobService.get_video_jobs_progress`. Flattens to LLM-optimised shape. |
| FR-14 | All five new agent routes (`search/semantic`, `youtube/search`, `videos/{id}`, `videos/{id}/segments`, `ask`) are protected by `require_api_key` dependency that checks the `X-API-Key` header. | High | New FastAPI dependency, separate from Auth0 `require_auth`. Returns 401 with consistent error body on missing/invalid key. |
| FR-15 | `ingest` and `get_job_status` agent routes also require API key auth. | High | All 7 MCP tools must operate with API key only — no Auth0 token required. |
| FR-16 | All agent API routes return errors in a consistent format: `{ "error": { "code": string, "message": string, "details"?: any } }`. | High | Consistent across all new routes. Covers 400, 401, 404, 422, 500 cases. |
| FR-17 | The summarize worker (`services/workers/summarize/worker.py`) generates a segment label for each segment after `_create_artifact()` succeeds, by calling GPT with: `"Summarize this transcript excerpt in 5-10 words: {text}"`. | High | Labels are stored in the new `Segments.label` column. Skipped in mock/no-OpenAI mode. |
| FR-18 | DB migration 015 adds `label NVARCHAR(200) NULL` to the `Segments` table. The SQLAlchemy `Segment` model in `services/shared` is updated to include `label: Mapped[str | None]`. | High | Nullable column — no default, no index. Forward-only for MVP; historical segments return `null` labels. |
| FR-19 | The MCP server (`services/mcp/yt-summarizer-mcp/server.py`) is updated to expose all 7 tools by wrapping the `/api/v1/agent/` routes. Existing tools (`submit_video`, `get_video`, `get_video_progress`, `search_library`, `get_library_stats`, `get_transcript`, `get_summary`) are replaced by the 7 MVP tools. | High | Sidecar pattern retained. MCP server calls API over HTTP. No business logic in MCP layer. |
| FR-20 | The MCP server tool `search_library` wraps `POST /api/v1/agent/search/semantic`. | High | Replaces the current `GET /api/v1/library/videos?search=` call. |
| FR-21 | The MCP server tool `search_youtube` wraps `GET /api/v1/agent/youtube/search`. | High | New tool. |
| FR-22 | The MCP server tool `get_video` wraps `GET /api/v1/agent/videos/{id}`. | High | Replaces `GET /api/v1/videos/{video_id}`. |
| FR-23 | The MCP server tool `get_segments` wraps `GET /api/v1/agent/videos/{id}/segments?start_sec=X&end_sec=Y`. | High | New tool. |
| FR-24 | The MCP server tool `ask` wraps `POST /api/v1/agent/ask`. | High | New tool. |
| FR-25 | The MCP server tool `ingest` wraps `POST /api/v1/agent/videos`. | High | Replaces `submit_video`. |
| FR-26 | The MCP server tool `get_job_status` wraps `GET /api/v1/agent/jobs/{job_id}`. | High | Replaces `get_video_progress`. |
| FR-27 | All large-content responses (`get_video`, `get_segments`, `ask`, `search_library`) include a top-level `estimated_tokens: int` field computed as `total_text_length // 4`. | Medium | SC-8 traceability. |
| FR-28 | All new agent API routes are registered under a dedicated FastAPI router with prefix `/api/v1/agent` and tag `Agent`. | Medium | SC-9: enables independent HTTP testing without MCP client. |

---

## 3. Non-Functional Requirements

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-1 | `POST /api/v1/agent/search/semantic` p95 response time (with embeddings) | < 3 seconds |
| NFR-2 | `POST /api/v1/agent/ask` p95 response time (end-to-end including LLM call) | < 15 seconds |
| NFR-3 | `GET /api/v1/agent/videos/{id}` p95 response time | < 1 second |
| NFR-4 | `GET /api/v1/agent/videos/{id}/segments` p95 response time | < 1 second |
| NFR-5 | `estimated_tokens` accuracy vs `cl100k_base` tokeniser | within ±20% |
| NFR-6 | Error response format consistency | 100% of agent routes return `{ "error": { "code", "message" } }` on error |
| NFR-7 | `GET /api/v1/agent/youtube/search` p95 response time (via proxy) | < 10 seconds |
| NFR-8 | Segment label generation latency per video (summarize worker) | < 15 seconds added to summarize step (~30 segments × 0.5s/call) |
| NFR-9 | API key auth overhead | < 5ms per request (in-memory key comparison) |
| NFR-10 | MCP server HTTP client timeout | 30 seconds (already configured); 60 seconds for `ask` calls |

---

## 4. API Contracts

> All agent routes use prefix `/api/v1/agent/`. All require `X-API-Key` header.
> All error responses use: `{ "error": { "code": string, "message": string, "details"?: any } }`

---

### POST /api/v1/agent/search/semantic

Search ingested transcript segments by natural language query using vector similarity.

**Auth**: `X-API-Key` header required

**Request**:
```json
{
  "query": "how does yt-dlp handle rate limiting",
  "limit": 10
}
```

| Field | Type | Required | Default | Notes |
|-------|------|----------|---------|-------|
| `query` | string | Yes | — | Natural language search query |
| `limit` | int | No | 10 | 1–50 |

**Response 200**:
```json
{
  "results": [
    {
      "video_id": "uuid",
      "youtube_video_id": "abc123",
      "title": "Deep Dive into yt-dlp",
      "channel_name": "AI Engineer",
      "snippet": "yt-dlp implements exponential backoff when...",
      "start_time": 142.5,
      "end_time": 178.0,
      "youtube_url": "https://www.youtube.com/watch?v=abc123&t=142",
      "score": 0.18
    }
  ],
  "total": 1,
  "estimated_tokens": 420
}
```

**Errors**: 400 (empty query), 401 (missing/invalid API key), 500 (search failure)

---

### GET /api/v1/agent/youtube/search

Search YouTube for videos matching a query. Uses yt-dlp — no YouTube Data API key required.

**Auth**: `X-API-Key` header required

**Query Parameters**:

| Param | Type | Required | Default | Notes |
|-------|------|----------|---------|-------|
| `q` | string | Yes | — | Search query |
| `limit` | int | No | 10 | 1–50 |

**Response 200**:
```json
{
  "results": [
    {
      "youtube_video_id": "abc123",
      "title": "What is RAG?",
      "channel": "AI Engineer",
      "duration_seconds": 942,
      "url": "https://www.youtube.com/watch?v=abc123",
      "thumbnail_url": "https://img.youtube.com/vi/abc123/mqdefault.jpg"
    }
  ],
  "total": 10
}
```

**Errors**: 400 (missing `q`), 401 (missing/invalid API key), 502 (yt-dlp upstream error), 504 (yt-dlp timeout)

---

### GET /api/v1/agent/videos/{id}

Fetch agent-optimised video metadata with segment index. Does NOT include full transcript text.

**Auth**: `X-API-Key` header required

**Path Parameters**: `id` — internal video UUID

**Response 200**:
```json
{
  "video_id": "uuid",
  "youtube_video_id": "abc123",
  "title": "Deep Dive into yt-dlp",
  "channel_name": "AI Engineer",
  "youtube_url": "https://www.youtube.com/watch?v=abc123",
  "duration": 3720,
  "processing_status": "completed",
  "summary": "This video covers yt-dlp's internals...",
  "segment_count": 42,
  "estimated_tokens": 18400,
  "segments_index": [
    { "seq": 1, "start": 0.0, "end": 42.5, "label": "Intro: what is yt-dlp?" },
    { "seq": 2, "start": 42.5, "end": 98.0, "label": "Rate limiting and backoff" }
  ]
}
```

Notes:
- `label` is `null` for segments ingested before migration 015 (forward-only labelling for MVP)
- `estimated_tokens` approximates the full transcript token count (not just the index)
- `summary` is `null` if summarize step has not completed

**Errors**: 401, 404 (video not found), 500

---

### GET /api/v1/agent/videos/{id}/segments

Fetch full transcript text for a timestamp range (or all segments if no range given).

**Auth**: `X-API-Key` header required

**Path Parameters**: `id` — internal video UUID

**Query Parameters**:

| Param | Type | Required | Default | Notes |
|-------|------|----------|---------|-------|
| `start_sec` | float | No | — | Range start in seconds (inclusive) |
| `end_sec` | float | No | — | Range end in seconds (exclusive) |

Overlap logic: a segment is included if `segment.start_time < end_sec AND segment.end_time > start_sec`.
If neither param is provided, all segments are returned.

**Response 200**:
```json
{
  "video_id": "uuid",
  "youtube_video_id": "abc123",
  "title": "Deep Dive into yt-dlp",
  "segments": [
    {
      "seq": 2,
      "start_time": 42.5,
      "end_time": 98.0,
      "text": "yt-dlp implements exponential backoff when it detects rate limiting...",
      "youtube_url": "https://www.youtube.com/watch?v=abc123&t=42"
    }
  ],
  "total": 1,
  "estimated_tokens": 180
}
```

**Errors**: 400 (invalid range — `start_sec >= end_sec`), 401, 404, 500

---

### POST /api/v1/agent/ask

Execute a RAG query across ingested transcripts. Returns a cited, grounded answer.

**Auth**: `X-API-Key` header required

**Request**:
```json
{
  "query": "How does yt-dlp handle rate limiting?",
  "scope": {
    "video_ids": ["uuid1", "uuid2"]
  },
  "max_evidence_segments": 5
}
```

| Field | Type | Required | Default | Notes |
|-------|------|----------|---------|-------|
| `query` | string | Yes | — | Natural language question |
| `scope` | object | No | null | Optional scope filter: `{ video_ids?, channel_ids?, facets? }` |
| `max_evidence_segments` | int | No | 5 | 1–20 — caps retrieved evidence to control token usage |

**Response 200**:
```json
{
  "answer": "yt-dlp implements exponential backoff when rate-limited, sleeping between retries...",
  "citations": [
    {
      "video_id": "uuid",
      "youtube_video_id": "abc123",
      "video_title": "Deep Dive into yt-dlp",
      "start_time": 142.5,
      "end_time": 178.0,
      "youtube_url": "https://www.youtube.com/watch?v=abc123&t=142",
      "snippet": "yt-dlp implements exponential backoff...",
      "confidence": 0.87
    }
  ],
  "estimated_tokens": 820
}
```

**Errors**: 400 (empty query), 401, 500 (LLM error), 503 (DB warming up — retry after 5s)

---

### POST /api/v1/agent/videos  *(ingest — unchanged route, new auth path)*

Submit a YouTube URL for async ingestion. Returns immediately with `job_id`.

**Auth**: `X-API-Key` header required (no Auth0 token needed)

**Request**:
```json
{ "url": "https://www.youtube.com/watch?v=abc123" }
```

**Response 202**:
```json
{
  "job_id": "uuid",
  "video_id": "uuid",
  "status": "pending"
}
```

**Errors**: 400 (invalid URL or already ingested), 401, 500

---

### GET /api/v1/agent/jobs/{job_id}

Poll ingestion job status by `job_id`.

**Auth**: `X-API-Key` header required

**Response 200**:
```json
{
  "job_id": "uuid",
  "video_id": "uuid",
  "status": "processing",
  "progress_pct": 45,
  "stages": [
    { "name": "transcribe", "status": "completed" },
    { "name": "summarize", "status": "processing" },
    { "name": "embed", "status": "pending" },
    { "name": "relationships", "status": "pending" }
  ],
  "created_at": "2026-04-06T10:00:00Z",
  "updated_at": "2026-04-06T10:02:15Z"
}
```

**Errors**: 401, 404 (job not found), 500

---

## 5. Out of Scope

The following are explicitly **not** part of this feature (MVP):

| Item | Rationale |
|------|-----------|
| `summarize` MCP tool (topic-focused summary) | Next tier — not needed for core agent use cases |
| `browse_library` MCP tool (filter/sort video list) | Next tier — `search_library` covers discovery needs |
| Multi-key API key management or key rotation | Next tier — single shared key sufficient for hobby-scale |
| Streaming/partial results during ingestion | Next tier — polling is sufficient for MVP |
| Push notifications on ingestion completion | Next tier — polling only |
| Any frontend (Next.js) changes | This is backend + MCP surface only |
| New deployment infrastructure | MCP sidecar registers in AppHost.cs — no new Azure resources |
| Backfill of segment labels for existing content | Forward-only for MVP. Backfill script is post-MVP work (~$0.34 total cost) |
| Per-user quotas or rate limiting on agent routes | Next tier — single API key, service-level access |
| Auth0 integration for agent routes | Agent routes are service-to-service only |

---

## 6. Glossary

| Term | Definition |
|------|-----------|
| **MCP** | Model Context Protocol — Anthropic's open standard for exposing tools to AI agents. The MCP server exposes "tools" that agents can call by name with typed parameters. |
| **RAG** | Retrieval-Augmented Generation — a technique where relevant text chunks are retrieved from a knowledge base (by semantic search) and injected into an LLM prompt as context before generating an answer. |
| **Segment index** | A lightweight list of all transcript segments for a video, containing only `{ seq, start, end, label }` — no full text. Allows an agent to understand video structure before deciding which segments to fetch. |
| **Agent API** | The dedicated FastAPI router under `/api/v1/agent/` providing flat, LLM-optimised JSON endpoints for AI agent consumption. Separate from the UI-facing API routes. |
| **Sidecar** | Deployment pattern where the MCP server is a separate process that calls the main API over HTTP. It handles only protocol translation (HTTP ↔ MCP) with no business logic of its own. |
| **estimated_tokens** | An approximate token count for a response's text content, computed as `total_text_length // 4`. Used by agents to decide whether content fits in their context window. Accuracy target: within ±20% of `cl100k_base` actual count. |
| **yt-dlp** | A command-line tool for downloading YouTube videos and extracting metadata. Used here via its `ytsearch{n}:` prefix to search YouTube without requiring a YouTube Data API key. |

---

## 7. Dependencies

| Dependency | Type | Notes |
|------------|------|-------|
| **DB migration 015** — `Segments.label NVARCHAR(200) NULL` | Schema | Must run before summarize worker changes are deployed. Forward-only for MVP. |
| **SQLAlchemy Segment model update** — add `label: Mapped[str \| None]` | Code | In `services/shared/shared/db/models/segment.py`. Required before API or worker reads `label`. |
| **Summarize worker change** — `_generate_segment_labels()` step | Code | Requires OpenAI chat client (already wired). No-ops in mock mode. |
| **`YouTubeService.search_videos(query, limit)`** — new method | Code | Added to `services/api/src/api/services/youtube_service.py`. Uses existing proxy config. |
| **`require_api_key` FastAPI dependency** | Code | New dependency in `services/api/src/api/dependencies/`. Reads `AGENT_API_KEY` env var. |
| **Agent router** — `services/api/src/api/routes/agent.py` | Code | New FastAPI router registered in `main.py` under `/api/v1/agent`. |
| **MCP server update** — replace 7 existing tools with 7 MVP tools | Code | `services/mcp/yt-summarizer-mcp/server.py`. No library changes needed (`mcp>=1.0.0` already installed). |
| **AppHost.cs registration** — MCP sidecar as named resource | Config | `services/aspire/AppHost/AppHost.cs`. Register MCP server process alongside workers. |
| **yt-dlp** | Runtime dep | Already a dependency of `YouTubeService`. No new package required. |
| **No new Azure infrastructure** | — | MCP sidecar is a process, not a new service. No Terraform changes. |

---

## 8. Success Criteria Traceability

All 9 success criteria from goals.md are traced to requirements:

| SC ID | Criterion | Traced To |
|-------|-----------|-----------|
| SC-1 | OpenClaw can call `search_library("what is RAG?")` and receive relevant segments with timestamps | FR-1, FR-2, US1 |
| SC-2 | OpenClaw can call `ask("How does yt-dlp handle rate limiting?")` and receive a cited answer | FR-10, FR-11, US5 |
| SC-3 | OpenClaw can submit a URL via `ingest`, poll `get_job_status`, and query the result | FR-12, FR-13, US6 |
| SC-4 | `get_video` returns a segment index with AI-generated labels — no full transcript text | FR-6, FR-7, FR-17, FR-18, US3 |
| SC-5 | All agent API routes return flat LLM-optimised JSON with consistent error format | FR-2, FR-5, FR-16, FR-28 |
| SC-6 | MCP server exposes all 7 tools and is connectable from any MCP client | FR-19 through FR-26 |
| SC-7 | Auth via API key (header or query param) — suitable for service-to-service over Tailscale | FR-14, FR-15, US7 |
| SC-8 | Large content responses include `estimated_tokens` field | FR-9, FR-27, US1 AC3, US4 AC3 |
| SC-9 | Agent API routes are independently testable via HTTP (no MCP client needed) | FR-28 — `/api/v1/agent/` routes are plain HTTP endpoints |
