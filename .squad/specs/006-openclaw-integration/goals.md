# Goals: OpenClaw Integration

**Status**: Draft
**Milestone**: M6
**Spec Phase**: discovery
**Created**: 2026-04-06
**Updated**: 2026-04-06

---

## Problem Statement

YT Summarizer is a rich personal knowledge library — transcripts, summaries, semantic embeddings, and relationship graphs — but it's only accessible through a web UI. AI agents (OpenClaw, Claude Code, Copilot, Squad) have no programmatic way to query or extend this library.

This feature creates a machine-first integration surface: a set of purpose-built agent API routes inside the existing FastAPI service, wrapped by a thin MCP (Model Context Protocol) server. Any MCP-compatible AI agent can connect and gain on-demand access to Ashley's YouTube knowledge base — search it, query it via RAG, and trigger new ingestion.

---

## Architecture Decision

**Two-layer design:**

1. **Agent API Routes** — dedicated FastAPI router (e.g. `/agent/v1/...`) inside the existing API service. Returns flat, LLM-optimised JSON. Contains all business logic. HTTP-testable independently.

2. **MCP Server** — thin Python module inside the same FastAPI process (separate port, e.g. `:8001`). Pure protocol translation — no business logic. Wraps the agent API routes and exposes them as MCP tools.

Both layers live in `services/api/`, deployed together, started with the same process.

---

## MVP Tool Set (7 Tools)

| Tool | Description | Notes |
|------|-------------|-------|
| `search_library` | Search existing ingested transcripts by keyword/semantic query | Returns matched segments with context snippets + deeplinks |
| `search_youtube` | Search YouTube for videos matching a query | Returns candidate list (title, channel, duration, URL) — does NOT auto-ingest |
| `get_video` | Fetch video metadata, AI summary, and segment index | Segment index: `{ seq, start, end, label }` — no full text. Includes `estimated_tokens` |
| `get_segments` | Fetch full transcript text for a timestamp range | `get_segments(video_id, start_sec, end_sec)` — includes deeplink URLs |
| `ask` | Server-side RAG query across one or more transcripts | Returns cited, timestamped answer. Primary way to query content. |
| `ingest` | Submit a YouTube URL for async processing | Returns `job_id`. Async — must poll for completion. |
| `get_job_status` | Poll ingestion job by job_id | Returns status + progress. |

**Not in MVP scope:** `summarize` (topic-focused), `browse_library` (filter/list). These are NEXT tier.

---

## Success Criteria

| ID | Criterion |
|----|-----------|
| SC-1 | OpenClaw can call `search_library("what is RAG?")` and receive relevant segments with timestamps |
| SC-2 | OpenClaw can call `ask("How does yt-dlp handle rate limiting?")` and receive a cited answer |
| SC-3 | OpenClaw can submit a YouTube URL via `ingest`, poll `get_job_status`, and query the result |
| SC-4 | `get_video` returns a segment index with AI-generated labels — no full transcript text in the response |
| SC-5 | All agent API routes return flat LLM-optimised JSON with consistent error format |
| SC-6 | MCP server exposes all 7 tools and is connectable from any MCP client |
| SC-7 | Auth via API key (header or query param) — suitable for service-to-service over Tailscale |
| SC-8 | Large content responses include `estimated_tokens` field |
| SC-9 | Agent API routes are independently testable via HTTP (no MCP client needed) |

---

## Segment Index Design

The `get_video` tool returns a lightweight segment index, not full transcript text:

```json
{
  "video_id": "...",
  "title": "...",
  "summary": "...",
  "estimated_tokens": 18400,
  "segment_count": 42,
  "segments_index": [
    { "seq": 1, "start": 0.0, "end": 42.5, "label": "Intro: what is RAG?" },
    { "seq": 2, "start": 42.5, "end": 98.0, "label": "Embedding models overview" }
  ]
}
```

**`label` field:** AI-generated 5-10 word summary per segment. Produced during the ingestion pipeline (summarise worker). Requires:
- A new `label` column on the `Segments` table (DB migration)
- Summarise worker updated to generate labels per segment
- `get_video` to return the index shape above

**Full text access:** Use `get_segments(video_id, start_sec, end_sec)` for specific ranges. Use `ask(...)` for most Q&A use cases — avoids context window issues entirely.

---

## Auth Model

- **Mechanism:** API key via request header (`X-API-Key`) or query param
- **Scope:** Service-to-service (no user sessions, no Auth0 required)
- **Transport:** Tailscale — assumes VPN-level network security
- **MVP:** Single shared API key (env var). Multi-key/rotation is NEXT tier.

---

## Out of Scope (MVP)

- `summarize` tool (topic-focused summary generation)
- `browse_library` tool (filter/sort video list)
- Multi-tenant API keys or key rotation
- Streaming/partial results during ingestion
- Push notifications when ingestion completes (polling only)
- Any frontend changes — this is a backend + MCP surface only
- Deployment/CI changes (MCP server ships inside the existing API — no new infra)

---

## Constraints

- All business logic stays in the Agent API routes — MCP layer is pure protocol translation
- Agent API responses must be flat, LLM-optimised JSON (not UI-shaped)
- Consistent error format across all routes
- Token estimates on all large-content responses (`estimated_tokens` field)
- MCP server: same process as FastAPI, separate module, separate port (`:8001`)
- Implementation order: Agent API routes first (HTTP-testable), then MCP wrapper
- Schema migration required for `Segments.label` column

---

## Open Questions

1. **YouTube Data API key** — `search_youtube` requires a YouTube Data API v3 key. Is this already provisioned or does it need to be set up?
2. **Summarise worker labels** — The ingestion pipeline needs to generate segment labels. Is the summarise worker the right place, or should this be a post-processing step?
3. **MCP port** — `:8001` assumed for the MCP server. Any conflict with existing services?
4. **Existing ingested content** — Will a backfill job be needed to generate labels for already-ingested segments, or is forward-only acceptable?
