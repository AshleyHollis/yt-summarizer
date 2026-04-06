# Goals: YT Summarizer Product Foundation

**Status**: Implementing
**Milestone**: M1
**Spec Phase**: execution
**Created**: 2025-12-13
**Updated**: 2026-04-04

---

## Problem Statement

YouTube contains vast amounts of valuable knowledge — tutorials, lectures, expert talks — but it is
not a knowledge tool. Content is ephemeral, unsearchable, and siloed. Users who want to *learn from*
and *reference* YouTube content have no structured way to:

- Ask questions across videos they have watched
- Find connections and progressions between related content
- Trust that AI-generated answers are grounded in actual content

**YT Summarizer** transforms selected YouTube videos and channels into a personal, searchable
knowledge library. The owner ingests videos by URL or channel; the system processes them into
searchable content with AI-generated summaries and semantic embeddings; an AI copilot answers
questions grounded in timestamped evidence drawn from the library.

**One-line description**: Ask questions, extract insights, and discover connections across your
YouTube library.

---

## Primary Actor

**Library Owner (Solo Power User)** — a single user who curates a personal YouTube library for
learning, reference, or research. Needs:

- **Accurate citations** — trust answers through timestamped evidence
- **Cross-content discovery** — find themes and connections across videos
- **Ingestion control** — decides what enters the library
- **Transparency** — understand what the system knows and does not know

---

## Success Criteria

| ID | Criterion | Target |
|----|-----------|--------|
| SC-001 | Ingest a video and view AI-generated summary | Within 5 min for a typical 10-min video |
| SC-002 | Ask a question and receive a cited answer | Within 3 seconds (excluding cold-start) |
| SC-003 | Library browse returns filtered results | Within 1 second across up to 1,500 videos |
| SC-004 | Every copilot answer includes timestamped citation | When video content exists for the query |
| SC-005 | Any failed ingestion job is visible with retry | One-click retry action from the UI |
| SC-006 | Active query scope always visible during copilot | Channels, time ranges, knowledge sources shown |
| SC-007 | Synthesized learning path matches human-verified order | Beginner → advanced for curated series |

---

## Scope

### In Scope

- Ingest individual YouTube videos by URL
- Batch-ingest all or selected videos from a channel
- Process each video: transcript → summary → embeddings → relationship extraction
- Browse the library with filters (channel, date range, tags/facets)
- Query the library via an AI copilot with scoped, citation-backed answers
- Discover related videos automatically through extracted relationships
- "Why this?" transparency panel for any recommended video
- Synthesize structured outputs (learning paths, watch lists) from library content
- Domain-agnostic — supports any topic

### Out of Scope

- **Copilot writes nothing** — strictly read-only, MUST NOT trigger ingestion or modify data
- **Web search off by default** — optional toggle; disabled unless explicitly enabled
- **No scale optimisation beyond hobby** — designed for ~1,500 videos and ~15,000 segments
- **No multi-tenant or multi-user architecture** — single-owner system
- Multi-user sharing, playlists, export, notifications, mobile app, podcast support, live transcription

---

## Milestones

| Milestone | Goal | Status |
|-----------|------|--------|
| M1 | Full product foundation — all 6 user stories, infra, observability | Implementing |

---

## Key Assumptions

- Frontend hosted on Azure Static Web Apps (Next.js)
- Backend runs as containerised Python services (FastAPI API + background workers)
- Single Azure SQL Database (serverless tier) — operational data, vectors, relationships
- Blob storage holds large artifacts; Azure Storage Queue drives background processing
- AI services: GPT-4o for chat and summarisation; text-embedding-3-small (1,536 dims) for embeddings
- Channel video lists fetched via yt-dlp (no YouTube Data API key required)
- Transcript source: YouTube auto-generated captions (primary); Whisper (fallback)
