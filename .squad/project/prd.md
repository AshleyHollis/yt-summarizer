# YT Summarizer — Product Requirements Document

**Version**: 1.0
**Created**: 2026-04-04
**Status**: Active — M1 in progress

---

## Product Vision

YT Summarizer is a personal YouTube knowledge library. A solo power user ingests YouTube videos (by URL or channel), the system processes them into searchable content with AI-generated summaries and semantic embeddings, and an AI copilot answers questions grounded in timestamped evidence drawn from the library.

**One-line**: Ask questions, extract insights, and discover connections across your YouTube library.

---

## Primary Actor

**Library Owner (Solo Power User)** — a single user curating a personal YouTube library for learning, reference, or research. Needs accurate citations, cross-content discovery, ingestion control, and transparency.

---

## User Stories

| ID | Story | Priority | Status |
|----|-------|----------|--------|
| US1 | As an owner, I want to submit a YouTube URL and watch it progress through processing, so that I can view the AI-generated summary, transcript, and key segments when complete | P1 🎯 MVP | Implementing |
| US2 | As an owner, I want to provide a channel URL, browse available videos, and start a batch ingestion | P2 | Implementing |
| US3 | As an owner, I want to browse my library with filters (channel, date range, tags), so I can find videos I've ingested | P1 🎯 MVP | Implementing |
| US4 | As an owner, I want to ask natural language questions about my library and receive cited, timestamped answers | P1 🎯 MVP | Implementing |
| US5 | As an owner, I want to discover related videos automatically and understand WHY they are related | P2 | Implementing |
| US6 | As an owner, I want to see a synthesized learning path across videos | P3 | Not started |

---

## Success Criteria

| ID | Criterion | Target |
|----|-----------|--------|
| SC-001 | Ingest a video and view AI-generated summary | Within 5 min for a typical 10-min video |
| SC-002 | Ask a question and receive a cited answer | Within 3 seconds (excluding cold-start) |
| SC-003 | Library browse returns filtered results | Within 1 second across up to 1,500 videos |
| SC-004 | Every copilot answer includes timestamped citation | When video content exists for the query |
| SC-005 | Any failed ingestion job is visible with retry | One-click retry from the UI |
| SC-006 | Active query scope always visible during copilot session | Channels, time ranges, sources shown |
| SC-007 | Synthesized learning path matches human-verified order | Beginner → advanced for curated series |

---

## Scope

### In Scope
- Ingest individual YouTube videos by URL
- Batch-ingest all or selected videos from a channel
- Process each video: transcript → summary → embeddings → relationship extraction
- Browse the library with filters
- Query the library via AI copilot with scoped, citation-backed answers
- Discover related videos through extracted relationships
- "Why this?" transparency panel for any recommended video
- Synthesize structured outputs (learning paths, watch lists)

### Out of Scope
- Multi-user, multi-tenant, sharing, playlists, export
- Copilot writing or modifying data (read-only always)
- Web search (optional toggle only, disabled by default)
- Scale beyond ~1,500 videos / ~15,000 segments
- Mobile app, notifications, podcast support, live transcription

---

## Milestones

| Milestone | Goal | Status |
|-----------|------|--------|
| M1 | Full product foundation — all 6 user stories, infra, observability | In progress |

---

## Features

| ID | Feature | Milestone | Status |
|----|---------|-----------|--------|
| F001 | Product Foundation (US1–US6, core stack) | M1 | Implementing |
| F002 | Azure CI/CD Pipeline | M1 | Implementing |
| F003 | Preview DNS + Cloudflare | M1 | Implementing |
| F004 | Auth0 UI Integration | M1 | Implementing |
| F005 | Webshare Proxy Pool | M1 | Implementing |
