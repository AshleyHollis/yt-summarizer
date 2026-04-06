# Requirements Checklist: YT Summarizer Product Foundation

**Status**: Implementing
**Milestone**: M1
**Spec Phase**: execution
**Created**: 2026-04-04
**Updated**: 2026-04-04

> One checkbox per functional requirement. Mark `[x]` when the requirement is fully implemented
> and verified. Tasks listed are from `.squad/specs/001-product-spec/tasks.md`.

---

## Ingestion & Processing

- [x] FR-001: System MUST accept a YouTube video URL and queue it for processing — T035, T036, T037
- [x] FR-002: System MUST process videos through four sequential stages (transcript → summarisation → chunking+embedding → relationship extraction) — T045, T046, T047, T048
- [x] FR-003: System MUST expose per-video job status at all times (pending, running with stage, succeeded, failed with error) — T040, T041, T042, T043, T050
- [x] FR-004: System MUST allow user to retry failed jobs from library UI — not via copilot — T039, T044, T055, T179, T180
- [x] FR-005: System MUST support batch ingestion from a channel (fetch list, up to 100 videos, per-video selection, "Ingest All", per-video status tracking) — T073–T095
- [x] FR-006: System MUST NOT duplicate content on reprocessing — all pipeline outputs MUST use upsert semantics — T036, T047, T048

## Library & Browsing

- [x] FR-007: System MUST provide library browse with filters: channel, date range, tags/facets — T056–T069
- [x] FR-008: System MUST display video detail pages with title, thumbnail, summary, full transcript, timestamped segments (clickable), and extracted metadata/tags — T052, T053, T054, T059, T071, T072
- [x] FR-009: System MUST paginate library results (10 per page, 50 maximum per request) — T043, T058, T070

## Copilot & Queries

- [x] FR-010: Copilot MUST be strictly read-only — T096, T105, T109
- [x] FR-011: Copilot MUST expose three independently togglable knowledge sources (Your Videos on, AI Knowledge on, Web Search off by default) — T096, T115, T119
- [x] FR-011a: When "Your Videos" off but "AI Knowledge" on, copilot answers from general knowledge with uncertainty indicator — T105, T106
- [x] FR-011b: When both "Your Videos" and "AI Knowledge" off, copilot returns error — T105
- [x] FR-012: Every copilot answer MUST include: short response, recommended video cards, timestamped evidence citations, optional follow-up buttons — T109, T118, T120, T121, T123, T124
- [x] FR-013: Copilot MUST display active query scope as visible chips including "Topics in Scope" panel — T112, T119, T122
- [x] FR-014: User MUST be able to adjust scope chips and immediately re-run query — T119, T125, T129
- [x] FR-015: When library has insufficient content, copilot MUST acknowledge and suggest ingesting more via library UI — T105, T127
- [x] FR-016: Copilot MAY generate structured outputs (learning paths, watch lists) from library content — T146–T160a
- [x] FR-028: Copilot conversation history MUST persist across page refreshes; cleared on logout — T118, T125

## Transparency & Provenance

- [x] FR-017: For any recommended video, user MUST be able to request "Why this?" explanation inline with no additional network request — T133, T135, T137, T138, T139, T141
- [x] FR-018: System MUST store relationships between videos with type, confidence, rationale, and evidence pointer — T018, T019, T048
- [x] FR-019: All derived artifacts SHOULD store traceability metadata (creation timestamp, model name, parameters) — T016, T046

## Error Handling & Resilience

- [x] FR-020: System MUST detect backend resuming from idle and respond with "Warming up…" messaging — T181a–T181l, T183
- [x] FR-020a: Health endpoint MUST report service status and readiness indicators — T027, T181a
- [x] FR-020b: UI MUST poll health endpoint on startup and display "Warming up" indicator when degraded — T181e, T181f, T181g, T181h
- [x] FR-020c: UI MUST auto-retry failed requests with exponential backoff while degraded — T032, T181i
- [x] FR-021: All background processing MUST retry transient failures with exponential backoff — T030, T176
- [x] FR-022: Jobs exceeding max retry count MUST be dead-lettered with full diagnostic context shown to user — T055
- [x] FR-026: System MUST validate fetched transcript content before storing — T175, T177
- [x] FR-027: System MUST detect rate-limit responses from external services and auto-retry — T176

## Observability

- [x] FR-023: System MUST propagate correlation ID from UI through every processing step — T024, T034a, T032, T187, T187a
- [x] FR-024: System MUST display job timelines in UI showing stage transitions and durations — T050, T185b
- [x] FR-025: All system components MUST emit structured JSON logs with timestamp, severity, correlation ID, component, message, entity IDs — T023, T188
