# Requirements Checklist: Webshare Rotating Proxy Pool (F005)

**Feature ID**: F005
**Status**: ~56% complete (15/27 tasks done)
**Last Updated**: 2026-04-04

---

## Functional Requirements

- [x] FR-001: Per-component feature flag independently enables/disables proxy routing; disabled = identical to current behaviour
- [x] FR-002: All YouTube-bound requests routed through Webshare rotating gateway when flag enabled; each request gets different residential IP
- [x] FR-003: Proxy routing implemented as shared service in common library; any component can use without duplicating logic
- [x] FR-004: yt-dlp built-in per-request delays preserved at defaults; not reduced or removed
- [ ] FR-005: Transcribe worker processes all queued jobs concurrently with no artificial cap when proxy enabled
- [x] FR-006: Existing retry-with-backoff applied to transient proxy failures; failed jobs follow dead-letter path after exhaustion
- [x] FR-007: Rate-limit responses (429) trigger retry; each retry automatically gets different residential IP
- [x] FR-008: Proxy request metrics tracked in DB: total requests, success/failure counts, estimated bandwidth per time period
- [ ] FR-009: Proxy service health exposed through health reporting: gateway status, success rate, bandwidth
- [x] FR-010: Webshare credentials stored in existing secrets management (Key Vault); never in config/env/source files
- [x] FR-011: Feature flag toggle takes effect within one poll cycle, no restart required
- [ ] FR-012: API service routes channel-browsing, video-listing, and video-metadata requests through proxy when flag enabled

---

## User Stories — Acceptance Criteria

### US-1: Proxy-Backed Transcription (✅ Complete)
- [x] AC-1.1: Proxy flag enabled + credentials → YouTube request through Webshare gateway with rotating IP
- [x] AC-1.2: Proxy flag disabled → native IP, identical to existing behaviour
- [x] AC-1.3: Gateway unreachable → retry with backoff → dead-letter on exhaustion; no silent loss

### US-2: Proxy-Backed Channel Browsing (🔄 In Progress)
- [ ] AC-2.1: Proxy flag enabled for API service → channel video listing through Webshare gateway
- [ ] AC-2.2: Proxy flag disabled for API service → native IP, identical to existing behaviour

### US-3: Concurrent Job Processing (⏳ Pending)
- [ ] AC-3.1: 10 jobs + proxy enabled → all 10 processed concurrently, each with rotating IP
- [ ] AC-3.2: Proxy disabled + multiple jobs → sequential processing, native IP
- [ ] AC-3.3: Concurrent job failure → retried without affecting other in-flight jobs

### US-4: Proxy Health & Cost Monitoring (⏳ Pending)
- [ ] AC-4.1: Health endpoint includes gateway status, request counts, bandwidth when proxy enabled
- [ ] AC-4.2: Gateway consecutive errors → reported as unhealthy in health endpoint
- [ ] AC-4.3: Completed jobs → cumulative bandwidth queryable by time period

### US-5: Shared Proxy Service (✅ Complete)
- [x] AC-5.1: New component imports shared proxy service → uses proxy routing without implementing own logic
- [x] AC-5.2: Two components with independent flags → each flag controls only its component

---

## Non-Functional Requirements

- [ ] NFR-1: ≥ 5× throughput improvement with proxy enabled (concurrent vs sequential)
- [ ] NFR-2: ≥ 80% reduction in HTTP 429 rate with proxy enabled
- [x] NFR-3: Zero jobs silently lost when gateway unavailable
- [ ] NFR-4: Health data freshness ≤ 30 seconds
- [x] NFR-5: Feature flag toggle latency ≤ 1 poll cycle (default 10 s)
- [ ] NFR-6: Bandwidth usage accuracy within 10% of Webshare reported figures

---

## Success Criteria

- [ ] SC-001: ≥ 5× throughput with proxy enabled
- [ ] SC-002: ≥ 80% reduction in 429 rate with proxy enabled
- [x] SC-003: Zero silent job loss on gateway failure
- [ ] SC-004: Health endpoint data ≤ 30 s stale
- [x] SC-005: Flag toggle reflected within one poll cycle
- [ ] SC-006: Bandwidth queryable by time period, accurate to ±10%
- [x] SC-007: Transcribe worker and API service independently controllable

---

## Quality Gates

- [x] Shared proxy service has unit tests (all 5 ProxyService methods)
- [x] Transcribe worker proxy injection has unit tests
- [ ] API service proxy injection has unit tests (T016–T018 pending)
- [ ] Concurrent BaseWorker has unit tests (T019–T022 pending)
- [ ] Health endpoints tested (T024–T025 pending)
- [ ] Regression run with `PROXY_ENABLED=false` (T027 pending)
- [ ] CI green on feature branch

---

## Notes

- Imported from `specs/005-webshare-proxy-pool/checklists/requirements.md` (2026-04-04)
- Core shared library (ProxyService, ProxyRequestLog, ProxySettings) is complete
- Transcribe worker integration is complete
- Remaining: API service proxy (T016–T018), concurrent processing (T019–T023), monitoring (T024–T025), polish (T026–T027)
