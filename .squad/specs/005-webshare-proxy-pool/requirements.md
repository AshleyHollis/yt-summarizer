# Requirements: Webshare Rotating Proxy Pool

**Feature ID**: F005
**Imported**: 2026-04-04 from `specs/005-webshare-proxy-pool/spec.md`

---

## Goal

Route all YouTube-bound requests through Webshare rotating residential proxies to eliminate IP-based rate limiting and enable concurrent job processing across the transcribe worker and API service, using a shared proxy library with per-component feature flags.

---

## User Stories

### US-1: Proxy-Backed Transcription
**As an** operator
**I want** the transcribe worker to route YouTube requests through the Webshare rotating proxy gateway
**So that** transcript fetching is resilient to IP-based rate limiting

**Priority**: P1

**Acceptance Criteria:**
- [x] AC-1.1: Given proxy flag enabled and credentials configured, when a transcription job is processed, then the YouTube request is sent through the Webshare rotating proxy gateway and a different residential IP is used for each new connection
- [x] AC-1.2: Given proxy flag disabled, when a transcription job is processed, then the request uses the worker's native IP — identical to existing behaviour with no proxy involvement
- [x] AC-1.3: Given flag enabled but gateway unreachable, when a transcription job is received, then the system retries with backoff; after exhausting retries the job follows the existing dead-letter path and no jobs are silently lost

---

### US-2: Proxy-Backed Channel Browsing
**As an** operator
**I want** the API service to route YouTube channel-browsing and video-listing requests through the Webshare rotating proxy gateway
**So that** channel imports are resilient to IP-based rate limiting and the full ingestion pipeline is protected end-to-end

**Priority**: P1

**Acceptance Criteria:**
- [ ] AC-2.1: Given proxy flag enabled for the API service, when a channel video listing is requested, then the YouTube request is sent through the Webshare rotating proxy gateway
- [ ] AC-2.2: Given proxy flag disabled for the API service, when a channel video listing is requested, then the request uses the API server's native IP — identical to existing behaviour

---

### US-3: Unlimited Concurrent Job Processing
**As an** operator
**I want** the transcribe worker to process all available queued jobs concurrently when the proxy is enabled
**So that** overall transcript throughput scales with job volume rather than being bottlenecked by sequential processing

**Priority**: P1

**Acceptance Criteria:**
- [ ] AC-3.1: Given proxy enabled and 10 jobs queued, when the worker picks up the batch, then all 10 jobs are processed concurrently, each routed through the proxy gateway and receiving a different residential IP automatically
- [ ] AC-3.2: Given proxy disabled and multiple jobs queued, when the worker picks up the batch, then jobs are processed sequentially using the worker's native IP — preserving existing behaviour
- [ ] AC-3.3: Given a concurrent job fails due to a transient proxy error, when the failure is detected, then that job is retried automatically per the existing retry strategy without affecting any other in-flight jobs

---

### US-4: Proxy Health and Cost Monitoring
**As an** operator
**I want** visibility into proxy gateway health (connectivity, request success rate, bandwidth consumption)
**So that** I can monitor costs and detect failures before they become silent outages

**Priority**: P2

**Acceptance Criteria:**
- [ ] AC-4.1: Given proxy enabled and requests have been processed, when the health endpoint is queried, then the response includes gateway connectivity status, total requests routed, success/failure counts, and estimated bandwidth consumed
- [ ] AC-4.2: Given the proxy gateway returns consecutive connection errors, when the failure threshold is reached, then the gateway is reported as unhealthy in the health endpoint
- [ ] AC-4.3: Given multiple transcription jobs have completed through the proxy, when an operator queries bandwidth metrics, then cumulative bandwidth usage is available broken down by time period

---

### US-5: Shared Proxy Service
**As a** developer
**I want** the proxy routing capability implemented as a shared service in the common library
**So that** any component that communicates with YouTube can use it without duplicating proxy logic

**Priority**: P2

**Acceptance Criteria:**
- [x] AC-5.1: Given the proxy service is available in the shared library, when a new component imports it, then that component can configure and use proxy routing without implementing its own gateway URL construction, credential handling, or request logging
- [x] AC-5.2: Given two components both use the shared proxy service, when each component sets its own feature flag independently, then each component's proxy behaviour is controlled solely by its own flag setting and does not affect the other

---

## Functional Requirements

| ID | Requirement | Priority | Verify |
|----|------------|----------|--------|
| FR-001 | System MUST provide a per-component feature flag that independently enables/disables Webshare proxy routing for the transcribe worker and API service. When disabled, component MUST behave identically to current behaviour. | Must | `PROXY_ENABLED=false` → no proxy URL in yt-dlp opts |
| FR-002 | System MUST route all YouTube-bound requests through Webshare rotating residential proxy gateway when component's flag is enabled. Each request MUST automatically receive a different residential IP. | Must | Verify yt-dlp opts contain proxy URL when enabled |
| FR-003 | System MUST implement proxy routing as a shared service in the common library, usable by any component without duplicating proxy logic. | Must | `from shared.proxy import ProxyService` in any consumer |
| FR-004 | System MUST preserve yt-dlp built-in per-request delays at their default values regardless of proxy status. Delays MUST NOT be reduced or removed. | Must | Assert `sleep_interval_subtitles` and `sleep_interval_requests` unchanged |
| FR-005 | When proxy flag is enabled, transcribe worker MUST process all available queued jobs concurrently with no artificial concurrency cap. | Must | Queue 10 jobs → verify all begin processing without sequential wait |
| FR-006 | System MUST apply existing retry-with-backoff logic to handle transient proxy failures. After exhausting retries, failed jobs MUST follow existing dead-letter path — no silent loss. | Must | Simulate gateway unavailable → verify DLQ receipt |
| FR-007 | When a YouTube request through the proxy returns a rate-limit response, system MUST retry. Each retry MUST automatically receive a different residential IP from the rotating pool. | Must | Inject 429 response → verify retry with new proxy connection |
| FR-008 | System MUST track proxy request metrics in the existing database: total requests routed, success/failure counts, estimated bandwidth per time period. | Must | Query `proxy_request_logs` after batch → assert rows present |
| FR-009 | System MUST expose proxy service health through existing health reporting mechanism: gateway connectivity status, request success rate, bandwidth consumption. | Must | `GET /debug/connectivity` → assert `proxy` key present |
| FR-010 | System MUST store Webshare gateway credentials using the project's existing secrets management infrastructure. Credentials MUST NOT appear in config files, env files, or source code. | Must | Grep source for credentials → zero matches |
| FR-011 | Feature flag toggle MUST take effect without a worker or service restart, reflected within one polling cycle. | Must | Toggle `PROXY_ENABLED` → verify change within 10 s |
| FR-012 | API service MUST route YouTube channel-browsing, video-listing, and video-metadata requests through the shared proxy service when API service's feature flag is enabled. | Must | API call with `PROXY_ENABLED=true` → proxy URL in yt-dlp opts |

---

## Non-Functional Requirements

| ID | Requirement | Metric | Target |
|----|------------|--------|--------|
| NFR-1 | Throughput improvement with proxy | Concurrent vs sequential jobs under same volume | ≥ 5× |
| NFR-2 | Rate-limit reduction with proxy | HTTP 429 rate (proxy vs no-proxy) | ≥ 80% reduction |
| NFR-3 | Job loss on gateway failure | Jobs silently lost after gateway unavailable | 0 |
| NFR-4 | Health data freshness | Staleness of gateway status + bandwidth in health endpoint | ≤ 30 s |
| NFR-5 | Flag toggle latency | Time to reflect feature flag change | ≤ 1 poll cycle (default 10 s) |
| NFR-6 | Bandwidth accuracy | Local estimate vs Webshare reported usage | Within 10% |

---

## Glossary

| Term | Definition |
|------|-----------|
| Rotating residential proxy | Proxy gateway where each new TCP connection automatically receives a different residential IP from a large pool (30M+) — no fixed IP list to manage |
| Webshare gateway | The single Webshare proxy endpoint (`p.webshare.io:80`) that fronts the rotating residential IP pool |
| Backbone mode | Webshare username suffix (`-backbone`) that routes traffic through the residential pool |
| Feature flag | Per-component environment variable (`PROXY_ENABLED`) that enables or disables proxy routing without a restart |
| ProxyService | Shared library module (`services/shared/shared/proxy/`) that encapsulates proxy URL construction, credential handling, request logging, and health checking |
| ProxyRequestLog | SQL Server table recording each proxied request with metadata for monitoring and cost estimation |
| Dead-letter path | Existing queue-based mechanism for jobs that exhaust all retries — jobs are moved to a dead-letter queue, never silently dropped |

---

## Out of Scope

- Hard bandwidth cap / circuit breaker (v2)
- Proxy status UI dashboard
- Non-Webshare proxy providers
- SOCKS5 gateway support
- Per-IP fixed proxy list management

---

## Dependencies

- Webshare rotating residential subscription (paid, bandwidth-based)
- Azure Key Vault (existing) — for credential storage
- Terraform (existing) — for Key Vault secret provisioning
- .NET Aspire AppHost (existing) — for env var wiring
- `httpx` — new dependency for gateway connectivity checks

---

## Success Criteria

- **SC-001**: Transcribe worker achieves ≥ 5× throughput with proxy enabled vs sequential baseline
- **SC-002**: HTTP 429 rate drops ≥ 80% with proxy enabled under equivalent job volume
- **SC-003**: Zero jobs silently lost when proxy gateway is unavailable (all reach DLQ)
- **SC-004**: Health endpoint returns gateway status + bandwidth data ≤ 30 s stale
- **SC-005**: Feature flag change reflected within one poll cycle, no restart required
- **SC-006**: Bandwidth usage queryable by time period, accurate within 10% of Webshare figures
- **SC-007**: Transcribe worker and API service can be independently enabled/disabled for proxy routing
