# Feature Specification: Webshare Rotating Proxy Service

| Field          | Value                                             |
| -------------- | ------------------------------------------------- |
| Feature Branch | `005-webshare-proxy-pool`                         |
| Created        | 2026-02-22                                        |
| Status         | Draft                                             |
| Input          | Implement Webshare proxy pool with rate-limited leases for transcribe worker |

---

## Clarifications

### Session 2026-02-22

- Q: Should proxies cover only the transcribe worker, or also the API service and be future-proofed for any component? → A: All YouTube-calling components + future-proof shared proxy service usable by any component.
- Q: What should back the shared lease/coordination registry? → A: SQL Server (existing infrastructure). Note: with rotating residential proxies, per-IP lease locking is no longer needed; SQL is used for request tracking and metrics.
- Q: Should the per-proxy pool cooldown stack with yt-dlp's built-in sleep, or replace it? → A: Pool cooldown replaces yt-dlp sleep as the inter-job delay mechanism. However, yt-dlp's built-in per-request delays (sleep_interval_subtitles, sleep_interval_requests) remain at defaults within each job. With rotating residential proxies, per-IP cooldowns are no longer applicable since each request gets a fresh IP.
- Q: What type of Webshare proxies should be used? → A: Rotating residential only. This fundamentally simplifies the architecture from managing a fixed pool of IPs with per-IP cooldowns and lease coordination to routing through a single gateway endpoint where each request automatically receives a different residential IP from a pool of 30M+.
- Q: How should concurrency be controlled when proxies are enabled? → A: Unlimited concurrency with retry logic. Process as many jobs as available with no artificial cap. Rely on retry logic to handle Webshare rate limits or transient failures.

---

## Assumptions

1. **Webshare rotating residential plan**: A paid Webshare rotating residential proxy subscription will be used. Pricing is bandwidth-based (e.g., 10 GB for ~$27.50/mo), providing access to 30M+ rotating residential IPs across 195+ locations.
2. **Gateway-based routing**: Webshare provides a single proxy gateway endpoint (host:port + credentials). Each request routed through the gateway automatically receives a different residential IP address. There is no fixed list of IPs to manage.
3. **yt-dlp internal delays preserved**: yt-dlp's built-in per-request delays (`sleep_interval_subtitles`, `sleep_interval_requests`) remain at their default values within each job's download session. These are not reduced or removed when proxies are enabled.
4. **Unlimited concurrency with retry**: When the proxy feature flag is enabled, workers process as many jobs as are available with no artificial concurrency cap. Retry logic handles any errors from Webshare throttling or transient failures.
5. **Shared proxy service**: The proxy routing capability is implemented as a shared service usable by any component that communicates with YouTube, not just the transcribe worker.
6. **Secure credential storage**: Webshare API credentials (gateway host, port, username, password) will be stored securely in the existing secrets management infrastructure.
7. **Bandwidth tracking**: The system will track bandwidth consumption through the proxy gateway for cost visibility, using the existing SQL Server database.

---

## 1. User Scenarios & Testing

### US-001: Proxy-Backed Transcription (P1)

**As an** operator, **I want** the transcribe worker to route YouTube requests through the Webshare rotating proxy gateway **so that** transcript fetching is resilient to IP-based rate limiting from YouTube.

**Priority justification**: Core feature — without proxy routing, the entire feature has no value.

**Independent test**: Submit a transcription job with the proxy feature enabled and verify the request is routed through the proxy gateway rather than the worker's native IP.

**Acceptance scenarios**:

| Scenario | Given | When | Then |
| -------- | ----- | ---- | ---- |
| Proxy routing active | The Webshare proxy feature flag is enabled and gateway credentials are configured | A transcription job is processed | The YouTube request is sent through the Webshare rotating proxy gateway |
| Feature flag disabled | The Webshare proxy feature flag is disabled | A transcription job is processed | The request uses the worker's native IP (existing behavior) |
| Gateway unreachable | The feature flag is enabled but the proxy gateway is unreachable | A transcription job is received | The system retries the request; after repeated failures, the job is retried per existing retry logic |

### US-002: Proxy-Backed Channel Browsing (P1)

**As an** operator, **I want** the API service to route YouTube channel-browsing requests through the Webshare rotating proxy gateway **so that** channel imports and video listing fetches are also resilient to IP-based rate limiting.

**Priority justification**: The API service also uses yt-dlp to fetch channel video listings from YouTube. Without proxy routing here, channel browsing can still be rate-limited, blocking the import pipeline.

**Independent test**: Trigger a channel import through the API with the proxy feature enabled and verify the request is routed through the proxy gateway.

**Acceptance scenarios**:

| Scenario | Given | When | Then |
| -------- | ----- | ---- | ---- |
| API proxy routing | The proxy feature flag is enabled | A channel video listing is requested through the API | The YouTube request is sent through the Webshare rotating proxy gateway |
| API fallback | The proxy feature flag is disabled | A channel video listing is requested | The request uses the API server's native IP (existing behavior) |

### US-003: Concurrent Job Processing (P1)

**As an** operator, **I want** the transcribe worker to process all available jobs concurrently when proxies are enabled **so that** overall transcript throughput scales with job volume rather than being bottlenecked by sequential processing.

**Priority justification**: With rotating residential proxies providing automatic IP diversity, there is no reason to process jobs sequentially. Concurrent processing is the primary throughput benefit.

**Independent test**: Submit 10 transcription jobs simultaneously with the proxy feature enabled and verify all 10 jobs begin processing without waiting for each other.

**Acceptance scenarios**:

| Scenario | Given | When | Then |
| -------- | ----- | ---- | ---- |
| Unlimited parallel processing | Proxy feature is enabled and 10 jobs are queued | Worker picks up jobs | All 10 jobs are processed concurrently, each routed through the proxy gateway (each getting a different IP automatically) |
| Sequential fallback | Proxy feature is disabled | Multiple jobs are queued | Jobs process sequentially using the worker's native IP (existing behavior) |
| Retry on failure | A concurrent job fails due to a transient proxy error | The failed job is detected | The job is retried automatically per the existing retry strategy |

### US-004: Proxy Service Health and Cost Monitoring (P2)

**As an** operator, **I want** visibility into proxy service health (gateway connectivity, request success rate, bandwidth consumption) **so that** I can monitor costs and detect problems.

**Priority justification**: Operational visibility prevents silent failures and enables bandwidth cost management.

**Independent test**: Query the worker's health endpoint and verify it includes proxy gateway metrics (connectivity status, request counts, bandwidth consumed).

**Acceptance scenarios**:

| Scenario | Given | When | Then |
| -------- | ----- | ---- | ---- |
| Health reporting | Proxy feature is enabled and requests have been processed | Health endpoint is queried | Response includes gateway connectivity status, total requests routed, success/failure counts, and estimated bandwidth consumed |
| Gateway failure detection | The proxy gateway returns consecutive connection errors | After the failure threshold is reached | The gateway is reported as unhealthy in the health endpoint; alerts are raised |
| Bandwidth tracking | Multiple transcription jobs complete through the proxy | Operator queries bandwidth metrics | Cumulative bandwidth usage is available, broken down by time period |

### US-005: Shared Proxy Service (P2)

**As a** developer, **I want** the proxy routing capability to be implemented as a shared service in the common library **so that** any component that communicates with YouTube can use it without duplicating proxy logic.

**Priority justification**: Both the transcribe worker and API service need proxy routing today. A shared service prevents duplication and enables future components to use proxies easily.

**Independent test**: Import the shared proxy service from the common library in a new test component and verify it can route a request through the proxy gateway.

**Acceptance scenarios**:

| Scenario | Given | When | Then |
| -------- | ----- | ---- | ---- |
| Shared service available | The proxy service is published in the shared library | A new component imports the proxy service | It can configure and use proxy routing without implementing its own proxy logic |
| Independent configuration | Two components use the shared proxy service | Each component configures the proxy independently (enable/disable) | Each component's proxy behavior is controlled by its own feature flag setting |

### Edge Cases

| Edge Case | Expected Behavior |
| --------- | ----------------- |
| Webshare gateway is unreachable | Requests fail and are retried per existing retry logic; after repeated failures, job follows existing dead-letter path; health endpoint reports gateway as unhealthy |
| Worker crashes mid-request | No proxy state to clean up (stateless gateway model); job message becomes visible again after queue visibility timeout; another worker picks it up |
| Webshare subscription expires or credentials become invalid | All proxied requests fail with authentication errors; system retries; health endpoint and logs surface the credential failure; operator is alerted |
| YouTube returns 429 despite proxy (residential IP flagged) | The request is retried automatically; next retry gets a different residential IP from the rotating pool; consecutive 429s trigger extended backoff per existing rate-limit handling |
| Webshare throttles the gateway connection (too many concurrent requests) | Requests receive throttling errors from the gateway; retry logic handles these with backoff; system remains stable |
| Bandwidth budget exceeded for the billing period | Webshare may throttle or block requests; system treats this like gateway unreachable; operator is alerted via bandwidth tracking metrics |
| Network partition between worker and proxy gateway | Requests time out; retry logic handles with backoff; if persistent, health endpoint reports gateway connectivity failure |

---

## 2. Requirements

### Functional Requirements

| ID     | Requirement |
| ------ | ----------- |
| FR-001 | The system MUST provide a feature flag that enables or disables Webshare proxy routing. The flag MUST be independently configurable per component (transcribe worker, API service). When disabled, each component MUST behave identically to current behavior. |
| FR-002 | The system MUST route YouTube requests through the Webshare rotating residential proxy gateway when the feature flag is enabled. Each request through the gateway receives a different residential IP automatically. |
| FR-003 | The system MUST implement the proxy routing capability as a shared service in the common library, usable by any component that needs to route requests through the proxy. |
| FR-004 | The system MUST preserve yt-dlp's built-in per-request delays (`sleep_interval_subtitles`, `sleep_interval_requests`) at their default values within each job's download session, regardless of whether proxies are enabled. |
| FR-005 | When the proxy feature flag is enabled, the transcribe worker MUST process all available queued jobs concurrently with no artificial concurrency cap. |
| FR-006 | The system MUST use existing retry logic to handle transient proxy failures (gateway timeouts, connection errors, Webshare throttling). Failed requests MUST be retried with backoff per the existing retry strategy. |
| FR-007 | When a YouTube request returns a rate-limit response (429) through the proxy, the system MUST retry the request. The next retry automatically receives a different residential IP from the rotating pool. |
| FR-008 | The system MUST track proxy request metrics in the existing SQL Server database: total requests routed, success/failure counts, and estimated bandwidth consumed per time period. |
| FR-009 | The system MUST expose proxy service health through the existing health reporting mechanism: gateway connectivity status, request success rate, and bandwidth consumption. |
| FR-010 | The system MUST securely store Webshare gateway credentials (host, port, username, password) using the project's existing secrets management infrastructure. |
| FR-011 | The feature flag toggle MUST take effect without requiring a worker or service restart. |
| FR-012 | The API service MUST route YouTube channel-browsing and video-listing requests through the shared proxy service when the feature flag is enabled. |

### Key Entities

| Entity                     | Description |
| -------------------------- | ----------- |
| Proxy Gateway              | The Webshare rotating residential proxy endpoint (host, port, credentials). Stateless — each request routed through it automatically receives a different residential IP from the 30M+ pool. |
| Shared Proxy Service       | A common library component that encapsulates proxy gateway configuration, request routing, health checking, and metrics tracking. Used by any component needing proxy-routed YouTube access. |
| Proxy Request Log          | A database record tracking each request routed through the proxy: timestamp, component, success/failure, estimated bandwidth, response status. Used for cost monitoring and operational visibility. |
| Feature Flag Configuration | A per-component configuration entry that controls whether proxy routing is enabled. Independently settable for each component (transcribe worker, API service). |

---

## 3. Success Criteria

| ID     | Criterion | Measurement |
| ------ | --------- | ----------- |
| SC-001 | Transcription throughput increases significantly when proxies are enabled | With proxies enabled, the transcribe worker processes all available queued jobs concurrently rather than sequentially, achieving at least 5x throughput compared to single-worker sequential baseline |
| SC-002 | YouTube rate-limit events decrease compared to non-proxy baseline | With proxies enabled, the rate of YouTube 429 responses decreases by at least 80% compared to operating without proxies under the same job volume |
| SC-003 | The system degrades gracefully when the proxy gateway is unavailable | When the gateway is unreachable, jobs are retried per existing retry logic and eventually follow the existing dead-letter path; no jobs are silently lost |
| SC-004 | Proxy service health is visible to operators | Health endpoint returns gateway connectivity status, request success/failure rates, and bandwidth consumption with data no more than 30 seconds stale |
| SC-005 | Feature flag toggle takes effect without restart | Enabling or disabling the proxy feature flag changes component behavior within one polling cycle (configurable, default 10 seconds) |
| SC-006 | Bandwidth consumption is trackable for cost management | Operators can query cumulative bandwidth usage by time period, with accuracy within 10% of Webshare's reported usage |
| SC-007 | Both the transcribe worker and API service can independently use proxy routing | Each component can be independently enabled/disabled for proxy routing without affecting the other |
