# Feature Specification: Webshare Rotating Proxy Pool

**Feature Branch**: `005-webshare-proxy-pool`
**Created**: 2026-02-22
**Status**: In Progress (~60% implemented)
**Input**: Route all YouTube-bound requests through Webshare rotating residential proxies to eliminate IP-based rate limiting and enable concurrent job processing.

---

## Clarifications

> Resolved during design session 2026-02-22. Preserved here as rationale for key decisions.

- **Proxy scope**: Covers all YouTube-calling components (transcribe worker + API service), not just the transcribe worker. A future-proof shared service makes it usable by any component.
- **Lease coordination**: With rotating residential proxies, per-IP lease locking is unnecessary. The database is used for request tracking and metrics only.
- **yt-dlp delays**: yt-dlp's built-in per-request delays remain at their defaults within each job's session. With rotating residential proxies, per-IP cooldowns are not needed.
- **Proxy type**: Rotating residential only. Each request automatically receives a different residential IP from a 30M+ pool via a single gateway endpoint — no fixed IP list to manage.
- **Concurrency**: Unlimited concurrency when the proxy is enabled. Rely on retry logic to handle Webshare rate limits or transient failures; no artificial cap.

---

## Assumptions

1. **Webshare rotating residential plan**: A paid Webshare rotating residential subscription will be used. Pricing is bandwidth-based (e.g., 10 GB for ~$27.50/mo), providing access to 30M+ rotating residential IPs across 195+ locations.
2. **Gateway-based routing**: Webshare provides a single proxy gateway endpoint (host:port + credentials). Each request through the gateway automatically receives a different residential IP. There is no fixed list of IPs to manage.
3. **yt-dlp internal delays preserved**: yt-dlp's built-in per-request delays remain at their default values within each job's download session. They are not reduced or removed when proxies are enabled.
4. **Unlimited concurrency with retry**: When the proxy feature flag is enabled, workers process as many jobs as available with no artificial concurrency cap. Retry logic handles Webshare throttling or transient failures.
5. **Shared proxy service**: The proxy routing capability is implemented as a shared service usable by any YouTube-calling component, not just the transcribe worker.
6. **Secure credential storage**: Webshare gateway credentials (host, port, username, password) are stored in the existing secrets management infrastructure and never committed to source code or config files.
7. **Bandwidth tracking**: The system tracks bandwidth consumption through the proxy gateway for cost visibility using the existing relational database.

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Proxy-Backed Transcription (Priority: P1)

As an operator, I want the transcribe worker to route YouTube requests through the Webshare rotating proxy gateway so that transcript fetching is resilient to IP-based rate limiting from YouTube.

**Why this priority**: Core feature — without proxy routing for the transcribe worker, the entire feature delivers no value. This is the highest-volume YouTube call site and the primary victim of IP-based rate limiting.

**Independent Test**: Submit a single transcription job with the proxy feature flag enabled and verify the request is routed through the proxy gateway rather than the worker's native IP. Delivers meaningful value on its own — one worker, one job, fully proxied.

**Acceptance Scenarios**:

1. **Given** the Webshare proxy feature flag is enabled and gateway credentials are configured, **When** a transcription job is processed, **Then** the YouTube request is sent through the Webshare rotating proxy gateway and a different residential IP is used for each new connection.

2. **Given** the Webshare proxy feature flag is disabled, **When** a transcription job is processed, **Then** the request uses the worker's native IP, identical to existing behavior with no proxy involvement.

3. **Given** the feature flag is enabled but the proxy gateway is unreachable, **When** a transcription job is received, **Then** the system retries the request with backoff; after repeated failures the job follows the existing dead-letter path and no jobs are silently lost.

---

### User Story 2 - Proxy-Backed Channel Browsing (Priority: P1)

As an operator, I want the API service to route YouTube channel-browsing and video-listing requests through the Webshare rotating proxy gateway so that channel imports are resilient to IP-based rate limiting and the entire ingestion pipeline is protected end-to-end.

**Why this priority**: The API service fetches channel video listings from YouTube. Without proxy coverage here, channel browsing remains rate-limited even when transcription is protected, blocking the import pipeline before jobs are ever created.

**Independent Test**: Trigger a channel import through the API with the proxy feature flag enabled and verify the YouTube listing request is routed through the proxy gateway. Can be verified independently of the transcribe worker.

**Acceptance Scenarios**:

1. **Given** the proxy feature flag is enabled for the API service, **When** a channel video listing is requested, **Then** the YouTube request is sent through the Webshare rotating proxy gateway.

2. **Given** the proxy feature flag is disabled for the API service, **When** a channel video listing is requested, **Then** the request uses the API server's native IP, identical to existing behavior.

---

### User Story 3 - Unlimited Concurrent Job Processing (Priority: P1)

As an operator, I want the transcribe worker to process all available queued jobs concurrently when the proxy is enabled so that overall transcript throughput scales with job volume rather than being bottlenecked by sequential processing.

**Why this priority**: With rotating residential proxies providing automatic IP diversity per request, there is no longer a reason to process jobs one at a time. Concurrent processing is the primary throughput benefit of the proxy pool.

**Independent Test**: Submit 10 transcription jobs simultaneously with the proxy feature enabled and verify all 10 begin processing without waiting for each other. A single job failure must not block or cancel the remaining 9.

**Acceptance Scenarios**:

1. **Given** the proxy feature is enabled and 10 jobs are queued, **When** the worker picks up the batch, **Then** all 10 jobs are processed concurrently, each routed through the proxy gateway and receiving a different residential IP automatically.

2. **Given** the proxy feature is disabled and multiple jobs are queued, **When** the worker picks up the batch, **Then** jobs are processed sequentially using the worker's native IP, preserving existing behavior.

3. **Given** a concurrent job fails due to a transient proxy error, **When** the failure is detected, **Then** that job is retried automatically per the existing retry strategy without affecting any other in-flight jobs.

---

### User Story 4 - Proxy Health and Cost Monitoring (Priority: P2)

As an operator, I want visibility into proxy gateway health (connectivity, request success rate, bandwidth consumption) so that I can monitor costs and detect failures before they become silent outages.

**Why this priority**: Operational visibility prevents silent failures when the gateway is unreachable or credentials expire, and enables bandwidth cost management before the billing period ends.

**Independent Test**: Query the worker's health endpoint with the proxy feature enabled and verify the response includes a proxy section covering gateway connectivity status, request counts, and estimated bandwidth consumed.

**Acceptance Scenarios**:

1. **Given** the proxy feature is enabled and requests have been processed, **When** the health endpoint is queried, **Then** the response includes gateway connectivity status, total requests routed, success/failure counts, and estimated bandwidth consumed.

2. **Given** the proxy gateway returns consecutive connection errors, **When** the failure threshold is reached, **Then** the gateway is reported as unhealthy in the health endpoint and an alert is raised.

3. **Given** multiple transcription jobs have completed through the proxy, **When** an operator queries bandwidth metrics, **Then** cumulative bandwidth usage is available broken down by time period.

---

### User Story 5 - Shared Proxy Service (Priority: P2)

As a developer, I want the proxy routing capability to be implemented as a shared service in the common library so that any component that communicates with YouTube can use it without duplicating proxy logic.

**Why this priority**: Both the transcribe worker and API service need proxy routing today. A shared service eliminates duplication, enforces consistent behavior, and makes it trivial for future components to adopt proxy routing.

**Independent Test**: Import the shared proxy service from the common library in a new test component, configure it with a valid feature flag, and verify it can produce a proxy-routed request without implementing any proxy logic itself.

**Acceptance Scenarios**:

1. **Given** the proxy service is available in the shared library, **When** a new component imports it, **Then** that component can configure and use proxy routing without implementing its own gateway URL construction, credential handling, or request logging.

2. **Given** two components both use the shared proxy service, **When** each component sets its own feature flag independently, **Then** each component's proxy behavior is controlled solely by its own flag setting and does not affect the other.

---

### Edge Cases

- What happens when the Webshare gateway is unreachable? Requests fail and are retried per existing retry logic; after repeated failures the job follows the existing dead-letter path; the health endpoint reports the gateway as unhealthy.
- What happens when a worker crashes mid-request? There is no proxy state to clean up (stateless gateway model); the job message becomes visible again after the queue visibility timeout and another worker picks it up.
- What happens when the Webshare subscription expires or credentials become invalid? All proxied requests fail with authentication errors; the system retries; the health endpoint and logs surface the credential failure; the operator is alerted.
- What happens when YouTube returns a 429 despite the proxy (residential IP flagged)? The request is retried automatically; the next retry gets a different residential IP from the rotating pool; consecutive 429s trigger extended backoff per existing rate-limit handling.
- What happens when Webshare throttles the gateway (too many concurrent connections)? Requests receive throttling errors; retry logic handles them with backoff; no data is lost and the system remains stable.
- What happens when the bandwidth budget is exhausted for the billing period? Webshare may throttle or block requests; the system treats this identically to the gateway being unreachable; the operator is alerted via bandwidth tracking metrics.
- What happens during a network partition between the worker and the proxy gateway? Requests time out; retry logic handles them with backoff; if the partition persists, the health endpoint reports gateway connectivity failure.

---

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: The system MUST provide a per-component feature flag that independently enables or disables Webshare proxy routing for the transcribe worker and the API service. When a component's flag is disabled, that component MUST behave identically to its current behavior.

- **FR-002**: The system MUST route all YouTube-bound requests through the Webshare rotating residential proxy gateway when a component's feature flag is enabled. Each request through the gateway MUST automatically receive a different residential IP.

- **FR-003**: The system MUST implement proxy routing as a shared service in the common library, usable by any component that communicates with YouTube without duplicating proxy logic.

- **FR-004**: The system MUST preserve yt-dlp's built-in per-request delays at their default values within each job's download session, regardless of whether proxies are enabled. These delays MUST NOT be reduced or removed.

- **FR-005**: When the proxy feature flag is enabled, the transcribe worker MUST process all available queued jobs concurrently with no artificial concurrency cap.

- **FR-006**: The system MUST apply existing retry-with-backoff logic to handle transient proxy failures (gateway timeouts, connection errors, throttling). After exhausting retries, failed jobs MUST follow the existing dead-letter path without silent loss.

- **FR-007**: When a YouTube request through the proxy returns a rate-limit response, the system MUST retry the request. Each retry MUST automatically receive a different residential IP from the rotating pool.

- **FR-008**: The system MUST track proxy request metrics in the existing database: total requests routed, success and failure counts, and estimated bandwidth consumed per time period.

- **FR-009**: The system MUST expose proxy service health through the existing health reporting mechanism, including gateway connectivity status, request success rate, and bandwidth consumption.

- **FR-010**: The system MUST store Webshare gateway credentials (host, port, username, password) using the project's existing secrets management infrastructure. Credentials MUST NOT appear in config files, environment files, or source code.

- **FR-011**: The feature flag toggle MUST take effect without requiring a worker or service restart. The change MUST be reflected within one polling cycle.

- **FR-012**: The API service MUST route YouTube channel-browsing, video-listing, and video-metadata requests through the shared proxy service when the API service's feature flag is enabled.

### Key Entities *(include if feature involves data)*

- **Proxy Gateway**: The Webshare rotating residential proxy endpoint (host, port, credentials). Stateless — each request routed through it automatically receives a different residential IP from the 30M+ pool. No fixed IP list is maintained by the system.

- **Shared Proxy Service**: A common library component that encapsulates proxy gateway configuration, request routing, credential validation, health checking, and metrics tracking. Used by any component that needs proxy-routed YouTube access.

- **Proxy Request Log**: A database record tracking each request routed through the proxy: timestamp, originating component, operation type, success or failure, error classification, estimated bandwidth in bytes, and duration. Used for cost monitoring and operational visibility. Records are retained for 90 days.

- **Feature Flag Configuration**: A per-component configuration entry that independently controls whether proxy routing is enabled. Set via environment variables, hot-reloadable without a service restart.

---

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: With the proxy enabled, the transcribe worker processes all available queued jobs concurrently rather than sequentially, achieving at least 5× throughput compared to the single-worker sequential baseline under the same job volume.

- **SC-002**: With the proxy enabled, the rate of YouTube rate-limit responses (HTTP 429) decreases by at least 80% compared to operating without a proxy under equivalent job volume.

- **SC-003**: When the proxy gateway is unavailable, all affected jobs are retried per existing retry logic and eventually reach the dead-letter queue. Zero jobs are silently lost.

- **SC-004**: The health endpoint returns gateway connectivity status, request success/failure rates, and bandwidth consumption with data no more than 30 seconds stale.

- **SC-005**: Enabling or disabling the proxy feature flag changes the component's behavior within one polling cycle (configurable, default 10 seconds) with no service restart required.

- **SC-006**: Operators can query cumulative proxy bandwidth usage by time period, with accuracy within 10% of the provider's reported usage figures.

- **SC-007**: The transcribe worker and the API service can each be independently enabled or disabled for proxy routing without affecting the other component's behavior.
