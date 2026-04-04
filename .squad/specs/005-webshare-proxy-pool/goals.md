# Goals: Webshare Rotating Proxy Pool

**Feature ID**: F005
**Status**: Implementing
**Milestone**: M3
**Spec Phase**: execution
**Imported**: 2026-04-04 from `specs/005-webshare-proxy-pool/spec.md`

---

## Problem Statement

The YT Summarizer's transcribe worker and API service make YouTube requests directly from their native IPs. YouTube aggressively rate-limits these requests (HTTP 429), which blocks transcript fetching and channel browsing — the core data-ingestion pipeline. Sequential processing of one job at a time compounds the problem by reducing throughput. The system needs IP diversity per request and concurrent processing to be resilient to YouTube's rate-limiting behaviour.

## Success Criteria

- With proxy enabled, transcribe worker processes all queued jobs **concurrently** (at least 5× throughput vs. sequential baseline under equal volume)
- With proxy enabled, YouTube 429 responses drop by at least **80%** vs. no-proxy baseline
- When the proxy gateway is unavailable, **zero jobs are silently lost** — all reach dead-letter after retry exhaustion
- Health endpoint reflects gateway status, success/failure rates, and bandwidth within **30 seconds**
- Feature flag toggles take effect within **one poll cycle** (default 10 s) — no restart required
- Bandwidth usage queryable by time period, accurate to within **10%** of Webshare-reported figures
- Transcribe worker and API service can be **independently** enabled/disabled for proxy routing

## In Scope

- Shared proxy service module (`services/shared/shared/proxy/`) usable by any YouTube-calling component
- Transcribe worker proxy integration (yt-dlp `proxy` option)
- API service proxy integration (channel browsing, video listing, video metadata, batch metadata)
- Concurrent job processing in `BaseWorker` via `asyncio.gather(return_exceptions=True)` with semaphore
- Per-component feature flags via environment variables (Pydantic Settings, hot-reload)
- Proxy request logging to SQL Server (`proxy_request_logs` table, 90-day retention)
- Proxy health checks exposed via existing `/debug/connectivity` and new `/debug/proxy` endpoint
- Webshare gateway credentials stored in Azure Key Vault via Terraform
- Aspire AppHost wiring of `PROXY_*` env vars

## Out of Scope

- Hard bandwidth cap / circuit breaker for billing period exhaustion (deferred to v2)
- UI for proxy status dashboard (Lambert not needed for this feature)
- Support for non-Webshare proxy providers
- SOCKS5 gateway (HTTP only in v1)
- Per-IP fixed proxy list management (stateless rotating gateway only)
- Support for Python < 3.11

## Constraints

- All Webshare credentials must go through Azure Key Vault — never in source code, config files, or .env files
- yt-dlp built-in per-request delays (`sleep_interval_subtitles`, `sleep_interval_requests`) must be preserved at defaults
- No changes to HTTP_PROXY / HTTPS_PROXY environment variables (would affect Azure SDK traffic)
- Python >=3.11 across all services
- Bandwidth-based pricing: Webshare rotating residential at ~$2.75/GB (10 GB tier)

## Users

- **Operator** — monitors proxy health, manages feature flags, tracks bandwidth cost
- **Developer** — consumes `ProxyService` from shared library without reimplementing proxy logic

## Testing Expectations

- Unit tests: `ProxyService` methods (is_enabled, get_proxy_url, get_ydl_proxy_opts, log_request, get_usage_summary) with mocked settings and DB
- Unit tests: concurrent `BaseWorker` (semaphore, gather, graceful shutdown, error isolation)
- Integration tests: transcribe worker with proxy enabled/disabled (verify yt-dlp opts)
- Integration tests: API service channel-browsing / video-listing with proxy enabled/disabled
- Integration tests: proxy request logging to DB and usage summary query
- E2E: `/debug/connectivity` includes proxy section; `/debug/proxy` returns usage summary
- Regression: all existing tests pass with `PROXY_ENABLED=false` (default)
