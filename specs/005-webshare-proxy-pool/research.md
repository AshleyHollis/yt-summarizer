# Research: Webshare Rotating Proxy Service

**Feature**: 005-webshare-proxy-pool
**Date**: 2026-02-22

---

## Research Area 1: Webshare Rotating Residential Proxy Configuration

### Decision
Use Webshare's rotating residential proxy gateway at `p.webshare.io:80` with username/password authentication and backbone mode for residential IP rotation.

### Rationale
- Rotating residential proxies provide automatic IP diversity (30M+ pool) without managing individual IPs
- Bandwidth-based pricing ($2.75/GB at 10 GB tier) is cost-effective for subtitle downloads (~50-200KB each)
- Gateway model eliminates the need for a complex per-IP lease/cooldown system
- Residential IPs are harder for YouTube to detect than datacenter IPs

### Key Findings
- **Gateway endpoint**: `p.webshare.io:80` (HTTP) or `p.webshare.io:1080` (SOCKS5)
- **Authentication**: Username/password in proxy URL format: `http://{username}-{backbone}:{password}@p.webshare.io:80`
- **Backbone parameter**: Append `-backbone` suffix to username for residential pool (e.g., `user123-backbone`)
- **Rotation**: Automatic per-connection — each new TCP connection gets a different residential IP
- **Bandwidth**: Metered per GB; no per-request or per-IP limits on the gateway itself
- **API**: REST API at `proxy.webshare.io/api/v2/` for bandwidth usage tracking, proxy list management

### Alternatives Considered
1. **Static datacenter proxies** — Cheaper per GB but datacenter IPs are easily detected by YouTube. Requires manual IP pool management with per-IP cooldowns.
2. **Static residential proxies** — More expensive ($0.30/proxy), requires fixed IP pool management, same lease complexity as datacenter.
3. **Self-hosted proxy rotation (e.g., ScraperAPI, BrightData)** — Higher cost, vendor lock-in, unnecessary complexity when Webshare provides built-in rotation.

---

## Research Area 2: yt-dlp Proxy Support

### Decision
Pass proxy URL via yt-dlp's `proxy` option in `ydl_opts` dict. Keep all existing yt-dlp delay settings at their defaults.

### Rationale
- yt-dlp natively supports HTTP/HTTPS/SOCKS proxies via a single `proxy` parameter
- The proxy URL format matches Webshare's gateway format exactly
- yt-dlp's built-in sleep intervals (`sleep_interval_subtitles`, `sleep_interval_requests`) provide per-request pacing that protects the proxy IP during each download session
- No need to modify yt-dlp's internal retry or sleep behavior

### Key Findings
- **yt-dlp parameter**: `'proxy': 'http://user-backbone:pass@p.webshare.io:80'` in `ydl_opts`
- **All yt-dlp network traffic** routes through the proxy when set (subtitle downloads, metadata fetches, etc.)
- **Existing delays preserved**: `sleep_interval_subtitles=60+random(0,10)`, `sleep_interval_requests=1.0`
- **5 call sites** across 4 files need proxy injection:
  1. `services/workers/transcribe/worker.py` — subtitle download (primary)
  2. `services/api/src/api/services/youtube_service.py` — channel video listing
  3. `services/api/src/api/services/video_service.py` — video metadata + transcript availability
  4. `services/api/src/api/services/batch_service.py` — batch video metadata

### Alternatives Considered
1. **Environment variable `HTTP_PROXY`/`HTTPS_PROXY`** — Would affect ALL HTTP traffic (including Azure SDK calls), not just YouTube. Rejected.
2. **Custom yt-dlp network adapter** — Over-engineered; the `proxy` option is the standard approach.

---

## Research Area 3: Concurrent Processing Architecture

### Decision
Use `asyncio.gather(return_exceptions=True)` with `asyncio.Semaphore` for concurrent message processing in BaseWorker. Each worker subclass controls its own max concurrency.

### Rationale
- `asyncio.TaskGroup` (Python 3.11+) cancels ALL tasks when ANY task fails — wrong for independent message processing where error isolation is critical
- `asyncio.gather(return_exceptions=True)` provides error isolation — each task succeeds or fails independently
- Semaphore bounds concurrency to prevent resource exhaustion (thread pool, DB connections, bandwidth)
- Existing `_process_single_message` already has comprehensive error handling — concurrent wrapper adds a thin layer

### Key Findings
- **Python version**: >=3.11 confirmed across all services
- **Current model**: Sequential `for` loop in `poll_once()` — processes one message at a time
- **Target model**: `asyncio.gather()` over all messages in batch, bounded by semaphore
- **Thread pool**: Dedicated `ThreadPoolExecutor` per worker (yt-dlp runs in executor)
- **Shared mutable state risk**: `_last_youtube_request_time` and `_youtube_request_count` globals in transcribe/worker.py need conversion to instance variables with asyncio.Lock
- **Logging isolation**: structlog with contextvars (not thread-locals) ensures per-task log context
- **Graceful shutdown**: Drain in-flight tasks with timeout → cancel pending → shutdown executor

### Alternatives Considered
1. **asyncio.TaskGroup** — Better error propagation but cancels sibling tasks on failure. Only suitable for sub-tasks within a single message, not across messages.
2. **Multiple worker instances (horizontal scaling)** — More complex orchestration, more Azure Queue consumers, more Aspire config. Vertical concurrency is simpler for the current scale.
3. **Unbounded concurrency (no semaphore)** — Risks exhausting thread pool, DB connections, and bandwidth budget simultaneously. Rejected for safety.

---

## Research Area 4: Feature Flag Implementation

### Decision
Environment-variable-based feature flags via Pydantic Settings, consistent with the project's existing configuration pattern.

### Rationale
- No existing feature flag system in the codebase
- Pydantic Settings already drives all configuration via environment variables
- Environment variables can be hot-reloaded by checking on each poll cycle (no restart required)
- Aspire AppHost already wires environment variables to all services

### Key Findings
- **Pattern**: `PROXY_ENABLED=true/false` per component (workers read from env, API reads from env)
- **Hot-toggle**: Worker checks flag on each `poll_once()` call; API checks per-request
- **No external flag service** needed for this scale
- **Config class**: New `ProxySettings` nested in existing `Settings` class with fields: `enabled`, `gateway_url`, `username`, `password`, `backbone`

### Alternatives Considered
1. **LaunchDarkly / Unleash** — Overkill for a single feature flag; adds external dependency
2. **Database-backed flags** — Unnecessary complexity; env vars are sufficient and consistent with existing patterns
3. **Config file flags** — Less portable than env vars; harder to change per-environment

---

## Research Area 5: Bandwidth Tracking and Cost Control

### Decision
Log proxy requests to a SQL Server table for bandwidth estimation and monitoring. No hard bandwidth cap in v1 — rely on Webshare plan limits and operator monitoring.

### Rationale
- Exact bandwidth measurement requires intercepting yt-dlp's HTTP traffic, which is complex and fragile
- Estimated bandwidth (based on subtitle file sizes) is sufficient for cost monitoring
- Webshare API provides actual bandwidth usage for reconciliation
- Hard caps add complexity and can cause silent job failures

### Key Findings
- **Subtitle download size**: Typically 50-200KB per video (JSON3 format)
- **Channel listing size**: Typically 10-50KB per API call
- **At 10 GB/month ($27.50)**: ~50,000-200,000 subtitle downloads, far exceeding expected volume
- **Tracking approach**: Log each proxy request with timestamp, component, estimated bytes, and success/failure
- **Webshare API**: `GET /api/v2/subscription/` returns bandwidth usage, remaining balance

### Alternatives Considered
1. **Hard bandwidth cap with circuit breaker** — Adds complexity; risk of stopping production processing mid-batch. Deferred to v2 if needed.
2. **No tracking** — Insufficient for cost monitoring. Rejected.
3. **Webshare API-only tracking** — Subject to API availability; local logging provides immediate visibility.
