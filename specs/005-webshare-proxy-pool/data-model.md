# Data Model: Webshare Rotating Proxy Service

**Feature**: 005-webshare-proxy-pool
**Date**: 2026-02-22

---

## Overview

The rotating residential proxy model is stateless — there are no fixed IPs to track, no leases to coordinate. The data model focuses on:

1. **Request logging** — Track proxy usage for monitoring, cost estimation, and debugging
2. **Configuration** — Feature flag and proxy credential settings

---

## Entities

### ProxyRequestLog

Tracks each request routed through the Webshare proxy gateway for monitoring and bandwidth estimation.

| Field | Type | Constraints | Description |
| ----- | ---- | ----------- | ----------- |
| id | UUID | PK, auto-generated | Unique request log entry identifier |
| timestamp | DateTime | NOT NULL, indexed | When the request was made |
| component | String(50) | NOT NULL, indexed | Which component made the request (e.g., "transcribe-worker", "api-youtube-service") |
| operation | String(50) | NOT NULL | Type of operation (e.g., "subtitle-download", "channel-listing", "video-metadata") |
| video_id | String(20) | NULLABLE | YouTube video ID (if applicable) |
| channel_name | String(100) | NULLABLE | YouTube channel name (if applicable) |
| job_id | UUID | NULLABLE, FK → Jobs.id | Associated job ID (for worker requests) |
| correlation_id | String(50) | NULLABLE | Distributed tracing correlation ID |
| success | Boolean | NOT NULL | Whether the request succeeded |
| error_type | String(50) | NULLABLE | Error classification (e.g., "rate_limited", "connection_error", "auth_failure") |
| estimated_bytes | BigInteger | NULLABLE | Estimated bandwidth consumed (bytes) |
| duration_ms | Integer | NULLABLE | Request duration in milliseconds |
| created_at | DateTime | NOT NULL, default=now | Record creation timestamp |

**Indexes**:
- `ix_proxy_request_log_timestamp` on (timestamp) — for time-range queries
- `ix_proxy_request_log_component` on (component) — for per-component aggregation
- `ix_proxy_request_log_component_timestamp` on (component, timestamp) — for component + time range queries

**Retention**: Records older than 90 days may be purged (configurable). This table is for operational monitoring, not long-term audit.

---

### Feature Flag Configuration (via Environment Variables)

No database table needed. Configuration is managed through Pydantic Settings loaded from environment variables.

| Setting | Type | Default | Description |
| ------- | ---- | ------- | ----------- |
| PROXY_ENABLED | bool | false | Master switch for proxy routing |
| PROXY_GATEWAY_HOST | str | "p.webshare.io" | Webshare gateway hostname |
| PROXY_GATEWAY_PORT | int | 80 | Webshare gateway port |
| PROXY_USERNAME | str | (required if enabled) | Webshare proxy username |
| PROXY_PASSWORD | str | (required if enabled) | Webshare proxy password |
| PROXY_USE_BACKBONE | bool | true | Whether to use residential backbone (appends `-backbone` to username) |
| PROXY_MAX_CONCURRENCY | int | 0 | Max concurrent proxied requests per worker (0 = unlimited) |

**Note**: `PROXY_USERNAME` and `PROXY_PASSWORD` must be stored in Azure Key Vault and injected via Terraform/Aspire. They must never appear in config files, .env files, or source code.

---

## State Transitions

### Proxy Request Lifecycle

```
Request Initiated
    │
    ├─ Success ──────→ Logged (success=true, estimated_bytes set)
    │
    ├─ Rate Limited ──→ Logged (success=false, error_type="rate_limited")
    │                   → Worker retry logic handles re-queue
    │
    ├─ Connection Error → Logged (success=false, error_type="connection_error")
    │                     → Worker retry logic handles re-queue
    │
    └─ Auth Failure ──→ Logged (success=false, error_type="auth_failure")
                        → Alert raised (credential issue)
```

### Feature Flag States

```
Disabled (default)
    │
    └─ PROXY_ENABLED=true → Enabled
        │                     │
        │                     ├─ Credentials valid → Proxy routing active
        │                     │
        │                     └─ Credentials missing/invalid → Fallback to direct
        │                                                       (logged as warning)
        │
        └─ PROXY_ENABLED=false → Disabled (immediate, next poll cycle)
```

---

## Relationships

```
ProxyRequestLog ──(many-to-one)──→ Job (optional, via job_id FK)
```

No other entity relationships. The proxy service is stateless — it builds a proxy URL from config and passes it to yt-dlp. The request log is write-only from the proxy service perspective.

---

## Data Volume Estimates

| Scenario | Requests/Day | Log Rows/Day | Storage/Day |
| -------- | ------------ | ------------ | ----------- |
| Low volume | 100 transcriptions + 50 API calls | ~150 | ~30 KB |
| Medium volume | 1,000 transcriptions + 200 API calls | ~1,200 | ~240 KB |
| High volume | 10,000 transcriptions + 1,000 API calls | ~11,000 | ~2.2 MB |

At high volume with 90-day retention: ~200 KB * 90 = ~198 MB. Well within SQL Server capacity.

---

## Migration Notes

- New table `proxy_request_logs` requires an Alembic migration
- Migration path: `cd services/shared && uv run alembic revision --autogenerate -m "add proxy_request_logs table"`
- No existing tables are modified
- Migration is additive and backward-compatible (no breaking changes)
