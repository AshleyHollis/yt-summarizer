# Interface Contract: Shared Proxy Service

**Feature**: 005-webshare-proxy-pool
**Date**: 2026-02-22

---

## Overview

The Shared Proxy Service is a library module within `services/shared/shared/proxy/` that provides proxy configuration to any component making YouTube-bound requests via yt-dlp. It is NOT a standalone service or HTTP server — it is a Python module imported by workers and the API service.

---

## Public Interface

### ProxyService

The primary entry point for consumers. Provides proxy URL construction and request logging.

```
ProxyService
├── __init__(settings: ProxySettings, db: DatabaseConnection | None)
├── is_enabled() -> bool
├── get_proxy_url() -> str | None
├── get_ydl_proxy_opts() -> dict[str, str]
├── log_request(entry: ProxyRequestEntry) -> None
└── get_usage_summary(since: datetime) -> ProxyUsageSummary
```

#### `is_enabled() -> bool`
Returns whether proxy routing is currently enabled (reads from settings on each call for hot-toggle support).

#### `get_proxy_url() -> str | None`
Returns the fully-formed proxy URL for use with HTTP clients, or `None` if proxies are disabled.
- Format: `http://{username}-backbone:{password}@p.webshare.io:80`
- Returns `None` when `PROXY_ENABLED=false`
- Raises `ProxyConfigurationError` if enabled but credentials are missing

#### `get_ydl_proxy_opts() -> dict[str, str]`
Returns a dict suitable for merging into yt-dlp `ydl_opts`. Returns empty dict if disabled.
- When enabled: `{"proxy": "http://user-backbone:pass@p.webshare.io:80"}`
- When disabled: `{}`

#### `log_request(entry: ProxyRequestEntry) -> None`
Logs a proxy request to the database for monitoring. Fire-and-forget — errors are logged but do not propagate.

#### `get_usage_summary(since: datetime) -> ProxyUsageSummary`
Returns aggregated proxy usage statistics since the given timestamp.

---

### Data Types

#### ProxySettings

```
ProxySettings (Pydantic BaseSettings)
├── enabled: bool = False
├── gateway_host: str = "p.webshare.io"
├── gateway_port: int = 80
├── username: str = ""
├── password: str = ""  (SecretStr)
├── use_backbone: bool = True
└── max_concurrency: int = 0  (0 = unlimited)
```

Environment variable prefix: `PROXY_`

#### ProxyRequestEntry

```
ProxyRequestEntry (dataclass)
├── component: str         # e.g., "transcribe-worker"
├── operation: str         # e.g., "subtitle-download"
├── video_id: str | None
├── channel_name: str | None
├── job_id: str | None
├── correlation_id: str | None
├── success: bool
├── error_type: str | None
├── estimated_bytes: int | None
├── duration_ms: int | None
```

#### ProxyUsageSummary

```
ProxyUsageSummary (dataclass)
├── total_requests: int
├── successful_requests: int
├── failed_requests: int
├── estimated_bandwidth_bytes: int
├── by_component: dict[str, int]     # component → request count
├── by_error_type: dict[str, int]    # error_type → count
```

#### ProxyConfigurationError

```
ProxyConfigurationError (Exception)
# Raised when proxy is enabled but configuration is invalid
# (missing credentials, unreachable gateway, etc.)
```

---

## Consumer Integration Pattern

### For yt-dlp Call Sites (Workers + API)

```
# Before (existing pattern):
ydl_opts = {
    "skip_download": True,
    "writesubtitles": True,
    ...
}

# After (with proxy integration):
proxy_opts = proxy_service.get_ydl_proxy_opts()
ydl_opts = {
    "skip_download": True,
    "writesubtitles": True,
    ...
    **proxy_opts,  # Merges {"proxy": "..."} if enabled, or {} if disabled
}
```

### For Request Logging

```
# After each yt-dlp call:
proxy_service.log_request(ProxyRequestEntry(
    component="transcribe-worker",
    operation="subtitle-download",
    video_id=youtube_video_id,
    job_id=str(job_id),
    correlation_id=correlation_id,
    success=True,
    estimated_bytes=len(subtitle_content),
    duration_ms=elapsed_ms,
))
```

---

## Health Endpoint Extension

The existing worker health server exposes `/debug/connectivity`. The proxy service adds a new connectivity check:

```
GET /debug/connectivity

Response (extended):
{
    "queue": { "status": "ok", ... },
    "database": { "status": "ok", ... },
    "blob_storage": { "status": "ok", ... },
    "proxy": {
        "status": "ok" | "disabled" | "error",
        "enabled": true | false,
        "gateway": "p.webshare.io:80",
        "error": null | "auth_failure" | "connection_refused"
    }
}
```

---

## Error Handling Contract

| Scenario | Behavior |
| -------- | -------- |
| Proxy disabled | `get_proxy_url()` returns `None`; `get_ydl_proxy_opts()` returns `{}`; no proxy routing occurs |
| Proxy enabled, credentials valid | Proxy URL returned; all YouTube traffic routes through gateway |
| Proxy enabled, credentials missing | `ProxyConfigurationError` raised on `get_proxy_url()`; consumer falls back to direct or fails explicitly |
| Proxy enabled, gateway unreachable | yt-dlp raises connection error; consumer's existing retry logic handles it |
| Request logging fails (DB error) | Warning logged; request continues — logging is non-blocking |
