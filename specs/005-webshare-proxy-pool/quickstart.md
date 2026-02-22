# Quickstart: Webshare Rotating Proxy Service

**Feature**: 005-webshare-proxy-pool
**Date**: 2026-02-22

---

## Prerequisites

1. **Webshare account** with a rotating residential proxy plan (minimum 1 GB tier)
2. **Proxy credentials** from Webshare dashboard (username and password)
3. **Existing dev environment** — Python >=3.11, uv, Aspire, SQL Server (via Aspire/Docker)

---

## Local Development Setup

### 1. Get Webshare Credentials

1. Sign up at [webshare.io](https://www.webshare.io/)
2. Subscribe to a Rotating Residential plan (1 GB minimum for testing)
3. Go to Dashboard → Proxy → Settings
4. Note your **Proxy Username** and **Proxy Password**

### 2. Configure Environment Variables

Add to your local environment (or `.env` file for the relevant service):

```bash
PROXY_ENABLED=true
PROXY_USERNAME=your-webshare-username
PROXY_PASSWORD=your-webshare-password
PROXY_USE_BACKBONE=true
PROXY_GATEWAY_HOST=p.webshare.io
PROXY_GATEWAY_PORT=80
```

For Aspire-based development, these will be wired through `AppHost.cs`.

### 3. Run Database Migration

```bash
cd services/shared
uv run alembic upgrade head
```

This creates the `proxy_request_logs` table.

### 4. Verify Proxy Connectivity

Start the services via Aspire:

```bash
aspire run
```

Check the transcribe worker health endpoint:

```bash
curl http://localhost:8091/debug/connectivity
```

Verify the `proxy` section shows `"status": "ok"`.

### 5. Test Proxy Routing

Submit a test transcription job and check the logs for proxy-related entries. The structured log output will include `proxy_enabled=true` and the request will route through `p.webshare.io`.

---

## Configuration Reference

| Variable | Type | Default | Description |
| -------- | ---- | ------- | ----------- |
| `PROXY_ENABLED` | bool | `false` | Enable/disable proxy routing |
| `PROXY_GATEWAY_HOST` | str | `p.webshare.io` | Webshare gateway hostname |
| `PROXY_GATEWAY_PORT` | int | `80` | Webshare gateway port |
| `PROXY_USERNAME` | str | (required) | Webshare proxy username |
| `PROXY_PASSWORD` | str | (required) | Webshare proxy password |
| `PROXY_USE_BACKBONE` | bool | `true` | Use residential backbone IPs |
| `PROXY_MAX_CONCURRENCY` | int | `0` | Max concurrent proxied requests (0 = unlimited) |

---

## Testing Without a Webshare Account

For unit and integration tests, the proxy service is mockable:

- Set `PROXY_ENABLED=false` (default) — all proxy code is bypassed
- Mock `ProxyService.get_ydl_proxy_opts()` to return `{}` or a test proxy URL
- The `ProxyRequestLog` database operations can be tested against the local SQL Server

E2E tests that verify actual proxy routing require a Webshare account with active credentials.

---

## Troubleshooting

| Issue | Check |
| ----- | ----- |
| Proxy not routing | Verify `PROXY_ENABLED=true` in environment; check `/debug/connectivity` |
| Authentication error | Verify `PROXY_USERNAME` and `PROXY_PASSWORD` match Webshare dashboard |
| Bandwidth exceeded | Check Webshare dashboard for plan limits; review `proxy_request_logs` table |
| Jobs still rate-limited | Verify proxy is active (check logs for `proxy_enabled=true`); yt-dlp's built-in delays are expected behavior |
| Health endpoint missing proxy | Ensure the proxy connectivity check is registered in the worker's health server |
