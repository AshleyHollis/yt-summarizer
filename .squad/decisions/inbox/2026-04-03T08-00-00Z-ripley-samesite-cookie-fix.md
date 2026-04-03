# Decision: SameSite=None; Secure Cookie + CORS Credentials Config (Ripley)

**Author:** Ripley (Backend Developer)  
**Date:** 2026-04-03  
**Status:** Implemented  
**Addresses:** Dallas decision `2026-04-03T07-21-52Z-dallas-cross-domain-cookie-fix.md` — Option C

---

## What Was Changed

### 1. Auth cookies — `services/api/src/api/routes/auth.py`

Both `set_cookie()` calls (callback + logout) use:

```python
response.set_cookie(
    auth.session_cookie_name,
    session_id,
    httponly=True,
    secure=True,
    samesite="none",   # ← allows cross-origin cookie sending
    max_age=auth.session_ttl_seconds,
    path="/",
)
```

`SameSite=None` tells browsers this cookie may be sent on cross-site requests. `Secure=True` enforces HTTPS — the cookie is never sent over plain HTTP.

### 2. CORS middleware — `services/api/src/api/main.py`

```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.api.cors_origins,
    allow_origin_regex=settings.api.cors_origin_regex,  # ^https://.*\.azurestaticapps\.net$
    allow_credentials=True,    # ← required for cross-origin cookies
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["Content-Type", "Authorization", "Cookie", "X-Correlation-ID"],
    expose_headers=["X-Correlation-ID"],
)
```

`allow_credentials=True` causes the API to emit `Access-Control-Allow-Credentials: true`. This is required alongside `credentials: 'include'` on the frontend. Note: `allow_origin_regex` is used for `*.azurestaticapps.net` — exact wildcard origins are not supported when credentials are in use, so regex is the correct approach.

### 3. CORS origin config — `services/shared/shared/config.py`

Default origins include the SWA production URL. The regex `^https://.*\.azurestaticapps\.net$` covers all SWA preview environments automatically without needing per-PR configuration.

```python
cors_origins: list[str] = Field(
    default=[
        "http://localhost:3000",
        "http://localhost:3001",
        "https://web.yt-summarizer.apps.ashleyhollis.com",
        "https://web-stg.yt-summarizer.apps.ashleyhollis.com",
        "https://proud-hill-0940e7300.6.azurestaticapps.net",
    ],
)
cors_origin_regex: str | None = Field(
    default=r"^https://.*\.azurestaticapps\.net$",
)
```

### 4. k8s preview overlay — `k8s/overlays/preview/kustomization.yaml`

The CI-generated preview overlay patches `API__CORS_ORIGINS` with the PR-specific SWA URL. The regex covers the rest.

---

## Why SameSite=None; Secure Is the Right Choice

The app is **inherently cross-origin**:
- SWA lives on `*.azurestaticapps.net`
- AKS API lives on `*.yt-summarizer.apps.ashleyhollis.com`

These are different registrable domains. `SameSite=Lax` (browser default) blocks cross-site subresource requests — exactly what happens when the SWA frontend calls `/api/auth/me` after the Auth0 callback sets a cookie on the API domain.

`SameSite=None; Secure` is the W3C-standard mechanism for this scenario. Security is maintained by:
- `Secure` — HTTPS-only, never sent over HTTP
- `HttpOnly` — JavaScript cannot read the cookie
- `Access-Control-Allow-Credentials: true` only for allowlisted origins (not `*`)

## Tradeoffs

| Concern | Mitigation |
|---------|-----------|
| `SameSite=None` cookies sent to any cross-site that includes the API URL | `HttpOnly` + `Secure` + CORS allowlist prevents exploitation |
| `secure=True` breaks local dev (HTTP) | Dev uses Aspire on localhost — cookie not set over HTTP in practice. Dev can use token auth or disable secure flag via env var if needed |
| Browser support | All modern browsers support `SameSite=None; Secure` since 2020 |

## Remaining Work (Lambert)

Frontend must add `credentials: 'include'` to all cross-origin API fetch calls. Without this, browsers won't send the cookie even with `SameSite=None`. See Dallas decision for details.
