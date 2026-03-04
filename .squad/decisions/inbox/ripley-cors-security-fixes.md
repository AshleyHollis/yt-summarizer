# Decision: CORS & Security Headers Middleware (Ripley, 2026-03-05)

## Context
After AKS cluster rebuild, CORS preflight requests returned 400 (blocking all browser→API calls) and no security headers were present.

## Decisions

### 1. Middleware ordering convention
**CORSMiddleware must always be the LAST `add_middleware()` call** so it's outermost in the stack. `BaseHTTPMiddleware` subclasses (like CorrelationIdMiddleware) must be added before CORS. This is a Starlette/FastAPI platform constraint — violating it breaks OPTIONS preflight.

### 2. Explicit CORS methods/headers
Changed from wildcard `*` to explicit lists: `GET, POST, PUT, DELETE, OPTIONS, PATCH` and `Content-Type, Authorization, Cookie, X-Correlation-ID`. This makes the API contract clearer and follows principle of least privilege. If new methods/headers are needed, they must be added explicitly.

### 3. Security headers via middleware
Added `SecurityHeadersMiddleware` applying HSTS, X-Content-Type-Options, X-Frame-Options, CSP (`default-src 'self'`), and Referrer-Policy. CSP is intentionally minimal — if the API starts serving HTML or scripts, CSP will need loosening.

### 4. SWA origin in explicit list
Added `https://white-meadow-0b8e2e000.6.azurestaticapps.net` to `cors_origins` default list alongside the regex `^https://.*\.azurestaticapps\.net$`. Belt-and-suspenders approach for the primary frontend URL.

## Action needed (not code)
- Set `AUTH0_DEFAULT_RETURN_TO=https://white-meadow-0b8e2e000.6.azurestaticapps.net` in K8s deployment env vars
- Once custom domain `web.yt-summarizer.apps.ashleyhollis.com` is re-pointed to SWA, update the env var
