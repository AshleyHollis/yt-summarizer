# Decisions

## 2026-03-04 — Production Deployment Verification

### Parker (DevOps)
- **transcribe-worker CrashLoopBackOff** — Root cause: Empty proxy credentials in Azure Key Vault (proxy-username, proxy-password). All transcription jobs blocked. Fix: Populate real Webshare credentials in Key Vault.
- **"Deploy to Production" pipeline failing** — Template syntax error in `.github/workflows/terraform-deploy.yml` at line 127. Empty expression likely cause. Fix: Audit and correct the expression.
- **Azure SWA not found** — `swa-ytsumm-prd` missing from `rg-ytsumm-prd-ci`. Either not provisioned or under different resource group. Action: Verify Terraform state and outputs.
- **API healthy** — Pod running, `/health/ready` returns 200 externally, database connected, TLS valid, DNS resolves, gateway routing correct.
- **ArgoCD in progress** — `yt-summarizer-prod` Synced but Progressing, blocked by transcribe-worker. Will self-resolve once proxy fixed.

### Kane (Tester)
- **Frontend SWA 404 — BLOCKER** — `https://white-meadow-0b8e2e000.6.azurestaticapps.net` has no deployed content. Azure returns native 404 page. Users cannot access application. Fix: Re-run frontend deployment pipeline or confirm SWA URL has changed.
- **API health checks pass** — `/health/ready` green, `/api/auth/session` correct (returns `isAuthenticated: false`).
- **Swagger 404 is intentional** — `/docs` disabled in production (security hardening).

### Ripley (Backend)
- **CORS preflight broken** — OPTIONS to `/api/v1/videos` with app origin returns 400, no Allow-Origin header. Browser-side API calls will fail. Fix: Verify `CORS_ORIGINS` env var includes `https://yt-summarizer.apps.ashleyhollis.com` in Kubernetes/Helm values.
- **Security headers missing** — No HSTS, X-Content-Type-Options, X-Frame-Options, or CSP. Server header exposes `nginx`. Fix: Add headers at nginx ingress (annotations/ConfigMap) or FastAPI SecurityHeadersMiddleware.
- **Worker health not exposed** — `/health/ready` only includes api and database checks. Workers (transcribe, summarize, embed, relationships) have no health representation. Recommendation: Surface workers health via Azure Queue depth or DB heartbeat if available.
- **API core healthy** — `/health/ready` all checks pass, database fully connected (live + cached), TLS cert valid until Feb 2026, response times acceptable.

## Priority Order
1. **P0 (Blockers)**: Fix transcribe-worker proxy credentials. Fix frontend SWA. Fix deploy pipeline.
2. **P1 (Breaks functionality)**: Fix CORS issue.
3. **P2 (Hardens security)**: Add security headers.
4. **P3 (Improves observability)**: Surface worker health.
