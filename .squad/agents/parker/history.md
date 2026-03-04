# Parker — History

## Project Context
- **Project**: YT Summarizer — YouTube video knowledge library
- **Stack**: Terraform, AKS, ArgoCD, Azure, GitHub Actions, .NET Aspire
- **User**: Ashley Hollis

## Key Knowledge
- Auth0 PATCH /connections/{id}/clients expects array of {client_id, status: boolean} objects.
- Auth0 deprecated enabled_clients. Use GET/PATCH /api/v2/connections/{id}/clients dedicated endpoints.
- Preview hostnames: api-pr-<num>.yt-summarizer.apps.ashleyhollis.com via Cloudflare wildcard.
- Auth0 preview client needs database connection enabled via additional_database_client_ids on prod auth0 module.
- K8s migration-job can't run alembic because Docker image doesn't include alembic.ini or migration scripts.
- E2E tests use maxFailures: 5 in CI. Auth0 connection enablement step in preview.yml with continue-on-error.

## Learnings
<!-- Append learnings below -->

### 2026-03-04 — Production Deployment Verification
- **transcribe-worker crash root cause**: `proxy-credentials` K8s secret has empty `username` and `password` values. The ExternalSecret reports `SecretSynced: True`, meaning Key Vault secrets exist but contain empty strings. Fix: populate Webshare proxy credentials in Azure Key Vault (`proxy-username`, `proxy-password`).
- **Pod labels follow `app.kubernetes.io/name=<name>` pattern** — `kubectl -l app=<name>` won't match; use `app.kubernetes.io/name=<name>` selector.
- **Gateway lives in `gateway-system` namespace** (not `yt-summarizer`). Gateway IP: `135.235.188.138`. HTTPRoute lives in `yt-summarizer` namespace.
- **TLS wildcard cert** `yt-summarizer-wildcard` is issued and `True` in `gateway-system`.
- **Azure SWA `swa-ytsumm-prd`** not found in `rg-ytsumm-prd-ci` — either not yet provisioned via Terraform or deployed under a different resource group.
- **ArgoCD `yt-summarizer-prod`** is `Synced` but `Progressing` — held back by transcribe-worker crash loop.
- **Latest "Deploy to Production" run (#252) failed**: Terraform workflow YAML error — `Unexpected value ''` at `terraform-deploy.yml` line 127 (empty expression in `continue-on-error`). Likely a recently introduced template bug.
- **`/health/ready` returns HTTP 200** — API is externally reachable and healthy.
- **DNS resolves correctly**: `api.yt-summarizer.apps.ashleyhollis.com` → `135.235.188.138` ✅

**Cross-agent findings:**
- Frontend SWA (`https://white-meadow-0b8e2e000.6.azurestaticapps.net`) has no deployed content (Kane finding) — users cannot access app.
- API CORS broken, security headers missing (Ripley findings) — browser-side calls will fail, security posture degraded.
