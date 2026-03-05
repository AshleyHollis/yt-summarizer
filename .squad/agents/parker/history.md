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

### 2026-03-05 — Preview PR-177 Infrastructure Audit

**Secrets (all synced via ExternalSecret → azure-keyvault-cluster ClusterSecretStore):**
- `auth0-credentials` — keys: `client-id`, `client-secret`, `domain`, `session-secret` ✅
- `db-credentials` — keys: `connection-string` ✅
- `openai-credentials` — keys: `api-key`, `azure-api-key`, `azure-deployment`, `azure-embedding-deployment`, `azure-endpoint` ✅
- `proxy-credentials` — keys: `username`, `password` ✅ (populated; note historically was empty in prod)
- `storage-credentials` — keys: `connection-string` (single string covers blob + queue) ✅

**Pods — all 5 Running, 0 restarts:**
- `api`, `transcribe-worker`, `summarize-worker`, `embed-worker`, `relationships-worker` all `1/1 Running` ✅

**Worker env vars:**
- `transcribe-worker`: DATABASE_URL, AZURE_STORAGE_CONNECTION_STRING, OPENAI_API_KEY, PROXY_USERNAME, PROXY_PASSWORD ✅
- `summarize-worker`: DATABASE_URL, AZURE_STORAGE_CONNECTION_STRING, OPENAI_API_KEY, AZURE_OPENAI_API_KEY, AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_DEPLOYMENT ✅
- `embed-worker`: DATABASE_URL, AZURE_STORAGE_CONNECTION_STRING, OPENAI_API_KEY, AZURE_OPENAI_API_KEY, AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_EMBEDDING_DEPLOYMENT ✅
- `relationships-worker`: DATABASE_URL, AZURE_STORAGE_CONNECTION_STRING, OPENAI_API_KEY ✅ (no Azure OpenAI keys — consistent with its role using standard OpenAI only)

**Azure Storage queue connectivity (all HTTP 200 from worker logs):**
- `transcribe-jobs`, `summarize-jobs`, `embed-jobs`, `relationships-jobs` — all polling successfully ✅

**ArgoCD app `preview-pr-177`**: `Synced` + `Healthy` @ revision `b3e7c6e5` ✅

**No issues found.** Preview environment is fully functional.

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

### 2026-03-04 — Infrastructure Fixes Post-Rebuild

**Pipeline Fix (PR #169):**
- **Root cause of `Unexpected value ''`**: GitHub Actions converts boolean `false` to empty string `''` when used in `${{ }}` expressions outside `if:` conditionals. `continue-on-error: ${{ inputs.post-to-pr }}` when `post-to-pr` is `false` → `continue-on-error: ''` → YAML parse error.
- **Fix**: Changed to ternary string pattern `${{ inputs.post-to-pr && 'true' || 'false' }}` which always produces a valid boolean string.

**Key Vault RBAC Fix (Azure CLI):**
- The `github-actions-yt-summarizer` SP (OID: `0a8480bd-2b41-449f-b16e-badd5616ae15`) had NO Key Vault role assignment after the cluster rebuild. Terraform plan failed with 403 ForbiddenByRbac on ALL Key Vault secret reads.
- **Fix**: Granted `Key Vault Secrets Officer` role on `kv-ytsumm-prd-ci` via `az role assignment create`. This is a bootstrap dependency — Terraform needs KV access to run, so it can't self-provision this role.

**Infrastructure Audit — All Configs Aligned to New Region (centralindia):**
- Cluster: `aks-ytsumm-prd-ci` in `centralindia` ✓
- ACR: `acrytsummprdci` in `centralindia` ✓
- Key Vault: `kv-ytsumm-prd-ci` in `centralindia` ✓
- DNS: `api.yt-summarizer.apps.ashleyhollis.com` → `135.235.188.138` ✓
- Gateway IP: `135.235.188.138` ✓
- All workflow files use parameterized `${{ vars.X || 'default' }}` pattern with correct defaults ✓
- SecretStore/ClusterSecretStore reference correct Key Vault URL ✓
- Workload Identity client ID matches across K8s manifests and deployed SA ✓
- No hardcoded old-region references found in active configs (only in `INFRASTRUCTURE_ISSUES.md` doc)

**SWA Situation:**
- `swa-ytsumm-prd` does NOT exist in Azure — resource destroyed during rebuild, not yet recreated.
- SWA is defined in Terraform (`swa.tf`). Once the fixed pipeline runs Terraform, it will create the new SWA.
- After creation, `SWA_DEPLOYMENT_TOKEN` GitHub secret needs updating with the new SWA API key (from Terraform output `swa_api_key`).
- Stale SWA callback URL in `variables.tf` (`red-grass-06d413100-64.eastasia.6.azurestaticapps.net`) — harmless, will be replaced when new SWA is created.

**ExternalSecret Configs — Correct, Data Issue Only:**
- All SecretStore/ClusterSecretStore configs reference `kv-ytsumm-prd-ci` correctly.
- All ExternalSecrets report `SecretSynced: True` / `Ready`.
- Proxy credentials (`webshare-proxy-username`, `webshare-proxy-password`) are empty strings in Key Vault — manual population required by Ashley via Azure Portal/CLI.
- transcribe-worker is in Error state (was CrashLoopBackOff) due to empty proxy credentials.
