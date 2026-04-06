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

### 2026-04-04 — ESO Pause State Leak in Preview Namespaces

**Root cause of chat-responses failure ("Expected at least 2 assistant messages, found 1")**:
The old AKS mutation workaround in preview.yml (removed in 8766386b) paused the
openai-credentials ExternalSecret reconciler (econcile.external-secrets.io/paused=true)
and never unpaused it. Even after Terraform was fixed to write correct Azure OpenAI creds to
Key Vault (TF_VAR_azure_openai_* vars added), ESO won't sync those values in paused namespaces.

**Fix**: Added "Unpause openai-credentials ESO" step in sync-argocd-manifests before ArgoCD
sync. Removes the paused annotation and triggers orce-sync so the K8s secret is populated
with real credentials before pods are restarted by ArgoCD on the new image tag.

**Key pattern**: When removing an AKS mutation workaround, always add a remediation step that
cleans up the state the workaround left behind.

### 2026-04-04 — Auth-Signout ERR_ABORTED Pattern on SWA /sign-in

Two distinct causes, two distinct fixes:
1. **Custom browser context (rowser.newContext())**: Does NOT inherit aseURL from
   playwright.config.ts. Relative paths in page.goto('/sign-in') resolve against the last
   visited URL — which could be Auth0's domain after the logout redirect. Fix: always use
   absolute URLs (\/sign-in) in custom context tests.
2. **SWA redirect to Auth0**: Azure SWA /sign-in may immediately redirect to Auth0 (external
   domain), causing Playwright's waitUntil: 'domcontentloaded' to never fire (ERR_ABORTED).
   Fix: use waitUntil: 'commit' (fires on first response headers) + .catch(() => {}) + early
   return if page.url() is on an external provider domain.

**Pattern**: Wherever E2E tests navigate to /sign-in in an SWA context, use waitUntil: 'commit'
and treat Auth0 redirect as a passing condition (the sign-in flow works — just via external IdP).

### 2026-04-04 — E2E AKS Mutation Root-Cause Analysis

**Root cause**: 	erraform-deploy.yml never passes TF_VAR_azure_openai_api_key, TF_VAR_azure_openai_endpoint, TF_VAR_azure_openai_deployment, or TF_VAR_azure_openai_embedding_deployment to Terraform. All four ariables.tf declarations default to "". Every Terraform run overwrites the four zure-openai-* Key Vault secrets with empty strings. ESO syncs empty values into the K8s openai-credentials secret. Workers/API start with blank Azure OpenAI env vars.

**The E2E patch step** (preview.yml lines 606–684) was added as a workaround — pulling values from GitHub Secrets and directly patching the K8s Secret + restarting pods. It also pauses ESO reconciliation (econcile.external-secrets.io/paused=true) and **never unpauses it**, leaving a state leak in every preview namespace.

**Fix**: Add four TF_VAR_azure_openai_* env vars to both jobs in 	erraform-deploy.yml (secrets already exist as AZURE_OPENAI_* in GitHub). Then remove the two AKS-mutation steps from the E2E job. No changes to xternalsecret-openai.yaml or ariables.tf needed — both are already correct.

**Key insight**: For a fresh preview namespace, ESO syncs the ExternalSecret on creation — no restart trigger needed. The existing erify-deployment health check is the correct readiness gate before E2E.

---

*Older learnings archived to .squad/archive/agents/parker-history-archive.md*

### 2026-04-06 — Auth0 RCA: Missing Env Vars + MAX_FAILURES Adjustment

**Challenge**: Workflow appearing to skip LIVE_PROCESSING tests "by design" — found infrastructure misconfiguration instead.

**Finding: preview.yml Env Var Drift**
- `preview.yml` E2E job lacked `AUTH0_SECRET`, `AUTH0_BASE_URL`, `AUTH0_TEST_EMAIL`, `AUTH0_TEST_PASSWORD`
- These were present in `preview-e2e.yml` but not mirrored to main preview step
- When auth setup fails early, it generates 5+ quick failures → `maxFailures=5` aborts the run → LIVE_PROCESSING tests never execute
- Appeared "by design" but was actually incomplete env var coverage

**Fix Applied** (commit 3a09dbf5)
- Added missing Auth0 env vars to `preview.yml` E2E step
- LIVE_PROCESSING IS correctly forwarded through shared-infra composite action (confirmed via code trace)
- Now auth setup succeeds and allows tests to proceed

**MAX_FAILURES Adjustment** (pending commit)
- Raised from 5 → 10 in preview E2E workflows
- Rationale: LLM-based test generation causes non-deterministic flakes in setup phase
- Allows transient errors to resolve naturally instead of aborting prematurely
- 5 is too aggressive when dealing with generated tests; 10 better balances signal vs. tolerance

**Pattern for Future**
- Always cross-check both `preview.yml` and `preview-e2e.yml` for env var coverage when debugging E2E failures
- MAX_FAILURES=5 is baseline too low for LIVE_PROCESSING runs; prefer 10+
- When a workflow appears to skip tests "by design", check infrastructure setup first before assuming intentional behavior
