# Dallas — Region/Cluster Audit
**Date:** 2026-01-09  
**Author:** Dallas (Lead)  
**Trigger:** AKS cluster rebuilt in new Azure region. Audit for stale references.

---

## Summary

The cluster was rebuilt in **East Asia** (based on all Terraform and runbook evidence). The old load balancer IP was `20.255.113.149`; the current Gateway IP is `20.187.186.135`. The domain stack (`*.yt-summarizer.apps.ashleyhollis.com`) appears correct and live. Key risks are: (1) **hardcoded old IP in nginx-gateway-fabric ArgoCD app**, (2) **hardcoded KV secret version IDs** that will break if KV was recreated, (3) **stale preview kustomization** with a specific old PR's SWA hostname baked in.

---

## 1. IP Addresses — Findings

### 🔴 CRITICAL: Old IP hardcoded in live K8s config

| File | Line | Current Value | Status | Should Be |
|------|------|---------------|--------|-----------|
| `k8s/argocd/gateway-api/nginx-gateway-fabric.yaml` | 31 | `service.beta.kubernetes.io/azure-load-balancer-ipv4: "20.255.113.149"` | **STALE — this pins the load balancer to the old IP** | Remove annotation entirely, or update to new IP. Azure should assign dynamically unless pinned. |

### ✅ Old IP in documentation only (safe — historical record)

| File | Line | Notes |
|------|------|-------|
| `docs/runbooks/production-deployment.md` | 24 | Runbook table shows `20.255.113.149` as "Ingress Controller IP" — **stale, needs update** |
| `docs/runbooks/production-deployment.md` | 99–100 | DNS table references old IP — **stale** |
| `DEPLOYMENT-AUDIT-FINDINGS.md` | 36, 95, 102 | Documents the old IP — historical record, low risk |
| `specs/003-preview-dns-cloudflare/tasks.md` | 23, 71 | Historical task notes — safe |
| `specs/003-preview-dns-cloudflare/IMPLEMENTATION_COMPLETE.md` | 115, 116 | Historical — safe |

### ✅ Current IP (`20.187.186.135`) — correctly referenced

Found in: `DEPLOYMENT-AUDIT-FINDINGS.md`, `MIGRATION-LOG.md`, `specs/003-preview-dns-cloudflare/`, `docs/runbooks/external-dns-troubleshooting.md` — all appear to be current documentation.

---

## 2. Cluster Names — Findings

Cluster name in use: **`aks-ytsumm-prd-ci`**

| File | Line | Value | Status |
|------|------|-------|--------|
| `infra/terraform/environments/prod/notes.tf` | 11 | `az aks get-credentials --resource-group rg-ytsumm-prd-ci --name aks-ytsumm-prd-ci` | Correct (comment) |
| `scripts/bootstrap-argocd.ps1` | 17 | same command | Correct |
| `scripts/setup-argocd-github-app.ps1` | 48 | same command | Correct |
| `.github/workflows/deploy-prod.yml` | 167 | `vars.AKS_CLUSTER_NAME \|\| 'aks-ytsumm-prd-ci'` | **Correct default** — if GitHub variable `AKS_CLUSTER_NAME` is set, it overrides |
| `.github/workflows/preview.yml` | 375 | same pattern | **Correct default** |
| `k8s/argocd/external-dns/deployment.yaml` | 32 | `--txt-owner-id=yt-summarizer-aks` | ✅ This is the ExternalDNS TXT record owner label — **NOT** the cluster name; OK but verify it matches what's in Cloudflare TXT records |

**Action for Parker/Ripley:** Confirm GitHub repo variable `AKS_CLUSTER_NAME` is set correctly (or matches the new cluster name). If the cluster was renamed during the rebuild, the default `aks-ytsumm-prd-ci` may be wrong.

---

## 3. Resource Group Names — Findings

Resource group in use: **`rg-ytsumm-prd-ci`**

This name appears consistently across all files. If the cluster was rebuilt into the **same resource group**, no changes needed. If a new resource group was created, every reference below needs updating.

| File | Line | Value | Notes |
|------|------|-------|-------|
| `infra/terraform/environments/prod/shared.tf` | 4 | `resource_group_name = "rg-ytsumm-prd-ci"` | **LIVE CONFIG** — drives Terraform data lookup |
| `infra/terraform/environments/prod/notes.tf` | 11 | comment reference | safe |
| `.github/workflows/deploy-prod.yml` | 166 | `vars.AZURE_RESOURCE_GROUP \|\| 'rg-ytsumm-prd-ci'` | Default — verify GitHub variable |
| `.github/workflows/deploy-frontend-swa.yml` | 140, 224 | same pattern | Default |
| `.github/workflows/preview.yml` | 374 | same pattern | Default |
| `docs/runbooks/production-deployment.md` | 10 | Table row: "East Asia" region listed | **Runbook data needs review** |
| Multiple `*.md` files | various | Documentation references | Low priority |

**`rg-ytsummarizer-tfstate`** (Terraform state RG) — referenced in `infra/terraform/backend.tf` (commented out) and `infra/terraform/environments/prod/backend.tf` — this is the state storage RG, separate from the app RG. Verify it still exists.

---

## 4. Region References — Findings

### Terraform default region

| File | Line | Value | Status |
|------|------|-------|--------|
| `infra/terraform/variables.tf` | 38 | `default = "eastus"` | ⚠️ **MISMATCH** — the deployed cluster is in East Asia, but the root module variables default to `eastus`. The prod environment uses `module.shared.resource_group_location` (dynamically read), so this may be unused in prod — but worth confirming. |

### SWA hostnames confirming East Asia region

All Static Web App preview URLs follow the pattern `*.eastasia.6.azurestaticapps.net`, confirming the SWA is provisioned in East Asia. These appear in:
- `k8s/overlays/preview/kustomization.yaml` — **⚠️ STALE VALUES (see Section 9)**
- `infra/terraform/environments/prod/variables.tf` line 145 — SWA callback URL for `red-grass-06d413100-64.eastasia...`
- Multiple `*.md` files — documentation

### Runbook region label

`docs/runbooks/production-deployment.md` line 10 lists resource group region as **"East Asia"** — this should be verified against the actual new region after rebuild.

---

## 5. DNS / Domain References — Findings

### ✅ Primary domain — consistent and current

`*.yt-summarizer.apps.ashleyhollis.com` references are consistent across:
- `k8s/base/api-httproute.yaml` — correct
- `k8s/argocd/gateway-api/gateway.yaml` — correct
- `k8s/argocd/certificates/yt-summarizer-wildcard.yaml` — correct
- `k8s/overlays/prod/kustomization.yaml` — correct
- `scripts/ci/templates/prod-kustomization-template.yaml` — correct
- `infra/terraform/environments/prod/variables.tf` — correct (Auth0 callbacks)

### ⚠️ Old domain `ytsummarizer.dev` in cert-manager ClusterIssuers

| File | Line | Value | Status |
|------|------|-------|--------|
| `k8s/argocd/cert-manager/clusterissuer-staging.yaml` | 9 | `email: ops@ytsummarizer.dev` | ⚠️ Uses old domain for Let's Encrypt registration email. Functionally OK (ACME doesn't verify), but stale |
| `k8s/argocd/cert-manager/clusterissuer-prod.yaml` | 8 | `email: ops@ytsummarizer.dev` | Same |

---

## 6. Auth0 Configuration — Findings

Auth0 callback URLs are managed via `infra/terraform/environments/prod/variables.tf`. All current API domain callbacks use `*.yt-summarizer.apps.ashleyhollis.com` which looks correct. However:

### ⚠️ Hardcoded staging SWA URL in Auth0 callback list

| File | Line | Value | Status |
|------|------|-------|--------|
| `infra/terraform/environments/prod/variables.tf` | 145 | `https://red-grass-06d413100-64.eastasia.6.azurestaticapps.net/api/auth/callback` | ⚠️ This is a specific SWA staging slot URL. If the SWA was recreated (new hostname), this needs updating. The `eastasia` subdomain indicates it's provisioned in East Asia — verify this URL still works. |

The production SWA appears to use the canonical URL via `web.yt-summarizer.apps.ashleyhollis.com` (custom domain), so the SWA hostname in Auth0 is a fallback for the Azure-assigned URL. **Confirm the SWA resource `swa-ytsumm-prd` was NOT recreated during the cluster rebuild** (SWA is separate from AKS).

---

## 7. Key Vault References — Findings

Key Vault in use: **`kv-ytsumm-prd-ci`**

### ✅ KV name consistent

All references (`k8s/overlays/prod-secretstore/`, `k8s/cluster-resources/`, `k8s/base/`, `infra/terraform/environments/prod/shared.tf`) consistently reference `kv-ytsumm-prd-ci`.

### 🔴 CRITICAL: Hardcoded secret version IDs

`infra/terraform/environments/prod/key-vault.tf` contains `import` blocks with **hardcoded secret version GUIDs**:

```
id = "https://kv-ytsumm-prd-ci.vault.azure.net/secrets/sql-connection-string/794fc0ef377d4263a2d63db0b7aff6d6"
id = "https://kv-ytsumm-prd-ci.vault.azure.net/secrets/storage-connection/4b95c33133f64a44b32aa8eec18fbd0a"
... (8 more secrets with hardcoded version IDs)
```

**If the Key Vault was recreated during the cluster rebuild, these version IDs are invalid.** Terraform import will fail or reference deleted secret versions. These were added after a partial-apply incident (comment says "2026-03-04"). Verify the KV still exists and secrets are at these version IDs, or remove the import blocks and re-import.

---

## 8. ACR References — Findings

ACR in use: **`acrytsummprdci.azurecr.io`**

| File | Line | Value | Status |
|------|------|-------|--------|
| `k8s/overlays/prod/kustomization.yaml` | 22, 25 | `acrytsummprdci.azurecr.io/yt-summarizer-api` etc. | ✅ Consistent |
| `k8s/overlays/preview/kustomization.yaml` | 28, 31 | same | ✅ Consistent |
| `scripts/ci/templates/prod-kustomization-template.yaml` | 19, 22 | same | ✅ Consistent |
| `.github/workflows/deploy-prod.yml` | 74–75 | `vars.ACR_NAME \|\| 'acrytsummprdci'` and `vars.ACR_LOGIN_SERVER \|\| 'acrytsummprdci.azurecr.io'` | ✅ Uses GitHub variable with correct default |
| `.github/workflows/preview.yml` | 72–73 | same | ✅ |
| `.github/workflows/preview-cleanup.yml` | 160 | same | ✅ |

ACR is **global** (not region-bound per se) and was likely not recreated with the cluster. Should be fine, but confirm `acrytsummprdci` is still the correct registry name.

---

## 9. Database / Connection Strings — Findings

Database server referenced: **`sql-ytsumm-prd.database.windows.net`** (from `docs/runbooks/production-deployment.md`)

Connection strings flow through Key Vault → ExternalSecrets → K8s Secret. No hardcoded connection strings were found in K8s manifests or application code.

| File | Notes |
|------|-------|
| `k8s/base/externalsecret-db.yaml` | Pulls `sql-connection-string` from KV — ✅ correct pattern |
| `infra/terraform/modules/sql-database/main.tf` | Generates connection string dynamically from `azurerm_mssql_server.server.fully_qualified_domain_name` — ✅ |
| `docker-compose.ci.yml` | Uses local `mssql:1433` — CI only, not production |

**If the SQL Server was recreated** during the cluster rebuild (it shouldn't be — it's not in AKS), the KV `sql-connection-string` secret needs to be updated. This is the most likely break point if anything was recreated.

---

## 10. GitHub Actions Secrets/Variables — Reference List

### Secrets (must exist in GitHub repo)
- `AZURE_CLIENT_ID` — OIDC federated credential client ID
- `AZURE_TENANT_ID`
- `AZURE_SUBSCRIPTION_ID`
- `SWA_DEPLOYMENT_TOKEN` — Static Web App deploy token
- `DEPLOY_APP_ID` / `DEPLOY_APP_PRIVATE_KEY` — GitHub App for ArgoCD GitOps
- `AUTH0_DOMAIN` / `AUTH0_CLIENT_ID` / `AUTH0_CLIENT_SECRET`
- `AUTH0_SECRET` / `AUTH0_ISSUER_BASE_URL`
- `AUTH0_ADMIN_TEST_EMAIL` / `AUTH0_ADMIN_TEST_PASSWORD`
- `AUTH0_USER_TEST_EMAIL` / `AUTH0_USER_TEST_PASSWORD`
- `COPILOT_ASSIGN_TOKEN`

### Variables (override defaults — these may need updating post-rebuild)
| Variable | Default in code | Notes |
|----------|----------------|-------|
| `AKS_CLUSTER_NAME` | `aks-ytsumm-prd-ci` | **Verify this matches the new cluster name** |
| `AZURE_RESOURCE_GROUP` | `rg-ytsumm-prd-ci` | **Verify this matches the new RG** |
| `ACR_NAME` | `acrytsummprdci` | Should be unchanged |
| `ACR_LOGIN_SERVER` | `acrytsummprdci.azurecr.io` | Should be unchanged |
| `PRODUCTION_URL` | `https://api.yt-summarizer.example.com` ⚠️ | **The default is a placeholder! Must be set to `https://api.yt-summarizer.apps.ashleyhollis.com`** |
| `PRODUCTION_API_URL` | falls back to `PRODUCTION_URL` | Same issue |
| `SWA_NAME` | `swa-ytsumm-prd` | Should be unchanged |
| `TERRAFORM_VERSION` | `1.9` | OK |
| `CLEANUP_PR_IMAGES` | — | Optional |

---

## 11. Stale Preview Kustomization — Findings

### 🔴 STALE: PR-specific values baked into preview overlay

`k8s/overlays/preview/kustomization.yaml` contains values specific to **PR #127**:

| Line | Value | Status |
|------|-------|--------|
| 3 | `# Image: acrytsummprdci.azurecr.io/api:pr-127-255b90f` | Comment only — OK |
| 4 | `# Preview Host: api-pr-127.yt-summarizer.apps.ashleyhollis.com` | Comment only — OK |
| 82 | `CORS_ORIGINS: "https://red-grass-06d413100-127.eastasia.6.azurestaticapps.net"` | **⚠️ LIVE CONFIG with PR-127-specific SWA URL** |
| 101 | `'["https://red-grass-06d413100-127.eastasia.6.azurestaticapps.net","http://localhost:3000"]'` | **⚠️ Same** |
| 113–116 | `api-pr-127.yt-summarizer...` hostname | **⚠️ PR-127 hostname** |

This overlay is used as a template base — the CI script should be overwriting these values via `prod-kustomization-template.yaml` + `kustomize edit`. Confirm the CI pipeline patches these correctly before deployment, as the static file still has PR-127 values.

---

## Priority Action Items for Parker / Ripley

| Priority | Item | File | Action |
|----------|------|------|--------|
| 🔴 P0 | Old IP hardcoded in nginx-gateway-fabric | `k8s/argocd/gateway-api/nginx-gateway-fabric.yaml:31` | Remove `azure-load-balancer-ipv4` annotation OR update to new IP |
| 🔴 P0 | KV secret version IDs — may be invalid post-rebuild | `infra/terraform/environments/prod/key-vault.tf` | Verify KV exists with same secret versions; update or re-import if not |
| 🔴 P0 | `PRODUCTION_URL` GitHub variable has placeholder default | `.github/workflows/deploy-prod.yml:80` | Confirm repo variable is set to actual prod URL |
| 🟡 P1 | Verify GitHub vars `AKS_CLUSTER_NAME`, `AZURE_RESOURCE_GROUP` match new cluster | GitHub repo settings | Manual check |
| 🟡 P1 | Runbook has stale IP and region data | `docs/runbooks/production-deployment.md` | Update IP (`20.255.113.149` → `20.187.186.135`) and verify region row |
| 🟡 P1 | Terraform `variables.tf` `location` default is `eastus`, cluster is East Asia | `infra/terraform/variables.tf:38` | Confirm prod uses dynamic location from shared module (not this default) |
| 🟢 P2 | Stale preview kustomization with PR-127 SWA URLs | `k8s/overlays/preview/kustomization.yaml:82,101` | Confirm CI patches these; or reset to a placeholder |
| 🟢 P2 | cert-manager ClusterIssuer ACME email uses old domain | `k8s/argocd/cert-manager/clusterissuer-*.yaml` | Update `ops@ytsummarizer.dev` to a valid email if needed |
