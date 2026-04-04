# Dallas — History

## Project Context
- **Project**: YT Summarizer — YouTube video knowledge library
- **Stack**: Next.js, Python/FastAPI, .NET Aspire, AKS/ArgoCD, Terraform, Auth0
- **User**: Ashley Hollis

## Learnings
<!-- Append learnings below -->

### 2026-01-09 — Region/Cluster Audit (AKS rebuild)

- **Deployed region is East Asia** (`rg-ytsumm-prd-ci`, `aks-ytsumm-prd-ci`, SWA hostnames all confirm `eastasia`). The Terraform root `variables.tf` still defaults `location = "eastus"` but prod reads region dynamically from `module.shared.resource_group_location` — so this default is not dangerous but misleading.
- **Old IP `20.255.113.149` is hardcoded live** in `k8s/argocd/gateway-api/nginx-gateway-fabric.yaml` as an Azure LB annotation. This is the single most dangerous stale reference — it pins the new cluster's LoadBalancer to an IP that no longer exists in the new region.
- **KV secret version GUIDs are hardcoded** in `infra/terraform/environments/prod/key-vault.tf` import blocks. If KV was recreated, these will fail.
- **GitHub variable `PRODUCTION_URL` has a placeholder default** in `deploy-prod.yml` (`https://api.yt-summarizer.example.com`). If the repo variable isn't set, smoke tests and frontend deployments will point nowhere.
- **`k8s/overlays/preview/kustomization.yaml`** has PR-127-specific SWA hostnames baked into CORS_ORIGINS. This is a "frozen template" file that CI should be patching — but it's a latent bug if CI ever skips the patch step.
- ACR (`acrytsummprdci`), SWA (`swa-ytsumm-prd`), and DNS domain (`*.yt-summarizer.apps.ashleyhollis.com`) appear stable and not region-tied — low risk.
- Full audit written to `.squad/decisions/inbox/dallas-region-audit.md`.

### 2026-04-03 — Cross-Domain Cookie Fix Architecture Decision

- **Root cause confirmed**: Preview SWA frontend (`*.azurestaticapps.net`) and AKS API (`api-pr-N.yt-summarizer.apps.ashleyhollis.com`) are different origins. Auth cookies set by BFF callback on API domain are not sent on cross-origin fetch from SWA domain due to default `SameSite=Lax`.
- **~80% of E2E tests skipped** via `test.fixme(!!process.env.CI, 'Cross-domain cookie issue...')` across auth, RBAC, library, copilot, queue, channel-ingest, synthesis specs.
- **Next.js rewrites already exist** in `next.config.ts` (`/api/*` → backend) but are unused — SWA intercepts `/api/*` as Azure Functions routes, and client-side code calls `getClientApiUrl()` which returns the direct API URL (bypassing proxy).
- **Recommended Option C**: `SameSite=None; Secure` cookies + CORS `Access-Control-Allow-Credentials: true` + frontend `credentials: 'include'`. This is the architecturally correct fix for an inherently cross-origin app.
- **Quick-win Option D**: Inject `appSession` cookies for SWA domain in Playwright `auth.setup.ts` to unblock CI immediately.
- **Option B (shared custom domain) not feasible**: SWA preview environments get auto-generated URLs; custom domains on previews are not a standard SWA capability.
- Decision written to `.squad/decisions/inbox/2026-04-03T07-21-52Z-dallas-cross-domain-cookie-fix.md`.
