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
