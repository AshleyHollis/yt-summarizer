# Research: Azure CI/CD Pipelines

**Status**: Implementing
**Milestone**: M2
**Spec Phase**: execution
**Created**: 2026-01-08
**Updated**: 2026-01-09

---

## Research Tasks

### 1. GitHub Actions for Monorepo CI

**Question**: How to efficiently run tests only for changed components in a monorepo?

**Decision**: Use path filters with job dependencies

**Rationale**:
- GitHub Actions supports `paths` filters in workflow triggers
- Jobs can be conditionally skipped based on changed files using `dorny/paths-filter`
- For this project, always run all tests on PR (comprehensive) but use path filters for quick feedback
- Shared package changes trigger all downstream tests

**Alternatives Considered**:
- Nx/Turborepo for task orchestration — Rejected: adds complexity for a 3-service monorepo
- Always run everything — Accepted for simplicity; optimize later if CI time exceeds 15 min target

---

### 2. AKS Single-Node with GitOps (Revised from ACA)

**Question**: How to deploy API and Workers cost-effectively for a hobby project?

**Decision**: AKS single-node cluster with Argo CD GitOps

**Rationale**:
- ACA with multiple apps = $15-50+/month variable
- AKS single-node (B2s) = ~$30/month fixed, predictable
- All services run in one cluster (API, Workers as Deployments)
- GitOps (Argo CD) watches repo, auto-deploys on manifest changes
- Rollback = `git revert` or Argo CD UI rollback

**Cost Breakdown**:
```
AKS Control Plane:  $0 (free tier)
Node (B2s VM):     ~$30/month
ACR (Basic):       ~$5/month
Total:             ~$35/month fixed
```

**Alternatives Considered**:
- ACA — Rejected: Variable cost, multiple apps add up
- k3s on VM — Rejected: More manual management
- Full AKS multi-node — Rejected: Overkill for hobby project

---

### 3. Argo CD for GitOps

**Question**: Which GitOps tool for Kubernetes deployments?

**Decision**: Argo CD with Pull Request Generator for PR previews

**Rationale**:
- Web UI for monitoring deployments and troubleshooting
- Visual diff of desired vs live state
- One-click rollback
- Health status aggregation across resources
- Pull Request Generator allows Argo CD to auto-discover open PRs via GitHub API and create preview Applications
- Active community, well-documented

**Alternatives Considered**:
- Flux — Rejected: No UI, harder to troubleshoot

---

### 4. Kustomize for K8s Manifests

**Question**: How to manage Kubernetes manifests with environment variations?

**Decision**: Kustomize with base + overlays

**Rationale**:
- Built into kubectl (`kubectl apply -k`)
- No templating language to learn (unlike Helm)
- Simple patching for environment differences
- Native K8s — no external tool installation
- Preview overlays live in PR branches (not main); prod overlay lives in main

**Directory Structure**:
```
k8s/
├── base/                    # Shared manifests
│   ├── kustomization.yaml
│   ├── namespace.yaml
│   ├── api-deployment.yaml
│   ├── api-service.yaml
│   ├── api-ingress.yaml
│   ├── *-worker-deployment.yaml
│   ├── configmap.yaml
│   └── externalsecret-*.yaml
├── overlays/
│   ├── prod/                # Production overlay (main branch)
│   │   ├── kustomization.yaml
│   │   └── patches/
│   └── previews/
│       └── _template/       # Template for PR overlays
│           ├── kustomization.yaml
│           ├── namespace.yaml
│           ├── resource-quota.yaml
│           ├── limit-range.yaml
│           └── patches/
```

**Alternatives Considered**:
- Helm — Rejected: More complex for small project

---

### 5. Azure Static Web Apps CI/CD

**Question**: How to integrate SWA with GitHub Actions and coordinate with backend?

**Decision**: Use SWA's built-in GitHub Action with deployment slots

**Rationale**:
- Azure provides `Azure/static-web-apps-deploy@v1` action
- Staging slot for PR preview, production slot for live
- SWA handles Next.js build internally
- Backend URL injected at build time via environment variables
- HTTPS provided automatically by SWA (no certificate management)

**Alternatives Considered**:
- Build externally and upload — Rejected: Loses SWA build optimizations
- Vercel — Rejected: User chose Azure-native stack

---

### 6. Terraform State Management in Azure

**Question**: How to configure Azure Storage backend for Terraform state?

**Decision**: Dedicated resource group with storage account and blob lease locking

**Configuration Pattern**:
```hcl
terraform {
  backend "azurerm" {
    resource_group_name  = "rg-ytsummarizer-tfstate"
    storage_account_name = "stytsummarizertfstate"
    container_name       = "tfstate"
    key                  = "prod.tfstate"
    use_oidc             = true
  }
}
```

---

### 7. GitHub Actions Authentication to Azure

**Question**: How to securely authenticate GitHub Actions to Azure without storing secrets?

**Decision**: OpenID Connect (OIDC) federation with Azure AD

**Rationale**:
- No secrets to rotate or leak
- GitHub Actions gets short-lived tokens via OIDC
- Azure AD app registration with federated credentials
- Separate service principals per environment for least privilege

---

### 8. Preview Hostname & TLS

**Question**: How to provide HTTPS preview URLs without per-PR certificate provisioning?

**Decision**: Shared wildcard TLS certificate via cert-manager + DNS-01 solver (Cloudflare)

**Rationale**:
- Single wildcard cert covers all PR previews (`*.yt-summarizer.apps.ashleyhollis.com`)
- No per-PR TLS issuance delay
- DNS-01 via Cloudflare API supports wildcard certificates (HTTP-01 does not)
- cert-manager manages renewal automatically

**Preview URL Pattern**: `api-pr-{number}.yt-summarizer.apps.ashleyhollis.com`

**Alternatives Considered**:
- Per-PR Let's Encrypt HTTP-01 — Rejected: Cannot issue wildcard certificates
- nip.io with per-PR certs — Rejected: Less clean URLs, still needs per-PR issuance

---

### 9. PR Preview Architecture

**Final Architecture** (Updated 2026-01-09):
- ❌ No long-lived staging environment
- ❌ No manual production approval gates
- ✅ PR Preview environments via Argo CD ApplicationSet with Pull Request Generator
- ✅ Preview overlays live in PR branches (not in main)
- ✅ Auto-deploy to production on merge to main (waits for CI to pass via `workflow_run`)
- ✅ Single `prod` overlay (replaced obsolete `staging` + `production` overlays)
- ✅ Frontend previews via Azure SWA staging environments
- ✅ CI includes `npm run build` to catch TypeScript errors

**Validated Results**:
- PR #141 preview deployed to SWA staging URL — 153 Playwright E2E tests passed (run 22490929040)
- Production deployment (run 22271246265) — all jobs succeeded including ArgoCD sync, API health checks, TLS cert verify
- GitOps rollback validated via commit `41e3cdb` (revert commit auto-synced by ArgoCD)
