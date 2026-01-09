# Implementation Plan: Azure CI/CD Pipelines

**Branch**: `002-azure-cicd` | **Date**: 2026-01-08 (Updated 2026-01-09) | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `specs/002-azure-cicd/spec.md`

## Summary

This plan implements CI/CD pipelines for the YT Summarizer application with the following flow:

1. **CI on Pull Request**: Run unit tests (shared, workers, API, frontend), linting, and validation on every PR
2. **PR Preview Environments**: Deploy ephemeral preview environments to AKS for each PR after CI passes; E2E tests run against preview URL
3. **Automatic Production Deployment**: On merge to `main`, update production Kustomize overlay with validated image digests; Argo CD syncs automatically

**Key Design Decisions**:
- **No permanent staging environment** — PR previews are the primary validation surface
- **GitOps**: Argo CD watches `k8s/overlays/prod/` for production; ApplicationSet generates preview apps from `k8s/overlays/previews/pr-*/`
- **Single-node AKS**: Cost-optimized (~$30/month) with resource quotas protecting production
- **Immutable artifacts**: Same Docker image digests validated in preview are promoted to production (no rebuild)

## Technical Context

**Language/Version**: Python 3.11 (API/Workers), TypeScript/Node 20 (Frontend)
**Primary Dependencies**: FastAPI, Next.js, Playwright, pytest, Argo CD, Kustomize
**Storage**: Azure SQL (serverless), Azure Blob Storage, Azure Storage Queue
**Testing**: pytest (Python), Vitest (Frontend unit), Playwright (E2E)
**Target Platform**: AKS (single-node), Azure Static Web Apps
**Project Type**: Monorepo (web frontend + Python backend services)

**Performance Goals**:
| Metric | Target |
|--------|--------|
| CI feedback (test results) | ≤15 minutes from PR creation/update |
| Preview environment ready | ≤10 minutes from CI passing |
| Production sync after merge | ≤10 minutes from merge to main |
| Preview cleanup after PR close | ≤5 minutes |

**Constraints**:
- Single-node AKS cluster — max 3 concurrent PR previews to avoid resource contention
- Production namespace protected with PodPriority
- Secrets never in repo or logs (GitHub Secrets + Azure Key Vault)
- All merges auto-deploy; no manual approval gates

**Scale/Scope**:
- Production environment (persistent)
- Ephemeral PR preview environments (1-3 concurrent, namespace per PR)
- Shared infrastructure (single AKS cluster, single ACR, single Azure SQL)

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Requirement | Compliance |
|-----------|-------------|------------|
| V.1 No secrets in repo | Secrets in GitHub Secrets + Azure Key Vault | ✅ OIDC auth, no secrets in overlays |
| V.2 Least-privilege | Per-environment RBAC, preview namespaces scoped | ✅ Resource quotas, limited RBAC |
| VI.3 Cost-aware defaults | AKS single-node, serverless SQL, free SWA tier | ✅ ~$35/month fixed |
| VI.4 Dev environment | Aspire for local only; AKS+Argo for production | ✅ GitOps for all deployed envs |
| IV.4 GitOps deployments | Argo CD syncs from k8s/overlays/* | ✅ Prod + preview overlays |
| II.1 Read-only copilot | Chat cannot trigger deploys | ✅ Pipelines are GitHub Actions |
| III.4 Traceability | Commit SHA + image digest on all artifacts | ✅ Tags + digest pinning |
| IV.4 Preview cleanup | Ephemeral envs auto-cleaned | ✅ On PR close, overlay deleted, Argo prunes |

**Constitution Version**: 1.0.2 (AKS + Argo CD aligned)

## Project Structure

### Documentation (this feature)

```text
specs/002-azure-cicd/
├── plan.md              # This file
├── research.md          # Phase 0 output (complete)
├── data-model.md        # N/A (no new entities)
├── quickstart.md        # Setup and usage guide (needs update)
├── contracts/           # N/A (no API contracts)
├── checklists/          # Per-task verification
└── tasks.md             # Phase 2 output (NEEDS REGENERATION)
```

### Repository Structure (Target State)

```text
.github/
└── workflows/
    ├── ci.yml               # PR: Run unit tests, linting, validation (no E2E)
    ├── preview.yml          # PR: Build images, deploy preview, E2E tests against preview URL
    ├── deploy-prod.yml      # Push to main: Pin prod overlay to merged image digests
    └── preview-cleanup.yml  # PR closed: Delete preview overlay (triggers Argo prune)

k8s/
├── base/                    # Shared manifests (unchanged)
│   ├── kustomization.yaml
│   ├── namespace.yaml
│   ├── api-deployment.yaml
│   ├── api-service.yaml
│   ├── api-ingress.yaml
│   ├── embed-worker-deployment.yaml
│   ├── summarize-worker-deployment.yaml
│   ├── transcribe-worker-deployment.yaml
│   ├── relationships-worker-deployment.yaml
│   ├── configmap.yaml
│   ├── externalsecret-*.yaml
│   └── migration-job.yaml
├── overlays/
│   ├── prod/                # Production overlay (pinned digests)
│   │   ├── kustomization.yaml
│   │   └── patches/
│   └── previews/            # Generated per PR (ephemeral)
│       └── pr-<number>/     # Created by preview.yml, deleted by preview-cleanup.yml
│           ├── kustomization.yaml
│           ├── namespace.yaml
│           └── patches/
└── argocd/
    ├── prod-app.yaml        # Production Argo Application (persistent)
    ├── preview-appset.yaml  # ApplicationSet for preview discovery
    └── repo-secret.yaml     # Git credentials (sealed)

infra/
└── terraform/
    ├── backend.tf
    ├── providers.tf           # Azure provider only (no Helm/K8s)
    ├── variables.tf
    ├── modules/
    │   ├── aks/               # AKS cluster (no add-ons installed via TF)
    │   ├── container-registry/
    │   ├── key-vault/
    │   ├── sql-database/
    │   ├── static-web-app/
    │   └── storage/
    └── environments/
        └── prod/              # Single environment (previews share infra)
            ├── main.tf
            ├── variables.tf
            └── terraform.tfvars

scripts/
└── bootstrap-argocd.ps1       # One-time Argo CD installation
```

**Structure Decision**: 
- Replaced `staging/` and `production/` overlays with `prod/` and `previews/pr-*/`
- Terraform collapsed to single `prod/` environment (previews reuse same infra, different namespaces)
- Argo CD ApplicationSet discovers preview overlays dynamically

## Terraform Scope (Azure Infrastructure Only)

**Architectural Decision**: Terraform manages Azure resources only. Helm charts and Kubernetes resources are managed by Argo CD.

| Layer | Tool | Resources |
|-------|------|-----------|
| **Azure Infrastructure** | Terraform | AKS, ACR, Azure SQL, Key Vault, Storage, SWA |
| **Cluster Bootstrap** | `scripts/bootstrap-argocd.ps1` | Argo CD installation (one-time) |
| **Cluster Infrastructure** | Argo CD | ingress-nginx, external-secrets (via Helm) |
| **Application Workloads** | Argo CD | API, Workers, migrations (via Kustomize) |

**Rationale**: See [research.md § 9. Terraform Scope](research.md#9-terraform-scope---azure-infrastructure-only)

**Removed Terraform Modules** (now managed by Argo CD):
- ~~`infra/terraform/modules/nginx-ingress/`~~
- ~~`infra/terraform/modules/external-secrets/`~~
- ~~`infra/terraform/modules/argocd/`~~

**New Argo CD Applications**:
```yaml
# k8s/argocd/infra-apps.yaml
# Manages ingress-nginx and external-secrets Helm charts
# Applied after Argo CD bootstrap
```

## Argo CD / GitOps Design

### Production Application

```yaml
# k8s/argocd/prod-app.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: yt-summarizer-prod
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/AshleyHollis/yt-summarizer
    targetRevision: main
    path: k8s/overlays/prod
  destination:
    server: https://kubernetes.default.svc
    namespace: yt-summarizer
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=true
```

### Preview ApplicationSet

```yaml
# k8s/argocd/preview-appset.yaml
apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata:
  name: yt-summarizer-previews
  namespace: argocd
spec:
  generators:
    - git:
        repoURL: https://github.com/AshleyHollis/yt-summarizer
        revision: main
        directories:
          - path: k8s/overlays/previews/pr-*
  template:
    metadata:
      name: 'preview-{{path.basename}}'
    spec:
      project: default
      source:
        repoURL: https://github.com/AshleyHollis/yt-summarizer
        targetRevision: main
        path: '{{path}}'
      destination:
        server: https://kubernetes.default.svc
        namespace: 'preview-{{path.basename}}'
      syncPolicy:
        automated:
          prune: true
          selfHeal: true
        syncOptions:
          - CreateNamespace=true
```

### Preview URL Exposure

- **Ingress approach**: Each preview namespace gets an Ingress with subdomain routing
- **Pattern**: `pr-<number>.preview.ytsummarizer.dev` (or path-based: `preview.ytsummarizer.dev/pr-<number>/`)
- **Status posting**: `preview.yml` posts a PR comment with:
  - Deploy status (deploying/ready/failed)
  - Preview URL
  - Link to Argo CD sync status

### Production Deploy Mechanism

1. PR merge triggers `deploy-prod.yml`
2. Workflow updates `k8s/overlays/prod/kustomization.yaml` with image digests:
   ```yaml
   images:
     - name: api
       newName: ytsummarizeracr.azurecr.io/api
       digest: sha256:abc123...
     - name: workers
       newName: ytsummarizeracr.azurecr.io/workers
       digest: sha256:def456...
   ```
3. Commit pushed to main triggers Argo CD sync
4. Argo CD applies changes to production namespace

## Single-Node AKS Safety & Cost

### Resource Isolation for Previews

```yaml
# Applied to each preview namespace
apiVersion: v1
kind: ResourceQuota
metadata:
  name: preview-quota
spec:
  hard:
    requests.cpu: "500m"
    requests.memory: "512Mi"
    limits.cpu: "1"
    limits.memory: "1Gi"
    pods: "10"
---
apiVersion: v1
kind: LimitRange
metadata:
  name: preview-limits
spec:
  limits:
    - default:
        cpu: "100m"
        memory: "128Mi"
      defaultRequest:
        cpu: "50m"
        memory: "64Mi"
      type: Container
```

### Production Protection

```yaml
# PriorityClass for production pods
apiVersion: scheduling.k8s.io/v1
kind: PriorityClass
metadata:
  name: production-critical
value: 1000000
globalDefault: false
description: "Priority for production workloads"
```

### Cleanup Policy

| Trigger | Action | Timeline |
|---------|--------|----------|
| PR closed/merged | `preview-cleanup.yml` deletes `k8s/overlays/previews/pr-<number>/` | Immediate |
| Argo CD detects deletion | Prunes namespace and all resources | <5 minutes |
| Orphan detection (optional) | Scheduled workflow scans for stale previews | Daily |

### Concurrency Limits

- Max 3 concurrent preview environments (enforced by workflow)
- Queue additional PRs until slot available
- Auto-cleanup reclaims slots

## Rollback Strategy

### Production Rollback

**Primary method (GitOps)**:
```bash
# Revert the merge commit that updated prod overlay
git revert <merge-commit-sha>
git push origin main
# Argo CD syncs to previous state
```

**Alternative (Argo CD UI)**:
1. Open Argo CD dashboard
2. Select `yt-summarizer-prod` application
3. Click "History and Rollback"
4. Select previous healthy revision
5. Sync to that revision

**Automatic rollback**:
- Argo CD health checks detect failing deployments
- If health checks fail, Argo CD automatically syncs to last healthy revision

### Preview Rollback

- Push new commit to PR branch → CI rebuilds → preview re-deploys
- Or close and reopen PR to force fresh preview

## Phase Completion Status

### Phase 0: Research ✅ Complete
- Technical decisions documented in [research.md](research.md)
- AKS + Argo CD + Kustomize stack validated
- Cost analysis complete (~$35/month)

### Phase 1: Design ✅ Complete (Revised)
- Repo structure defined (above)
- GitOps flow documented
- Resource isolation strategy defined
- Rollback mechanisms specified

### Phase 2: Tasks ⚠️ NEEDS REGENERATION

The existing `tasks.md` was generated for the old staging/manual-production approach with 97 tasks. It is now **stale** and must be regenerated to reflect:

- Removal of staging environment and workflows
- New preview environment workflows
- Auto-production deployment on merge
- ApplicationSet for preview discovery
- Updated overlay structure (`prod/` + `previews/pr-*/`)

**Action Required**: Run `/speckit.tasks` to regenerate task list after plan approval.

### Artifacts Status

| Artifact | Status | Notes |
|----------|--------|-------|
| plan.md | ✅ Updated | This file (2026-01-09 revision) |
| research.md | ✅ Complete | Decisions still valid |
| quickstart.md | ⚠️ Needs Update | Commands/URLs for preview workflow |
| tasks.md | ❌ Stale | Must regenerate (old 97-task list invalid) |
| data-model.md | N/A | No new entities |
| contracts/ | N/A | No API contracts |

## Complexity Tracking

| Aspect | Complexity | Justification |
|--------|------------|---------------|
| Single-node AKS | Medium | ResourceQuota + LimitRange + PriorityClass protect prod |
| ApplicationSet | Medium | Standard Argo CD pattern for ephemeral environments |
| Image digest pinning | Low | Kustomize native feature |
| Preview cleanup | Low | Simple delete overlay → Argo prunes |

## Open Items

1. **Ingress controller**: Need to decide on nginx-ingress vs Azure Application Gateway Ingress Controller (AGIC) for preview subdomain routing
2. **Preview URL domain**: Configure DNS wildcard `*.preview.ytsummarizer.dev` or use path-based routing
3. **Concurrent preview limit enforcement**: Workflow logic to queue/reject when 3 previews active
4. **Orphan preview detection**: Optional scheduled cleanup for previews without corresponding PRs
