# Implementation Plan: Azure CI/CD Pipelines

**Branch**: `002-azure-cicd` | **Date**: 2026-01-08 | **Spec**: [spec.md](spec.md)
**Input**: Feature specification from `/specs/002-azure-cicd/spec.md`

## Summary

Implement GitHub Actions CI/CD pipelines to automate testing on PRs. Deploy to Azure using GitOps: CI builds and pushes images to ACR, Argo CD on AKS auto-syncs from K8s manifests in the repo. Infrastructure provisioned via Terraform. Hosting uses AKS single-node (API/Workers), Azure Static Web Apps (Frontend), and Azure Container Registry (images).

## Technical Context

**Language/Version**: GitHub Actions YAML, Terraform HCL, Kustomize, Python 3.11, Node.js 20+  
**Primary Dependencies**: GitHub Actions, Terraform azurerm provider, Argo CD, kubectl  
**Storage**: Azure Storage Account (Terraform state), Azure Container Registry (images)  
**Testing**: pytest (Python), Vitest (Frontend), Playwright (E2E)  
**Target Platform**: GitHub Actions runners (ubuntu-latest), AKS single-node (~$30/month)  
**Project Type**: Multi-service monorepo (frontend + API + workers)  
**Performance Goals**: CI feedback <15 min, GitOps sync <5 min after image push  
**Constraints**: Zero secrets in logs, GitOps pull-based deployment, ~$35/month budget  
**Scale/Scope**: 2 environments (staging, production), 3 deployable services

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Status | Notes |
|-----------|--------|-------|
| V.1 No secrets in repo | ✅ PASS | All secrets in GitHub Secrets or Azure Key Vault → K8s Secrets |
| V.2 Least-privilege access | ✅ PASS | AKS managed identity, OIDC for CI |
| VI.1 Simplicity first | ✅ PASS | Kustomize over Helm, single-node AKS |
| VI.4 Dev environment (Aspire) | ✅ PASS | Local dev unchanged; K8s only for Azure |
| VI.5 Testing | ✅ PASS | All test suites in CI; E2E via Docker Compose |
| VI.6 Migration-driven schema | ✅ PASS | Alembic as K8s Job or init container |
| IV.1 Async-first | ✅ PASS | Workers as separate K8s Deployment |
| IV.3 Observability | ✅ PASS | Argo CD UI, commit SHA in image tags |

**Gate Status**: ✅ PASS - No violations requiring justification

## Project Structure

### Documentation (this feature)

```text
specs/002-azure-cicd/
├── plan.md              # This file
├── research.md          # Phase 0 output
├── data-model.md        # Phase 1 output (N/A - no data model changes)
├── quickstart.md        # Phase 1 output
├── contracts/           # Phase 1 output (N/A - no API contracts)
└── tasks.md             # Phase 2 output
```

### Source Code (repository root)

```text
.github/
├── workflows/
│   ├── ci.yml                    # PR testing workflow
│   ├── build-push.yml            # Build images, push to ACR on merge
│   └── cd-production.yml         # Manual trigger to promote staging → prod
├── actions/
│   ├── setup-python/action.yml   # Reusable Python setup with caching
│   └── setup-node/action.yml     # Reusable Node.js setup with caching

k8s/
├── base/                         # Shared K8s manifests
│   ├── kustomization.yaml
│   ├── namespace.yaml
│   ├── api-deployment.yaml
│   ├── api-service.yaml
│   ├── api-ingress.yaml
│   ├── transcribe-worker-deployment.yaml
│   ├── summarize-worker-deployment.yaml
│   ├── embed-worker-deployment.yaml
│   ├── relationships-worker-deployment.yaml
│   ├── externalsecret-db.yaml
│   ├── externalsecret-openai.yaml
│   ├── externalsecret-storage.yaml
│   ├── migration-job.yaml
│   └── configmap.yaml
├── overlays/
│   ├── staging/
│   │   ├── kustomization.yaml
│   │   └── patches/
│   └── production/
│       ├── kustomization.yaml
│       └── patches/
└── argocd/
    ├── staging-app.yaml          # Argo CD Application for staging
    └── production-app.yaml       # Argo CD Application for production

infra/
├── terraform/
│   ├── environments/
│   │   ├── staging/
│   │   │   └── main.tf
│   │   └── production/
│   │       └── main.tf
│   ├── modules/
│   │   ├── aks/                  # AKS single-node cluster
│   │   ├── static-web-app/       # SWA for frontend
│   │   ├── container-registry/   # ACR
│   │   ├── storage/              # Blob + Queue storage
│   │   ├── sql-database/         # Azure SQL
│   │   └── key-vault/            # Azure Key Vault
│   ├── backend.tf
│   ├── providers.tf
│   └── variables.tf

scripts/
├── deploy-infra.ps1              # Local/CI infrastructure deployment
└── run-migrations.ps1            # Alembic migration runner
```

**Structure Decision**: K8s manifests in `k8s/` with Kustomize base + overlays. Argo CD Applications defined in `k8s/argocd/`. Terraform provisions infrastructure only (AKS, ACR, SQL, etc.), not application deployments. GitOps handles app deployment.

## Phase Completion Status

### Phase 0: Research ✅ Complete

- [x] GitHub Actions monorepo patterns researched
- [x] AKS + GitOps deployment strategy defined
- [x] Azure Static Web Apps integration documented
- [x] Terraform state management configured
- [x] OIDC authentication approach selected
- [x] E2E testing in CI approach defined
- [x] Database migration strategy documented
- [x] Secrets management tiered approach established

**Output**: [research.md](research.md)

### Phase 1: Design ✅ Complete

- [x] Project structure defined (workflows, terraform modules)
- [x] Quickstart guide created with setup commands
- [x] Agent context updated with new technologies
- [x] Constitution re-check passed (see below)

**Outputs**: 
- [quickstart.md](quickstart.md) - Setup and usage guide
- data-model.md - N/A (no data model changes for CI/CD)
- contracts/ - N/A (no API contracts for CI/CD)

### Phase 2: Tasks ✅ Complete

- [x] Generated 97 tasks organized by user story (4 workers, comprehensive coverage)
- [x] Phase dependencies documented
- [x] Parallel execution opportunities identified
- [x] MVP-first implementation strategy defined

**Output**: [tasks.md](tasks.md)

---

## Constitution Re-Check (Post-Design)

| Principle | Pre-Design | Post-Design | Notes |
|-----------|------------|-------------|-------|
| V.1 No secrets in repo | ✅ PASS | ✅ PASS | OIDC eliminates stored secrets; Key Vault for runtime |
| V.2 Least-privilege | ✅ PASS | ✅ PASS | Separate federated credentials per environment |
| VI.1 Simplicity first | ✅ PASS | ✅ PASS | Standard patterns; modules keep Terraform DRY |
| VI.4 Dev environment | ⚠️ N/A | ✅ PASS | Docker Compose for CI E2E; Aspire untouched for dev |
| VI.5 Testing | ✅ PASS | ✅ PASS | All test suites in CI; E2E via containerized stack |
| VI.6 Migration-driven | ✅ PASS | ✅ PASS | Alembic runs as K8s Job during Argo CD sync |
| IV.1 Async-first | ✅ PASS | ✅ PASS | Workers as separate K8s Deployment |
| IV.3 Observability | ✅ PASS | ✅ PASS | Commit SHA tagging; Argo CD UI + GitHub Actions logs |

**Post-Design Gate**: ✅ PASS - Design complies with all constitutional principles

### Architecture Deviation: AKS vs ACA

**Constitution states**: Backend = Azure Container Apps  
**This feature uses**: AKS single-node cluster

**Justification**: Cost optimization for hobby/personal project
- ACA: Variable cost, ~$15-50+/month depending on usage
- AKS single-node: Fixed ~$30/month with predictable billing
- GitOps (Argo CD) provides better deployment visibility and rollback
- Single-node sufficient for low-traffic personal project

**Impact**: No functional difference for the application. Both run containerized workloads. Constitution amendment may be proposed if AKS becomes the permanent choice.

### Rollback Strategy

**GitOps rollback** (preferred):
```bash
# Revert the kustomization.yaml commit
git revert <commit-sha>
git push origin main
# Argo CD automatically syncs the reverted state
```

**Emergency rollback** (immediate):
```bash
kubectl rollout undo deployment/api -n yt-summarizer
kubectl rollout undo deployment/workers -n yt-summarizer
```
