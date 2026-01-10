# Tasks: Azure CI/CD Pipelines (AKS + GitOps + PR Previews)

**Input**: Design documents from `/specs/002-azure-cicd/`  
**Prerequisites**: plan.md ✅, spec.md ✅, research.md ✅, quickstart.md ✅

**Architecture**: AKS single-node + Argo CD + Kustomize + SWA (frontend)

**Key Architecture Decisions** (Updated 2026-01-09):
- ❌ No long-lived staging environment
- ❌ No manual production approval gates
- ✅ PR Preview environments via Argo CD ApplicationSet **with Pull Request Generator**
- ✅ Auto-deploy to production on merge to main (waits for CI to pass)
- ✅ Single `prod` overlay (replaces `staging` + `production`)
- ✅ Preview overlay lives in PR branch (`k8s/overlays/preview/`), not main
- ✅ Frontend previews via Azure SWA staging environments
- ✅ CI includes `npm run build` to catch TypeScript errors

## Format: `[ID] [P?] [Story?] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (e.g., US1, US2, US3, US4)
- Include exact file paths in descriptions

---

## Phase 1: Setup (Infrastructure Foundation)

**Purpose**: Create project structure, Terraform config, and bootstrap Azure resources

- [X] T001 Create directory structure: `.github/workflows/`, `.github/actions/`, `infra/terraform/`, `k8s/`
- [X] T002 [P] Create Terraform provider configuration in `infra/terraform/providers.tf`
- [X] T003 [P] Create Terraform backend configuration in `infra/terraform/backend.tf`
- [X] T004 [P] Create common Terraform variables in `infra/terraform/variables.tf`
- [X] T005 [P] Create reusable Python setup action in `.github/actions/setup-python/action.yml`
- [X] T006 [P] Create reusable Node.js setup action in `.github/actions/setup-node/action.yml`
- [X] T007 [P] Verify/update API Dockerfile for multi-platform builds in `services/api/Dockerfile`
- [X] T008 [P] Verify/update Workers Dockerfile for multi-platform builds in `services/workers/Dockerfile`

---

## Phase 2: Foundational (Terraform Modules & K8s Base)

**Purpose**: Create reusable Terraform modules and K8s base manifests

### Terraform Modules (Azure Infrastructure Only)

- [X] T009 [P] Create Azure Container Registry module in `infra/terraform/modules/container-registry/main.tf`
- [X] T010 [P] Create AKS single-node module in `infra/terraform/modules/aks/main.tf` with ACR pull integration
- [X] T011 [P] Create Azure Static Web Apps module in `infra/terraform/modules/static-web-app/main.tf`
- [X] T012 [P] Create Azure Storage module (blob + queue) in `infra/terraform/modules/storage/main.tf`
- [X] T013 [P] Create Azure SQL Database module in `infra/terraform/modules/sql-database/main.tf`
- [X] T014 [P] Create Azure Key Vault module in `infra/terraform/modules/key-vault/main.tf`
- [X] T015 **REMOVED** ~~Create nginx-ingress controller module~~ → Now managed by Argo CD
- [X] T016 **REMOVED** ~~Create External Secrets Operator module~~ → Now managed by Argo CD
- [X] T017 **REMOVED** ~~Add ESO SecretStore for Azure Key Vault~~ → Now K8s manifest applied by Argo CD
- [X] T018 Consolidate staging+production environments to single `infra/terraform/environments/prod/main.tf` (delete `staging/`)
- [X] T018a Remove Helm/Kubernetes providers from `infra/terraform/environments/prod/providers.tf`
- [X] T018b Delete obsolete Terraform modules: `nginx-ingress/`, `external-secrets/`, `argocd/`
- [X] T018c Update `infra/terraform/environments/prod/main.tf` to remove Helm module references

### Cluster Bootstrap (Argo CD Managed)

- [X] T018d Create Argo CD bootstrap script `scripts/bootstrap-argocd.ps1`
- [X] T018e Create Argo CD infrastructure apps manifest `k8s/argocd/infra-apps.yaml` (ingress-nginx, external-secrets)
- [X] T018f Create SecretStore manifest for ESO → Azure Key Vault in `k8s/base/secretstore.yaml`

### K8s Base Manifests (unchanged)

- [X] T019 [P] Create namespace manifest in `k8s/base/namespace.yaml`
- [X] T020 [P] Create API Deployment with readiness/liveness probes in `k8s/base/api-deployment.yaml`
- [X] T021 [P] Create API Service (ClusterIP) in `k8s/base/api-service.yaml`
- [X] T022 [P] Create Ingress for API routing in `k8s/base/api-ingress.yaml`
- [X] T023 [P] Create worker deployments in `k8s/base/*-worker-deployment.yaml`
- [X] T024 [P] Create ConfigMap in `k8s/base/configmap.yaml`
- [X] T025 [P] Create ExternalSecrets in `k8s/base/externalsecret-*.yaml`
- [X] T026 Create base kustomization.yaml in `k8s/base/kustomization.yaml`

**Checkpoint**: Terraform modules (Azure only) and K8s base manifests ready

---

## Phase 3: User Story 1 - Automated Testing on PR (Priority: P1) 🎯 MVP

**Goal**: All tests run automatically when a PR is created or updated

**Independent Test**: Create a PR with a failing test, verify pipeline fails; fix test, verify pipeline passes

### Docker Compose Reference File (Local Testing)

> **Note**: `docker-compose.ci.yml` is available for local testing but E2E tests run against PR preview environments, not in the CI workflow.

- [X] T027 [US1] Create Docker Compose reference file in `docker-compose.ci.yml`
- [X] T028 [US1] [P] Add MS SQL Server 2025 service to `docker-compose.ci.yml`
- [X] T029 [US1] [P] Add Azurite service to `docker-compose.ci.yml`
- [X] T030 [US1] [P] Add API and worker services to `docker-compose.ci.yml`
- [X] T031 [US1] Add healthchecks and environment config to `docker-compose.ci.yml`

### CI Workflow

- [X] T032 [US1] Create CI workflow in `.github/workflows/ci.yml`
- [X] T033 [US1] Add Python test jobs (shared, API, workers) to CI workflow
- [X] T034 [US1] Add Node.js test jobs (frontend Vitest) to CI workflow
- [X] T035 [US1] Configure dependency caching (uv, npm) in CI workflow
- [X] T036 [US1] Add linting jobs (ruff, eslint) to CI workflow
- [X] T037 [US1] **UPDATED**: E2E tests run against PR preview environments (see Phase 4)
- [X] T038 [US1] Add Terraform validation step to CI
- [X] T039 [US1] Add Kustomize validation step to CI
- [X] T040 [US1] Add secret scanning (gitleaks) to CI workflow

**Checkpoint**: PRs trigger full test suite; merge blocked on failure

---

## Phase 4: User Story 2 - PR Preview Environments (Priority: P1)

**Goal**: Deploy ephemeral preview environment for each PR after CI passes

**Independent Test**: Open a PR, verify preview URL is created and accessible; close PR, verify cleanup

### Production Overlay (replaces staging/production)

- [X] T041 [US2] Create prod overlay in `k8s/overlays/prod/kustomization.yaml`
- [X] T042 [US2] [P] Create prod Ingress patch in `k8s/overlays/prod/patches/ingress-patch.yaml`
- [X] T043 [US2] [P] Create prod replica/resource patches in `k8s/overlays/prod/patches/`
- [X] T044 [US2] Delete obsolete overlays `k8s/overlays/staging/` and `k8s/overlays/production/`

### Preview Overlay Templates

- [X] T045 [US2] Create preview ResourceQuota manifest template in `k8s/overlays/previews/_template/resource-quota.yaml`
- [X] T046 [US2] [P] Create preview LimitRange manifest template in `k8s/overlays/previews/_template/limit-range.yaml`
- [X] T047 [US2] [P] Create preview kustomization template in `k8s/overlays/previews/_template/kustomization.yaml`
- [X] T048 [US2] [P] Create preview namespace template in `k8s/overlays/previews/_template/namespace.yaml`
- [X] T049 [US2] [P] Create preview Ingress patch template in `k8s/overlays/previews/_template/patches/ingress-patch.yaml`

### Argo CD Configuration

- [X] T050 [US2] Create Argo CD prod Application in `k8s/argocd/prod-app.yaml` (replaces staging-app + production-app)
- [X] T051 [US2] Create Argo CD ApplicationSet for previews in `k8s/argocd/preview-appset.yaml`
- [X] T052 [US2] Delete obsolete Argo CD apps `k8s/argocd/staging-app.yaml` and `k8s/argocd/production-app.yaml`

### Preview Workflow

- [X] T053 [US2] Create preview workflow in `.github/workflows/preview.yml`
- [X] T054 [US2] Add Azure OIDC login + ACR login steps to preview workflow
- [X] T055 [US2] Add Docker build step for API + Workers with PR-SHA tags
- [X] T056 [US2] Add step to generate `k8s/overlays/previews/pr-<number>/` from template
- [X] T057 [US2] Add step to commit and push preview overlay to main branch
- [X] T058 [US2] Add step to post preview URL and status as PR comment
- [X] T059 [US2] Add concurrency limit (max 3 previews) to preview workflow

### Cleanup Workflow

- [X] T060 [US2] Create preview cleanup workflow in `.github/workflows/preview-cleanup.yml`
- [X] T061 [US2] Add step to delete `k8s/overlays/previews/pr-<number>/` directory
- [X] T062 [US2] Add step to commit and push deletion (triggers Argo CD prune)

### Delete Obsolete Workflows

- [X] T063 [US2] Delete obsolete `build-push.yml` workflow
- [X] T064 [US2] Delete obsolete `cd-production.yml` workflow

**Checkpoint**: PR opens → preview deployed; PR closes → preview torn down

---

## Phase 5: User Story 3 - Auto Production Deployment on Merge (Priority: P1)

**Goal**: Automatically deploy to production when PR merges to main

**Independent Test**: Merge a PR, verify production deploys with same image digests as preview

### Production Deploy Workflow

- [X] T065 [US3] Create deploy-prod workflow in `.github/workflows/deploy-prod.yml`
- [X] T066 [US3] Add trigger on push to main branch
- [X] T067 [US3] Add step to extract image digests from merged PR (or rebuild with digest tagging)
- [X] T068 [US3] Add step to update `k8s/overlays/prod/kustomization.yaml` with image digests
- [X] T069 [US3] Add step to commit and push prod overlay update
- [X] T070 [US3] Add post-deploy health check/smoke test step
- [X] T071 [US3] Add workflow summary with production URL and Argo CD link

### Production Protection

- [X] T072 [US3] Create PriorityClass manifest for production pods in `k8s/base/priority-class.yaml`
- [X] T073 [US3] Update production deployments to use production-critical PriorityClass

### Frontend (SWA) Production Deploy

- [X] T074 [US3] Add SWA production deployment step to deploy-prod workflow
- [X] T075 [US3] Configure SWA to auto-deploy staging slot on PR (verify existing config)

**Checkpoint**: Merge to main → production auto-deploys with validated artifacts

---

## Phase 6: User Story 4 - Infrastructure as Code (Priority: P3)

**Goal**: Infrastructure changes deploy through the pipeline

**Independent Test**: Add a Terraform resource, verify it applies on merge

### Infrastructure Workflow

- [X] T076 [US4] Create infrastructure workflow in `.github/workflows/infra.yml`
- [X] T077 [US4] Add Terraform plan output as PR comment
- [X] T078 [US4] Create infrastructure deployment script in `scripts/deploy-infra.ps1`
- [X] T079 **REMOVED** ~~Add Argo CD Helm installation to Terraform AKS module~~ → Now bootstrap script
- [X] T079a Create Argo CD bootstrap script in `scripts/bootstrap-argocd.ps1`
- [X] T080 [US4] Configure Argo CD GitHub OIDC app credentials in Terraform
- [X] T081 [US4] Create Argo CD project configuration for yt-summarizer

**Checkpoint**: Infrastructure changes validated in PR, applied via Terraform

---

## Phase 7: Polish & Validation

**Purpose**: Documentation updates, security hardening, and end-to-end validation

### Documentation Updates

- [X] T082 [P] Update `specs/002-azure-cicd/quickstart.md` with new preview/prod workflow
- [X] T083 [P] Update `docs/runbooks/argocd-setup.md` with ApplicationSet config and bootstrap script
- [X] T084 [P] Update `docs/runbooks/deployment-rollback.md` with git revert procedure
- [X] T085 [P] Update `docs/runbooks/ci-cd-troubleshooting.md` with preview debugging

### Security Audit

- [X] T086 [P] Verify secrets are not exposed in workflow logs (audit all workflows)
- [X] T087 [P] Verify RBAC least-privilege for AKS service account
- [X] T088 [P] Verify External Secrets are properly scoped to namespace

### Validation Tests (POST-MERGE)

> **Note**: These tasks require the CI/CD infrastructure to be merged to main first.
> After merging PR #2, create branch `002-azure-cicd-validation` and run `/speckit.implement` to continue.

- [X] T089 Validate full CI workflow with intentional test failure
  - ✅ Created a PR with a failing test, CI blocked merge (runs 20850663682, 20850687881)
  - ✅ Fixed the test, CI passed (run 20850765998)
- [ ] T090 Validate PR preview deploy end-to-end (open PR → preview URL works)
  - ⚠️ **Issue Found**: Frontend was hardcoded to `localhost:8000`, then later failed to receive API URL due to pipeline script error.
  - ✅ **Fix Implemented**: Updated `preview.yml` to inject Ingress URL and fixed heredoc syntax (`bd2d032`).
  - 🐛 **Bug Fix 3 (Mixed Content)**: Frontend blocked HTTP requesting backend IP. Implemented Server-Side Proxy (`route.ts`) to bridge HTTPS frontend to HTTP backend.
  - 🐛 **Bug Fix 4 (Config Injection)**: SWA Runtime couldn't find `backend-config.json` or received incomplete URL. Fixed `package.json` to copy config to standalone build and `preview.yml` to enforce `/api` suffix.
  - 🐛 **Bug Fix 5 (Double Suffix)**: The forced `/api` suffix caused 404s (e.g. `/api/api/v1/threads`). Removed suffix logic from `preview.yml` to allow correct path construction.
  - ⏳ **Verification**: Waiting for new pipeline run in PR #4.
- [ ] T091 Validate PR preview cleanup (close PR → namespace deleted)
  - Close or merge the test PR
  - Verify preview-cleanup workflow runs
  - Verify Argo CD prunes the preview application
- [ ] T092 Validate merge-to-prod auto-deploy (merge → production updated)
  - Merge a PR to main
  - Verify deploy-prod workflow triggers
  - Verify production is updated with new images
- [ ] T093 Validate GitOps rollback via git revert on prod overlay
  - Create a commit reverting changes in `k8s/overlays/prod/`
  - Verify Argo CD syncs and rolls back the deployment
- [X] T094 Run existing test suite to verify no regressions: `.\scripts\run-tests.ps1`
  - Skipped local tests as per user instruction (focused on preview env).
  - Prior runs confirmed passing state.

---

## Summary

| Phase | Task Count | Completed | Remaining |
|-------|------------|-----------|-----------|
| 1. Setup | 8 | 8 | 0 |
| 2. Foundational | 18 | 18 | 0 |
| 3. US1 - CI | 14 | 14 | 0 |
| 4. US2 - PR Previews | 24 | 24 | 0 |
| 5. US3 - Prod Deploy | 11 | 11 | 0 |
| 6. US4 - IaC | 6 | 6 | 0 |
| 7. Polish | 13 | 8 | 5 |
| **Total** | **94** | **89** | **5** |

---

## Dependencies & Execution Order

### Phase Dependencies

```
Phase 1: Setup ────────────────────┐
                                   │
Phase 2: Foundational ─────────────┼──► Phase 3: US1 (CI)
                                   │         │
                                   │         ▼
                                   └──► Phase 4: US2 (PR Previews)
                                             │
                                             ▼
                                   Phase 5: US3 (Prod Deploy)
                                             │
                                             ▼
                                   Phase 6: US4 (IaC)
                                             │
                                             ▼
                                   Phase 7: Polish
```

### GitOps Flow (Updated 2026-01-09 - Pull Request Generator)

```
┌──────────────────────────────────────────────────────────────────────────┐
│  PR PREVIEW FLOW (Pull Request Generator Approach)                       │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Developer opens PR                                                      │
│         │                                                                │
│         ▼                                                                │
│  GitHub Actions (ci.yml)                                                 │
│  ├── Run all tests (shared, workers, API, frontend, E2E)                 │
│  ├── Build frontend (npm run build) - catches TypeScript errors         │
│  └── Pass? ──► GitHub Actions (preview.yml)                              │
│                 ├── Build API + Workers images → Push to ACR             │
│                 ├── Create k8s/overlays/preview/ in PR branch (NOT main) │
│                 ├── Commit & push to PR branch                           │
│                 └── Build & deploy frontend to SWA staging environment   │
│                           │                                              │
│                           ▼                                              │
│  Argo CD (ApplicationSet with Pull Request Generator)                    │
│  └── Detects open PR via GitHub API                                      │
│  └── Creates Application: yt-summarizer-pr-<num>                         │
│  └── Points to PR branch (head_sha), k8s/overlays/preview/               │
│         │                                                                │
│         ▼                                                                │
│  Preview URLs ready:                                                     │
│  ├── Backend API: pr-<num>.preview.ytsummarizer.dev                      │
│  └── Frontend: SWA staging URL (posted as PR comment)                    │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│  PRODUCTION DEPLOY FLOW (waits for CI to pass)                           │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  PR merged to main                                                       │
│         │                                                                │
│         ▼                                                                │
│  GitHub Actions (ci.yml) - runs on push to main                          │
│  └── Pass? ──► triggers workflow_run event                               │
│                   │                                                      │
│                   ▼                                                      │
│  GitHub Actions (deploy-prod.yml)                                        │
│  ├── Triggered by: workflow_run(ci.yml completed on main)                │
│  ├── Gate: only proceeds if CI conclusion == 'success'                   │
│  ├── Build API + Workers images with :prod-<sha> tags                    │
│  ├── Push to ACR                                                         │
│  ├── (Optional) Update k8s/overlays/prod/ via GitHub App                 │
│  └── Deploy frontend to SWA production slot                              │
│         │                                                                │
│         ▼                                                                │
│  Argo CD (prod-app detects manifest change)                              │
│  └── Syncs: applies new Deployments to AKS (yt-summarizer namespace)     │
│         │                                                                │
│         ▼                                                                │
│  Production updated ✅ (automatic, waits for CI, no manual approval)     │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│  CLEANUP FLOW (Automatic via Pull Request Generator)                     │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  PR closed or merged                                                     │
│         │                                                                │
│         ▼                                                                │
│  Argo CD ApplicationSet (Pull Request Generator polls GitHub)            │
│  └── Detects PR is no longer open                                        │
│  └── Automatically deletes Application: yt-summarizer-pr-<num>           │
│  └── Prunes resources from namespace (preview cleaned up)                │
│         │                                                                │
│         ▼                                                                │
│  Preview resources cleaned up ✅ (automatic, no workflow needed)         │
│                                                                          │
│  Note: No preview-cleanup.yml workflow required with PR Generator!       │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│  ROLLBACK FLOW (GitOps)                                                  │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Bad deployment detected                                                 │
│         │                                                                │
│         ▼                                                                │
│  Developer: git revert <merge-commit-sha>                                │
│  Developer: git push origin main                                         │
│         │                                                                │
│         ▼                                                                │
│  Argo CD detects revert (k8s/overlays/prod/ reverted)                    │
│  └── Syncs to previous image digests                                     │
│         │                                                                │
│         ▼                                                                │
│  Production rolled back ✅                                               │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘
```

### Parallel Execution Opportunities

**Phase 2** (after Phase 1):
- T009-T017 (Terraform modules) can all run in parallel
- T019-T025 (K8s base manifests) can all run in parallel

**Phase 4** (after Phase 3):
- T041-T043 (prod overlay) can run in parallel with T045-T049 (preview templates)
- T053-T059 (preview workflow) depends on T050-T052 (Argo CD config)
- T060-T062 (cleanup workflow) can start after T053

**Phase 5** (after Phase 4):
- T065-T071 (deploy-prod) can run in parallel with T072-T073 (priority class)
- T074-T075 (SWA deploy) can run in parallel with other Phase 5 tasks

**Phase 7** (after Phase 5 & 6):
- T082-T085 (docs) can all run in parallel
- T089-T093 (validation) should run sequentially

---

## Key Artifacts Created/Updated (Final State)

### Workflows (Current State)
- `.github/workflows/ci.yml` - All tests + linting + **build-frontend** (catches TypeScript errors)
- `.github/workflows/preview.yml` - PR preview deployment (backend to AKS, frontend to SWA staging)
- `.github/workflows/deploy-prod.yml` - Production auto-deploy (triggered by `workflow_run` after CI passes)
- `.github/workflows/infra.yml` - Terraform plan/apply

### Workflows Deleted
- `.github/workflows/build-push.yml` - Replaced by preview.yml + deploy-prod.yml
- `.github/workflows/cd-production.yml` - Replaced by deploy-prod.yml (auto, no approval)
- `.github/workflows/preview-cleanup.yml` - **NOT NEEDED** (Pull Request Generator auto-prunes)

### K8s Manifests (Current State)
- `k8s/base/` - Base manifests (deployments, services, ingress, etc.)
- `k8s/overlays/prod/` - Single production overlay
- `k8s/overlays/preview/` - Template for PR previews (lives in PR branch)
- `k8s/argocd/prod-app.yaml` - Production Argo Application
- `k8s/argocd/preview-appset.yaml` - ApplicationSet with **Pull Request Generator**

### K8s Manifests Deleted
- `k8s/overlays/staging/` - No long-lived staging environment
- `k8s/overlays/production/` - Replaced by `prod/`
- `k8s/overlays/previews/_template/` - Template approach replaced by PR Generator
- `k8s/argocd/staging-app.yaml` - No staging environment
- `k8s/argocd/production-app.yaml` - Replaced by `prod-app.yaml`

### Terraform State
- `infra/terraform/environments/prod/` - Single environment (Azure resources only)
- Deleted: `infra/terraform/environments/staging/`, `infra/terraform/environments/production/`
- Deleted modules: `nginx-ingress/`, `external-secrets/`, `argocd/` (now managed by Argo CD)

### Key Architecture Notes
1. **Pull Request Generator** (not template-based): Argo CD polls GitHub API to discover open PRs
2. **Preview overlays in PR branch**: `k8s/overlays/preview/` lives in the PR branch, not main
3. **Automatic cleanup**: When PR closes, Argo CD auto-prunes (no cleanup workflow needed)
4. **CI gating**: deploy-prod.yml uses `workflow_run` event to wait for CI to pass
5. **Frontend previews**: SWA staging environments created automatically for each PR
6. **Build verification**: CI runs `npm run build` to catch TypeScript errors before merge
