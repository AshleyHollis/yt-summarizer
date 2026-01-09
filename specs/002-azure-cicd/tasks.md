# Tasks: Azure CI/CD Pipelines (AKS + GitOps + PR Previews)

**Input**: Design documents from `/specs/002-azure-cicd/`  
**Prerequisites**: plan.md ✅, spec.md ✅, research.md ✅, quickstart.md ✅

**Architecture**: AKS single-node + Argo CD + Kustomize + SWA (frontend)

**Key Changes from Previous Plan**:
- ❌ No long-lived staging environment
- ❌ No manual production approval gates
- ✅ PR Preview environments via Argo CD ApplicationSet
- ✅ Auto-deploy to production on merge to main
- ✅ Single `prod` overlay (replaces `staging` + `production`)

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

### Terraform Modules

- [X] T009 [P] Create Azure Container Registry module in `infra/terraform/modules/container-registry/main.tf`
- [X] T010 [P] Create AKS single-node module in `infra/terraform/modules/aks/main.tf` with ACR pull integration
- [X] T011 [P] Create Azure Static Web Apps module in `infra/terraform/modules/static-web-app/main.tf`
- [X] T012 [P] Create Azure Storage module (blob + queue) in `infra/terraform/modules/storage/main.tf`
- [X] T013 [P] Create Azure SQL Database module in `infra/terraform/modules/sql-database/main.tf`
- [X] T014 [P] Create Azure Key Vault module in `infra/terraform/modules/key-vault/main.tf`
- [X] T015 [P] Create nginx-ingress controller module in `infra/terraform/modules/nginx-ingress/main.tf`
- [X] T016 Create External Secrets Operator module in `infra/terraform/modules/external-secrets/main.tf`
- [X] T017 Add ESO SecretStore for Azure Key Vault in `infra/terraform/modules/external-secrets/secretstore.tf`
- [X] T018 Consolidate staging+production environments to single `infra/terraform/environments/prod/main.tf` (delete `staging/`)

### K8s Base Manifests (unchanged)

- [X] T019 [P] Create namespace manifest in `k8s/base/namespace.yaml`
- [X] T020 [P] Create API Deployment with readiness/liveness probes in `k8s/base/api-deployment.yaml`
- [X] T021 [P] Create API Service (ClusterIP) in `k8s/base/api-service.yaml`
- [X] T022 [P] Create Ingress for API routing in `k8s/base/api-ingress.yaml`
- [X] T023 [P] Create worker deployments in `k8s/base/*-worker-deployment.yaml`
- [X] T024 [P] Create ConfigMap in `k8s/base/configmap.yaml`
- [X] T025 [P] Create ExternalSecrets in `k8s/base/externalsecret-*.yaml`
- [X] T026 Create base kustomization.yaml in `k8s/base/kustomization.yaml`

**Checkpoint**: Terraform modules and K8s base manifests ready

---

## Phase 3: User Story 1 - Automated Testing on PR (Priority: P1) 🎯 MVP

**Goal**: All tests run automatically when a PR is created or updated

**Independent Test**: Create a PR with a failing test, verify pipeline fails; fix test, verify pipeline passes

### Docker Compose CI Environment

- [X] T027 [US1] Create Docker Compose CI file in `docker-compose.ci.yml`
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
- [X] T037 [US1] Add E2E test job using Docker Compose CI environment
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
- [X] T079 [US4] Add Argo CD Helm installation to Terraform AKS module
- [X] T080 [US4] Configure Argo CD GitHub OIDC app credentials in Terraform
- [X] T081 [US4] Create Argo CD project configuration for yt-summarizer

**Checkpoint**: Infrastructure changes validated in PR, applied via Terraform

---

## Phase 7: Polish & Validation

**Purpose**: Documentation updates, security hardening, and end-to-end validation

### Documentation Updates

- [ ] T082 [P] Update `specs/002-azure-cicd/quickstart.md` with new preview/prod workflow
- [ ] T083 [P] Update `docs/runbooks/argocd-setup.md` with ApplicationSet config
- [ ] T084 [P] Update `docs/runbooks/deployment-rollback.md` with git revert procedure
- [ ] T085 [P] Update `docs/runbooks/ci-cd-troubleshooting.md` with preview debugging

### Security Audit

- [X] T086 [P] Verify secrets are not exposed in workflow logs (audit all workflows)
- [X] T087 [P] Verify RBAC least-privilege for AKS service account
- [X] T088 [P] Verify External Secrets are properly scoped to namespace

### Validation Tests

- [ ] T089 Validate full CI workflow with intentional test failure
- [ ] T090 Validate PR preview deploy end-to-end (open PR → preview URL works)
- [ ] T091 Validate PR preview cleanup (close PR → namespace deleted)
- [ ] T092 Validate merge-to-prod auto-deploy (merge → production updated)
- [ ] T093 Validate GitOps rollback via git revert on prod overlay
- [X] T094 Run existing test suite to verify no regressions: `.\scripts\run-tests.ps1`

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
| 7. Polish | 13 | 4 | 9 |
| **Total** | **94** | **85** | **9** |

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

### GitOps Flow (Updated)

```
┌──────────────────────────────────────────────────────────────────────────┐
│  PR PREVIEW FLOW                                                         │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  Developer opens PR                                                      │
│         │                                                                │
│         ▼                                                                │
│  GitHub Actions (ci.yml)                                                 │
│  ├── Run all tests (shared, workers, API, frontend, E2E)                 │
│  └── Pass? ──► GitHub Actions (preview.yml)                              │
│                 ├── Build API + Workers images → Push to ACR             │
│                 ├── Generate k8s/overlays/previews/pr-<num>/             │
│                 └── Commit & push overlay                                │
│                           │                                              │
│                           ▼                                              │
│  Argo CD (ApplicationSet detects new preview overlay)                    │
│  └── Creates Application: preview-pr-<num>                               │
│  └── Syncs to namespace: preview-pr-<num>                                │
│         │                                                                │
│         ▼                                                                │
│  Preview URL ready: pr-<num>.preview.ytsummarizer.dev                    │
│  (Posted as PR comment)                                                  │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│  PRODUCTION DEPLOY FLOW                                                  │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  PR merged to main                                                       │
│         │                                                                │
│         ▼                                                                │
│  GitHub Actions (deploy-prod.yml)                                        │
│  ├── Get image digests from merged commit                                │
│  ├── Update k8s/overlays/prod/kustomization.yaml with digests            │
│  └── Commit & push                                                       │
│         │                                                                │
│         ▼                                                                │
│  Argo CD (prod-app detects manifest change)                              │
│  └── Syncs: applies new Deployments to AKS (yt-summarizer namespace)     │
│         │                                                                │
│         ▼                                                                │
│  Production updated ✅ (automatic, no approval gate)                     │
│                                                                          │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│  CLEANUP FLOW                                                            │
├──────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  PR closed/merged                                                        │
│         │                                                                │
│         ▼                                                                │
│  GitHub Actions (preview-cleanup.yml)                                    │
│  ├── Delete k8s/overlays/previews/pr-<num>/                              │
│  └── Commit & push                                                       │
│         │                                                                │
│         ▼                                                                │
│  Argo CD (ApplicationSet detects overlay deleted)                        │
│  └── Deletes Application: preview-pr-<num>                               │
│  └── Prunes namespace: preview-pr-<num>                                  │
│         │                                                                │
│         ▼                                                                │
│  Preview resources cleaned up ✅                                         │
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

## Key Artifacts to Create/Update

### New Workflows
- `.github/workflows/preview.yml` - PR preview deployment
- `.github/workflows/preview-cleanup.yml` - PR preview cleanup
- `.github/workflows/deploy-prod.yml` - Production auto-deploy on merge

### Workflows to Delete
- `.github/workflows/build-push.yml` - Replaced by preview.yml + deploy-prod.yml
- `.github/workflows/cd-production.yml` - Replaced by deploy-prod.yml (auto, no approval)

### New K8s Manifests
- `k8s/overlays/prod/` - Single production overlay
- `k8s/overlays/previews/_template/` - Preview overlay templates
- `k8s/argocd/prod-app.yaml` - Production Argo Application
- `k8s/argocd/preview-appset.yaml` - Preview ApplicationSet

### K8s Manifests to Delete
- `k8s/overlays/staging/` - No longer needed
- `k8s/overlays/production/` - Replaced by `prod/`
- `k8s/argocd/staging-app.yaml` - No staging environment
- `k8s/argocd/production-app.yaml` - Replaced by `prod-app.yaml`

### Terraform Changes
- `infra/terraform/environments/prod/` - Consolidated environment
- Delete `infra/terraform/environments/staging/`
- Delete `infra/terraform/environments/production/`
