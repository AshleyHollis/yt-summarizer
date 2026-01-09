# Tasks: Azure CI/CD Pipelines (AKS + GitOps)

**Input**: Design documents from `/specs/002-azure-cicd/`  
**Prerequisites**: plan.md ✅, spec.md ✅, research.md ✅, quickstart.md ✅

**Architecture**: AKS single-node + Argo CD + Kustomize + SWA (frontend)

**Database**: MS SQL Server 2025 (Docker container in dev/CI for native VECTOR support, Azure SQL in production)

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

## Phase 2: Foundational (Terraform Modules)

**Purpose**: Create reusable Terraform modules for Azure infrastructure

**⚠️ CRITICAL**: Modules must be complete before environment configurations

- [X] T009 [P] Create Azure Container Registry module in `infra/terraform/modules/container-registry/main.tf`
- [X] T010 [P] Create AKS single-node module in `infra/terraform/modules/aks/main.tf` with ACR pull integration
- [X] T011 [P] Create Azure Static Web Apps module in `infra/terraform/modules/static-web-app/main.tf`
- [X] T012 [P] Create Azure Storage module (blob + queue) in `infra/terraform/modules/storage/main.tf`
- [X] T013 [P] Create Azure SQL Database module in `infra/terraform/modules/sql-database/main.tf`
- [X] T014 [P] Create Azure Key Vault module in `infra/terraform/modules/key-vault/main.tf`
- [X] T015 [P] Create nginx-ingress controller module in `infra/terraform/modules/nginx-ingress/main.tf`
- [X] T016 Create External Secrets Operator module in `infra/terraform/modules/external-secrets/main.tf`
- [X] T017 Add ESO SecretStore for Azure Key Vault in `infra/terraform/modules/external-secrets/secretstore.tf`
- [X] T018 Create staging environment configuration in `infra/terraform/environments/staging/main.tf`
- [X] T019 Create production environment configuration in `infra/terraform/environments/production/main.tf`

**Checkpoint**: Terraform modules ready - K8s manifests can begin

---

## Phase 3: Kubernetes Manifests (Kustomize)

**Purpose**: Create K8s base manifests and environment overlays

### Base Manifests

- [X] T020 [P] Create namespace manifest in `k8s/base/namespace.yaml`
- [X] T021 [P] Create API Deployment manifest with readiness/liveness probes in `k8s/base/api-deployment.yaml`
- [X] T022 [P] Create API Service manifest (ClusterIP) in `k8s/base/api-service.yaml`
- [X] T023 [P] Create transcribe-worker Deployment manifest in `k8s/base/transcribe-worker-deployment.yaml`
- [X] T023a [P] Create summarize-worker Deployment manifest in `k8s/base/summarize-worker-deployment.yaml`
- [X] T023b [P] Create embed-worker Deployment manifest in `k8s/base/embed-worker-deployment.yaml`
- [X] T023c [P] Create relationships-worker Deployment manifest in `k8s/base/relationships-worker-deployment.yaml`
- [X] T024 [P] Create ConfigMap for shared config in `k8s/base/configmap.yaml`
- [X] T025 [P] Create Ingress manifest for API routing in `k8s/base/api-ingress.yaml`
- [X] T026 Create base kustomization.yaml in `k8s/base/kustomization.yaml`

### External Secrets Manifests

- [X] T027 [P] Create ExternalSecret for database connection in `k8s/base/externalsecret-db.yaml`
- [X] T028 [P] Create ExternalSecret for OpenAI API key in `k8s/base/externalsecret-openai.yaml`
- [X] T029 [P] Create ExternalSecret for Azure Storage connection in `k8s/base/externalsecret-storage.yaml`

### Environment Overlays

- [X] T030 [P] Create staging overlay with resource limits in `k8s/overlays/staging/kustomization.yaml`
- [X] T031 [P] Create staging Ingress patch with staging hostname in `k8s/overlays/staging/patches/ingress-patch.yaml`
- [X] T032 [P] Create production overlay with resource limits in `k8s/overlays/production/kustomization.yaml`
- [X] T033 [P] Create production Ingress patch with production hostname in `k8s/overlays/production/patches/ingress-patch.yaml`

### Argo CD Applications

- [X] T034 Create Argo CD staging Application in `k8s/argocd/staging-app.yaml`
- [X] T035 Create Argo CD production Application in `k8s/argocd/production-app.yaml`
- [X] T036 Create Argo CD repository secret template in `k8s/argocd/repo-secret.yaml` (uses GitHub OIDC)

**Checkpoint**: K8s manifests ready - workflows can begin

---

## Phase 4: User Story 1 - Automated Testing on PR (Priority: P1) 🎯 MVP

**Goal**: All tests run automatically when a PR is created or updated

**Independent Test**: Create a PR with a failing test, verify pipeline fails; fix test, verify pipeline passes

### Docker Compose CI Environment

- [X] T037 [US1] Create Docker Compose CI base file in `docker-compose.ci.yml`
- [X] T038 [US1] [P] Add MS SQL Server 2025 service (mcr.microsoft.com/mssql/server:2025-latest) to `docker-compose.ci.yml`
- [X] T039 [US1] [P] Add Azurite (Azure Storage emulator) service to `docker-compose.ci.yml`
- [X] T040 [US1] [P] Add API service definition to `docker-compose.ci.yml`
- [X] T041 [US1] [P] Add transcribe-worker service to `docker-compose.ci.yml`
- [X] T041a [US1] [P] Add summarize-worker service to `docker-compose.ci.yml`
- [X] T041b [US1] [P] Add embed-worker service to `docker-compose.ci.yml`
- [X] T041c [US1] [P] Add relationships-worker service to `docker-compose.ci.yml`
- [X] T042 [US1] Add healthchecks and depends_on for service ordering in `docker-compose.ci.yml`
- [X] T043 [US1] Add CI network configuration to `docker-compose.ci.yml`
- [X] T044 [US1] Add environment variables for OpenAI/Azure credentials in `docker-compose.ci.yml`

### CI Workflow

- [X] T045 [US1] Create CI workflow file in `.github/workflows/ci.yml`
- [X] T046 [US1] Add Python test jobs (shared, API, workers) to CI workflow
- [X] T047 [US1] Add Node.js test jobs (frontend Vitest) to CI workflow
- [X] T048 [US1] Configure dependency caching (uv, npm) in CI workflow
- [X] T049 [US1] Add linting jobs (ruff, eslint) to CI workflow
- [X] T050 [US1] Add E2E test job using Docker Compose CI environment
- [X] T051 [US1] Add Terraform validation step (terraform validate) to CI
- [X] T052 [US1] Add Kustomize validation step (kustomize build) to CI
- [X] T052a [US1] Add secret scanning step (gitleaks) to CI workflow

**Checkpoint**: PRs trigger full test suite; merge blocked on failure

---

## Phase 5: User Story 2 - Deploy to Staging on Merge (Priority: P2)

**Goal**: GitOps auto-deploys to staging when code merges to main

**Independent Test**: Merge a small change to main, verify Argo CD syncs and pods update

### Build & Push Workflow

- [X] T053 [US2] Create build-push workflow in `.github/workflows/build-push.yml`
- [X] T054 [US2] Add Azure OIDC login step using existing GitHub Actions credentials
- [X] T055 [US2] Add Docker build step for API service with commit SHA tag
- [X] T056 [US2] Add Docker build step for Workers service with commit SHA tag
- [X] T057 [US2] Add ACR push step (azure/docker-login + docker push)
- [X] T058 [US2] Add step to update image tags in `k8s/overlays/staging/kustomization.yaml`
- [X] T059 [US2] Commit and push the updated kustomization.yaml (triggers Argo CD sync)

### Frontend Deployment

- [X] T060 [US2] Add Static Web Apps deployment step for frontend

### Database Migrations

- [X] T061 [US2] Create migration Job manifest in `k8s/base/migration-job.yaml` (Argo CD PreSync hook)
- [X] T062 [US2] Add migration script with timeout and error handling in `scripts/run-migrations.ps1`

### Documentation

- [X] T063 [US2] Document Argo CD installation steps in `docs/aks-setup.md`
- [X] T064 [US2] Document Argo CD GitHub OIDC repository access setup in `docs/aks-setup.md`

**Checkpoint**: Merge to main → CI builds images → Argo CD auto-syncs staging

---

## Phase 6: User Story 3 - Manual Production Deployment (Priority: P3)

**Goal**: Production deployments require manual trigger and approval

**Independent Test**: Trigger production workflow, verify approval required, then Argo CD syncs production

### Production Workflow

- [X] T065 [US3] Create CD production workflow in `.github/workflows/cd-production.yml`
- [X] T066 [US3] Configure manual workflow_dispatch trigger with inputs
- [X] T067 [US3] Add GitHub environment protection rules for production (in workflow)
- [X] T068 [US3] Add step to copy staging image tags to production overlay
- [X] T069 [US3] Commit and push production kustomization.yaml (triggers Argo CD sync)
- [X] T070 [US3] Add production Static Web Apps deployment step
- [X] T071 [US3] Add deployment health check verification step
- [X] T071a [US3] Add workflow summary step with Azure portal and Argo CD dashboard links

**Checkpoint**: Production deployment requires approval; uses same artifacts as staging

---

## Phase 7: User Story 4 - Infrastructure as Code (Priority: P4)

**Goal**: Infrastructure changes deploy through the pipeline

**Independent Test**: Add a new resource via Terraform, verify it applies on merge

### Infrastructure Pipeline

- [X] T072 [US4] Create infrastructure deployment script in `scripts/deploy-infra.ps1`
- [X] T073 [US4] Add Terraform plan output as PR comment in CI
- [X] T074 [US4] Create infrastructure workflow in `.github/workflows/infra.yml`
- [X] T075 [US4] Add Argo CD Helm installation to Terraform AKS module

### Argo CD Configuration

- [X] T076 [US4] Configure Argo CD GitHub OIDC app credentials in Terraform
- [X] T077 [US4] Create Argo CD project configuration for yt-summarizer

**Checkpoint**: Infrastructure changes validated in PR, applied via Terraform

---

## Phase 8: Polish & Validation

**Purpose**: Documentation, security hardening, and end-to-end validation

### Documentation

- [X] T078 [P] Update quickstart.md with AKS/GitOps setup commands
- [X] T079 [P] Create Argo CD setup runbook in `docs/runbooks/argocd-setup.md`
- [X] T080 [P] Create CI/CD troubleshooting guide in `docs/runbooks/ci-cd-troubleshooting.md`
- [X] T081 [P] Document rollback procedure in `docs/runbooks/deployment-rollback.md`

### Security Audit

- [X] T082 [P] Verify secrets are not exposed in workflow logs (audit all workflows)
- [X] T083 [P] Verify RBAC least-privilege for AKS service account
- [X] T084 [P] Verify External Secrets are properly scoped to namespace

### Validation Tests

- [ ] T085 Validate full CI workflow with intentional test failure
- [ ] T086 Validate GitOps staging deployment end-to-end
- [ ] T087 Validate production deployment with approval gate
- [ ] T088 Validate rollback scenario (git revert triggers Argo CD rollback)
- [X] T089 Run existing test suite to verify no regressions: `.\scripts\run-tests.ps1`

---

## Dependencies & Execution Order

### Phase Dependencies

```
Phase 1: Setup ──────────────────┐
                                 │
Phase 2: Foundational (TF) ──────┼──► Phase 3: K8s Manifests
                                 │
         ┌───────────────────────┴───────────────────────┐
         │                                               │
         ▼                                               ▼
Phase 4: US1 (CI)              Phase 5: US2 (GitOps Staging)
         │                               │
         └───────────┬───────────────────┘
                     │
                     ▼
         Phase 6: US3 (Production CD)
                     │
                     ▼
         Phase 7: US4 (IaC)
                     │
                     ▼
         Phase 8: Polish
```

### GitOps Flow

```
Developer merges to main
         │
         ▼
GitHub Actions (build-push.yml)
├── Build API image → Push to ACR (sha-abc123)
├── Build Workers image → Push to ACR (sha-abc123)
├── Update k8s/overlays/staging/kustomization.yaml with new tags
└── Commit & push manifest changes
         │
         ▼
Argo CD (watching main branch via OIDC)
├── Detects manifest change
├── Compares desired vs live state
└── Syncs: applies new Deployments to AKS
         │
         ▼
Staging updated ✅
```

### Parallel Execution Opportunities

**Phase 1** (after T001):
- T002-T008 can all run in parallel

**Phase 2** (after Phase 1):
- T009-T015 can all run in parallel
- T016-T017 sequential (ESO depends on AKS)
- T018-T019 can run in parallel after modules complete

**Phase 3** (after Phase 2):
- T020-T025 can all run in parallel
- T027-T029 can all run in parallel
- T030-T033 can all run in parallel

**Phase 4** (after Phase 3):
- T037-T044 (Docker Compose) can run in parallel with T045-T052 (CI workflow)
- Within Docker Compose: T038-T042 all parallel after T037

---

## Task Summary

| Phase | Task Range | Count | Description |
|-------|------------|-------|-------------|
| 1 | T001-T008 | 8 | Setup & Dockerfiles |
| 2 | T009-T019 | 11 | Terraform Modules |
| 3 | T020-T036 | 20 | K8s Manifests (4 worker deployments) |
| 4 | T037-T052a | 20 | US1: CI Pipeline (4 workers + secret scanning) |
| 5 | T053-T064 | 12 | US2: Staging Deploy |
| 6 | T065-T071a | 8 | US3: Prod Deploy (+ portal links) |
| 7 | T072-T077 | 6 | US4: IaC Pipeline |
| 8 | T078-T089 | 12 | Polish & Validation |
| **Total** | | **97** | |

---

## Notes

- **Database**: MS SQL Server 2025 (mcr.microsoft.com/mssql/server:2025-latest) for native VECTOR support in dev/CI; Azure SQL serverless in Azure
- **Workers**: 4 separate K8s Deployments (transcribe, summarize, embed, relationships) from 1 unified Docker image; matches Aspire AppHost
- **GitOps**: Argo CD pulls from repo using GitHub OIDC; no static credentials
- **Rollback**: `git revert` the kustomization change, Argo CD auto-reverts
- **Ingress**: nginx-ingress controller for API routing
- **Secrets**: External Secrets Operator syncs Azure Key Vault → K8s Secrets
- **Local dev**: Unchanged - continue using Aspire + Docker
- **Cost**: ~$35/month (AKS B2s node + ACR Basic)
