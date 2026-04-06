# Tasks: Azure CI/CD Pipelines

**Status**: Implementing
**Milestone**: M2
**Spec Phase**: execution
**Created**: 2026-01-08
**Updated**: 2026-01-09

## Overview
- **Total Tasks**: 94
- **Completed**: 89
- **Workflow**: POC-first (GREENFIELD)
- **Intent**: GREENFIELD

### Phase Distribution
| Phase | Tasks | Completed |
|-------|-------|-----------|
| Phase 1: Setup | 8 | 8 |
| Phase 2: Foundational | 18 | 18 |
| Phase 3: US1 — Automated CI | 14 | 14 |
| Phase 4: US2 — PR Previews | 31 | 31 |
| Phase 5: US3 — Production Deploy | 11 | 11 |
| Phase 6: US4 — Infrastructure as Code | 6 | 6 |
| Phase 7: Polish & Validation | 13 | 8 |

---

## Phase 1: Setup (Infrastructure Foundation)

**Goal**: Create project structure, Terraform config, and bootstrap Azure resources.

- [x] T01 [P] Create directory structure: `.github/workflows/`, `.github/actions/`, `infra/terraform/`, `k8s/`
  - **Agent**: Parker
  - **Files**: `.github/workflows/`, `.github/actions/`, `infra/terraform/`, `k8s/`
  - **Done when**: All required directories exist in repository
  - **Verify**: `git ls-files --directory .github infra k8s | head -5`
  - _Requirements: FR-001_

- [x] T02 [P] Create Terraform provider configuration
  - **Agent**: Parker
  - **Files**: `infra/terraform/providers.tf`
  - **Done when**: `providers.tf` defines AzureRM provider with OIDC auth
  - **Verify**: `cd infra/terraform && terraform validate`
  - _Requirements: FR-020_

- [x] T03 [P] Create Terraform backend configuration
  - **Agent**: Parker
  - **Files**: `infra/terraform/backend.tf`
  - **Done when**: Backend configured for Azure Storage with `use_oidc = true`
  - **Verify**: `cd infra/terraform && terraform init -backend=false`
  - _Requirements: FR-018_

- [x] T04 [P] Create common Terraform variables
  - **Agent**: Parker
  - **Files**: `infra/terraform/variables.tf`
  - **Done when**: Common variables declared (resource group, location, env)
  - **Verify**: `cd infra/terraform && terraform validate`
  - _Requirements: FR-024_

- [x] T05 [P] Create reusable Python setup composite action
  - **Agent**: Parker
  - **Files**: `.github/actions/setup-python/action.yml`
  - **Done when**: Action installs Python, uv, and caches dependencies
  - **Verify**: Action YAML validates; used by at least one workflow
  - _Requirements: FR-001, FR-004_

- [x] T06 [P] Create reusable Node.js setup composite action
  - **Agent**: Parker
  - **Files**: `.github/actions/setup-node/action.yml`
  - **Done when**: Action installs Node 20 and caches npm dependencies
  - **Verify**: Action YAML validates; used by at least one workflow
  - _Requirements: FR-001, FR-004_

- [x] T07 [P] Verify/update API Dockerfile for multi-platform builds
  - **Agent**: Ripley + Parker
  - **Files**: `services/api/Dockerfile`
  - **Done when**: Dockerfile builds successfully for linux/amd64 target
  - **Verify**: `docker build --platform linux/amd64 services/api`
  - _Requirements: FR-007_

- [x] T08 [P] Verify/update Workers Dockerfile for multi-platform builds
  - **Agent**: Ripley + Parker
  - **Files**: `services/workers/Dockerfile`
  - **Done when**: Dockerfile builds successfully for linux/amd64 target
  - **Verify**: `docker build --platform linux/amd64 services/workers`
  - _Requirements: FR-007_

---

## Phase 2: Foundational (Terraform Modules & K8s Base)

**Goal**: Create reusable Terraform modules and K8s base manifests.

- [x] T09 [P] Create Azure Container Registry Terraform module
  - **Agent**: Parker
  - **Files**: `infra/terraform/modules/container-registry/main.tf`
  - **Done when**: Module creates ACR with admin access disabled and geo-replication optional
  - **Verify**: `cd infra/terraform && terraform validate`
  - _Requirements: FR-007_

- [x] T10 [P] Create AKS single-node Terraform module
  - **Agent**: Parker
  - **Files**: `infra/terraform/modules/aks/main.tf`
  - **Done when**: Module creates single B2s node pool with ACR pull integration
  - **Verify**: `cd infra/terraform && terraform validate`
  - _Requirements: FR-006_

- [x] T11 [P] Create Azure Static Web Apps Terraform module
  - **Agent**: Lambert + Parker
  - **Files**: `infra/terraform/modules/static-web-app/main.tf`
  - **Done when**: Module creates SWA with Standard SKU (supports staging slots)
  - **Verify**: `cd infra/terraform && terraform validate`
  - _Requirements: FR-006_

- [x] T12 [P] Create Azure Storage Terraform module (blob + queue)
  - **Agent**: Parker
  - **Files**: `infra/terraform/modules/storage/main.tf`
  - **Done when**: Module creates storage account with blob containers and queues
  - **Verify**: `cd infra/terraform && terraform validate`
  - _Requirements: FR-024_

- [x] T13 [P] Create Azure SQL Database Terraform module
  - **Agent**: Parker
  - **Files**: `infra/terraform/modules/sql-database/main.tf`
  - **Done when**: Module creates serverless SQL DB with auto-pause enabled
  - **Verify**: `cd infra/terraform && terraform validate`
  - _Requirements: FR-024_

- [x] T14 [P] Create Azure Key Vault Terraform module
  - **Agent**: Parker
  - **Files**: `infra/terraform/modules/key-vault/main.tf`
  - **Done when**: Module creates Key Vault with RBAC authorization mode
  - **Verify**: `cd infra/terraform && terraform validate`
  - _Requirements: FR-018_

- [x] T15 Consolidate staging+production to single prod environment
  - **Agent**: Parker
  - **Files**: `infra/terraform/environments/prod/main.tf`
  - **Done when**: Single `prod/` environment replaces obsolete `staging/` and `production/` directories
  - **Verify**: `cd infra/terraform/environments/prod && terraform validate`
  - _Requirements: FR-013_

- [x] T16 Remove Helm/Kubernetes providers from Terraform prod environment
  - **Agent**: Parker
  - **Files**: `infra/terraform/environments/prod/providers.tf`
  - **Done when**: Helm and Kubernetes providers removed; AzureRM only
  - **Verify**: `cd infra/terraform/environments/prod && terraform init -backend=false && terraform validate`
  - _Requirements: FR-024_

- [x] T17 Delete obsolete Terraform modules
  - **Agent**: Parker
  - **Files**: `infra/terraform/modules/nginx-ingress/`, `infra/terraform/modules/external-secrets/`, `infra/terraform/modules/argocd/`
  - **Done when**: Obsolete modules removed; Argo CD manages these cluster resources
  - **Verify**: Directory listing confirms modules deleted
  - _Requirements: FR-024_

- [x] T18 Create Argo CD bootstrap script
  - **Agent**: Parker
  - **Files**: `scripts/bootstrap-argocd.ps1`
  - **Done when**: Script installs Argo CD into cluster and applies initial configuration
  - **Verify**: `scripts/bootstrap-argocd.ps1 --dry-run`
  - _Requirements: FR-006_

- [x] T19 [P] Create Argo CD infrastructure apps manifest
  - **Agent**: Parker
  - **Files**: `k8s/argocd/infra-apps.yaml`
  - **Done when**: Manifest declares Argo CD Applications for ingress-nginx and external-secrets
  - **Verify**: `kubectl apply --dry-run=client -f k8s/argocd/infra-apps.yaml`
  - _Requirements: FR-006_

- [x] T20 [P] Create SecretStore manifest for ESO → Azure Key Vault
  - **Agent**: Parker
  - **Files**: `k8s/base/secretstore.yaml`
  - **Done when**: SecretStore references Key Vault with workload identity auth
  - **Verify**: `kubectl apply --dry-run=client -f k8s/base/secretstore.yaml`
  - _Requirements: FR-018_

- [x] T21 [P] Create K8s namespace manifest
  - **Agent**: Parker
  - **Files**: `k8s/base/namespace.yaml`
  - **Done when**: Namespace manifest defines `yt-summarizer` namespace
  - **Verify**: `kubectl apply --dry-run=client -f k8s/base/namespace.yaml`
  - _Requirements: FR-008_

- [x] T22 [P] Create API Deployment with readiness/liveness probes
  - **Agent**: Ripley + Parker
  - **Files**: `k8s/base/api-deployment.yaml`
  - **Done when**: Deployment includes HTTP readiness and liveness probes on `/health`
  - **Verify**: `kubectl apply --dry-run=client -f k8s/base/api-deployment.yaml`
  - _Requirements: FR-012, FR-017_

- [x] T23 [P] Create API Service (ClusterIP) and Ingress
  - **Agent**: Parker
  - **Files**: `k8s/base/api-service.yaml`, `k8s/base/api-ingress.yaml`
  - **Done when**: Service exposes API pod; Ingress routes external traffic
  - **Verify**: `kubectl apply --dry-run=client -f k8s/base/`
  - _Requirements: FR-006_

- [x] T24 [P] Create worker deployments
  - **Agent**: Ripley + Parker
  - **Files**: `k8s/base/*-worker-deployment.yaml` (transcribe, summarize, embed, relationships)
  - **Done when**: All four worker deployments defined with health probes
  - **Verify**: `kubectl apply --dry-run=client -f k8s/base/`
  - _Requirements: FR-007_

- [x] T25 [P] Create ConfigMap and ExternalSecrets
  - **Agent**: Parker
  - **Files**: `k8s/base/configmap.yaml`, `k8s/base/externalsecret-*.yaml`
  - **Done when**: ConfigMap holds non-secret config; ExternalSecrets sync from Key Vault
  - **Verify**: `kubectl apply --dry-run=client -f k8s/base/`
  - _Requirements: FR-018_

- [x] T26 Create base kustomization.yaml
  - **Agent**: Parker
  - **Files**: `k8s/base/kustomization.yaml`
  - **Done when**: kustomization.yaml lists all base resources; `kubectl kustomize k8s/base` succeeds
  - **Verify**: `kubectl kustomize k8s/base`
  - _Requirements: FR-006_

---

## Phase 3: US1 — Automated Testing on PR

**Goal**: All tests run automatically when a PR is created or updated; merge blocked on failure.

- [x] T27 Create Docker Compose reference file
  - **Agent**: Parker
  - **Files**: `docker-compose.ci.yml`
  - **Done when**: Compose file defines MS SQL Server 2025, Azurite, API, workers with healthchecks
  - **Verify**: `docker compose -f docker-compose.ci.yml config`
  - _Requirements: FR-001_

- [x] T28 [P] Create CI workflow
  - **Agent**: Parker
  - **Files**: `.github/workflows/ci.yml`
  - **Done when**: Workflow triggers on `pull_request` and `push` to main
  - **Verify**: `gh workflow view ci.yml`
  - _Requirements: FR-001, FR-002_

- [x] T29 [P] Add Python test jobs (shared, API, workers) to CI workflow
  - **Agent**: Parker
  - **Files**: `.github/workflows/ci.yml`
  - **Done when**: `test-shared`, `test-api`, `test-workers` jobs run pytest with uv
  - **Verify**: `gh run list --workflow ci.yml -L 3`
  - _Requirements: FR-001, FR-003_

- [x] T30 [P] Add Node.js test jobs (frontend Vitest) to CI workflow
  - **Agent**: Lambert + Parker
  - **Files**: `.github/workflows/ci.yml`
  - **Done when**: `test-frontend` job runs `npm run test` (Vitest)
  - **Verify**: `gh run view --log <run-id> | grep test-frontend`
  - _Requirements: FR-001, FR-003_

- [x] T31 [P] Configure dependency caching (uv, npm) in CI workflow
  - **Agent**: Parker
  - **Files**: `.github/workflows/ci.yml`
  - **Done when**: uv cache and npm cache configured; second run observably faster
  - **Verify**: Check cache hit in workflow run log
  - _Requirements: FR-004_

- [x] T32 [P] Add linting jobs (ruff, eslint) to CI workflow
  - **Agent**: Parker
  - **Files**: `.github/workflows/ci.yml`
  - **Done when**: `lint-python` (ruff) and `lint-frontend` (eslint + tsc) jobs run
  - **Verify**: `gh run view --log <run-id> | grep lint`
  - _Requirements: FR-005_

- [x] T33 [P] Add Terraform validation step to CI
  - **Agent**: Parker
  - **Files**: `.github/workflows/ci.yml`
  - **Done when**: `validate-terraform` job runs `terraform validate` on `infra/terraform/`
  - **Verify**: `gh run view --log <run-id> | grep validate-terraform`
  - _Requirements: FR-024_

- [x] T34 [P] Add Kustomize validation step to CI
  - **Agent**: Parker
  - **Files**: `.github/workflows/ci.yml`
  - **Done when**: `validate-k8s` job runs `kubectl kustomize` on base and prod overlay
  - **Verify**: `gh run view --log <run-id> | grep validate-k8s`
  - _Requirements: FR-006_

- [x] T35 [P] Add secret scanning (gitleaks) to CI workflow
  - **Agent**: Parker
  - **Files**: `.github/workflows/ci.yml`
  - **Done when**: `security-scan` job runs gitleaks on every PR; fails on secrets found
  - **Verify**: `gh run view --log <run-id> | grep security-scan`
  - _Requirements: FR-018, FR-019_

- [x] T36 Add frontend build validation to CI (`npm run build`)
  - **Agent**: Lambert + Parker
  - **Files**: `.github/workflows/ci.yml`
  - **Done when**: `build-frontend` job runs `npm run build`; fails on TypeScript errors
  - **Verify**: `gh run view --log <run-id> | grep build-frontend`
  - _Requirements: FR-005_

## [VERIFY] V1 — CI Checkpoint
- [x] CI workflow runs on every PR
- [x] All test jobs (shared, API, workers, frontend) pass
- [x] Linting, type-check, and build validation pass
- [x] PR merge blocked when any check fails
- **Verify**: `gh pr checks <pr-number>`

---

## Phase 4: US2 — PR Preview Environments

**Goal**: Deploy ephemeral preview environment for each PR after CI passes; auto-clean on PR close.

### Production Overlay

- [x] T37 Create prod overlay
  - **Agent**: Parker
  - **Files**: `k8s/overlays/prod/kustomization.yaml`, `k8s/overlays/prod/patches/`
  - **Done when**: `kubectl kustomize k8s/overlays/prod` renders valid manifests
  - **Verify**: `kubectl kustomize k8s/overlays/prod`
  - _Requirements: FR-013_

- [x] T38 [P] Delete obsolete overlays
  - **Agent**: Parker
  - **Files**: `k8s/overlays/staging/`, `k8s/overlays/production/`
  - **Done when**: Obsolete directories removed; only `prod/` and `previews/` remain
  - **Verify**: `ls k8s/overlays/`
  - _Requirements: FR-013_

### Preview Overlay Templates

- [x] T39 [P] Create preview ResourceQuota and LimitRange templates
  - **Agent**: Parker
  - **Files**: `k8s/overlays/previews/_template/resource-quota.yaml`, `k8s/overlays/previews/_template/limit-range.yaml`
  - **Done when**: Templates define resource limits protecting production from preview workloads
  - **Verify**: `kubectl apply --dry-run=client -f k8s/overlays/previews/_template/resource-quota.yaml`
  - _Requirements: FR-010_

- [x] T40 [P] Create preview kustomization and namespace templates
  - **Agent**: Parker
  - **Files**: `k8s/overlays/previews/_template/kustomization.yaml`, `k8s/overlays/previews/_template/namespace.yaml`
  - **Done when**: Templates parametrize PR number for namespace scoping
  - **Verify**: `kubectl kustomize k8s/overlays/previews/_template`
  - _Requirements: FR-008_

- [x] T41 [P] Create preview Ingress patch template
  - **Agent**: Parker
  - **Files**: `k8s/overlays/previews/_template/patches/ingress-patch.yaml`
  - **Done when**: Template patches ingress hostname to `api-pr-<num>.yt-summarizer.apps.ashleyhollis.com`
  - **Verify**: Template contains `api-pr` hostname pattern
  - _Requirements: FR-001_

### Argo CD Configuration

- [x] T42 Create Argo CD prod Application
  - **Agent**: Parker
  - **Files**: `k8s/argocd/prod-app.yaml`
  - **Done when**: Application points to `k8s/overlays/prod` on `main` branch with auto-sync
  - **Verify**: `kubectl apply --dry-run=client -f k8s/argocd/prod-app.yaml`
  - _Requirements: FR-013_

- [x] T43 Create Argo CD ApplicationSet for previews
  - **Agent**: Parker
  - **Files**: `k8s/argocd/preview-appset.yaml`
  - **Done when**: ApplicationSet uses Pull Request Generator to auto-create apps per open PR
  - **Verify**: `kubectl apply --dry-run=client -f k8s/argocd/preview-appset.yaml`
  - _Requirements: FR-006, FR-008_

- [x] T44 Delete obsolete Argo CD apps (staging-app, production-app)
  - **Agent**: Parker
  - **Files**: `k8s/argocd/staging-app.yaml`, `k8s/argocd/production-app.yaml`
  - **Done when**: Obsolete app definitions removed; only `prod-app.yaml` and `preview-appset.yaml` remain
  - **Verify**: `ls k8s/argocd/`
  - _Requirements: FR-013_

### Preview Workflow

- [x] T45 Create preview workflow
  - **Agent**: Parker
  - **Files**: `.github/workflows/preview.yml`
  - **Done when**: Workflow triggers after CI passes on PR; builds images, generates overlay, deploys SWA staging
  - **Verify**: `gh workflow view preview.yml`
  - _Requirements: FR-006, FR-007_

- [x] T46 [P] Add Azure OIDC + ACR login to preview workflow
  - **Agent**: Parker
  - **Files**: `.github/workflows/preview.yml`
  - **Done when**: Workflow authenticates to Azure via OIDC; `docker push` to ACR succeeds
  - **Verify**: Workflow run log shows successful ACR push
  - _Requirements: FR-020_

- [x] T47 [P] Add Docker build step with PR-SHA tags
  - **Agent**: Parker
  - **Files**: `.github/workflows/preview.yml`
  - **Done when**: API and workers images built and pushed with tag `pr-<num>-<sha>`
  - **Verify**: `az acr repository show-tags --name <acr> --repository api`
  - _Requirements: FR-007, FR-023_

- [x] T48 Add step to generate preview overlay from template
  - **Agent**: Parker
  - **Files**: `.github/workflows/preview.yml`
  - **Done when**: `k8s/overlays/previews/pr-<number>/` created and committed to PR branch
  - **Verify**: Overlay directory exists in PR branch after workflow runs
  - _Requirements: FR-008_

- [x] T49 Add step to post preview URL as PR comment
  - **Agent**: Parker
  - **Files**: `.github/workflows/preview.yml`
  - **Done when**: PR comment shows preview URL and deployment status
  - **Verify**: PR shows comment with `api-pr-<num>` URL
  - _Requirements: FR-009_

- [x] T50 Add concurrency limit (max 3 previews) to preview workflow
  - **Agent**: Parker
  - **Files**: `.github/workflows/preview.yml`
  - **Done when**: Workflow rejects new preview if 3+ active previews exist
  - **Verify**: Fourth concurrent PR triggers concurrency gate
  - _Requirements: FR-010_

### Preview Hostname & TLS

- [x] T51 Install cert-manager via Argo CD infra-apps
  - **Agent**: Parker
  - **Files**: `k8s/argocd/infra-apps.yaml`
  - **Done when**: cert-manager running in `cert-manager` namespace
  - **Verify**: `kubectl get pods -n cert-manager`
  - _Requirements: FR-001_

- [x] T52 [P] Create ClusterIssuer for Let's Encrypt (DNS-01 via Cloudflare)
  - **Agent**: Parker
  - **Files**: `k8s/argocd/cert-manager/clusterissuer-cloudflare.yaml`
  - **Done when**: ClusterIssuers `letsencrypt-staging` and `letsencrypt-prod` deployed; wildcard cert issued
  - **Verify**: `kubectl get clusterissuer`
  - _Requirements: FR-001_

- [x] T53 Update preview Ingress template for TLS with wildcard cert
  - **Agent**: Parker
  - **Files**: `k8s/overlays/previews/_template/patches/ingress-patch.yaml`
  - **Done when**: Ingress template includes TLS block referencing shared wildcard secret
  - **Verify**: Template YAML includes `tls:` block
  - _Requirements: FR-001_

- [x] T54 [P] Create compute-preview-urls composite action
  - **Agent**: Parker
  - **Files**: `.github/actions/compute-preview-urls/action.yml`
  - **Done when**: Action outputs `preview_backend_url` as `https://api-pr-<num>.yt-summarizer.apps.ashleyhollis.com`
  - **Verify**: Action YAML defines correct output
  - _Requirements: FR-009_

- [x] T55 [P] Create verify-certificate composite action
  - **Agent**: Parker
  - **Files**: `.github/actions/verify-certificate/`
  - **Done when**: Action polls until wildcard TLS secret exists in cluster; fails on timeout
  - **Verify**: Action YAML defines check loop
  - _Requirements: FR-012_

- [x] T56 Validate secure preview E2E (Playwright against preview URL)
  - **Agent**: Kane
  - **Files**: `.github/workflows/preview.yml`
  - **Done when**: Playwright E2E tests run against `https://` preview URL; all 153 tests pass
  - **Verify**: `gh run view 22490929040 --log | grep -i "153 passed"`
  - _Requirements: FR-012, AC-2.3_

### Cleanup Workflow

- [x] T57 Create preview cleanup workflow
  - **Agent**: Parker
  - **Files**: `.github/workflows/preview-cleanup.yml`
  - **Done when**: Workflow triggers on PR close/merge; deletes overlay directory and commits deletion
  - **Verify**: `gh workflow view preview-cleanup.yml`
  - _Requirements: FR-011_

- [x] T58 [P] Delete obsolete workflows (build-push.yml, cd-production.yml)
  - **Agent**: Parker
  - **Files**: `.github/workflows/build-push.yml`, `.github/workflows/cd-production.yml`
  - **Done when**: Obsolete workflows removed from repository
  - **Verify**: `ls .github/workflows/`
  - _Requirements: FR-013_

## [VERIFY] V2 — Preview Checkpoint
- [x] PR opens → preview deployed and accessible via HTTPS URL
- [x] PR comment shows preview URL with status
- [x] PR closes → preview environment torn down within 5 minutes
- [x] Concurrent PR previews isolated (no cross-PR interference)
- **Verify**: `gh run list --workflow preview.yml`

---

## Phase 5: US3 — Automatic Production Deployment on Merge

**Goal**: Production automatically deploys with validated artifacts on merge to main.

- [x] T59 Create deploy-prod workflow
  - **Agent**: Parker
  - **Files**: `.github/workflows/deploy-prod.yml`
  - **Done when**: Workflow triggered by `workflow_run` after `ci.yml` completes on `main`
  - **Verify**: `gh workflow view deploy-prod.yml`
  - _Requirements: FR-013_

- [x] T60 [P] Add trigger on CI pass (workflow_run)
  - **Agent**: Parker
  - **Files**: `.github/workflows/deploy-prod.yml`
  - **Done when**: `workflow_run` trigger configured for `ci.yml` completion on main
  - **Verify**: Workflow config contains `workflow_run` trigger
  - _Requirements: FR-013_

- [x] T61 [P] Add step to update prod kustomization with image digests
  - **Agent**: Parker
  - **Files**: `.github/workflows/deploy-prod.yml`, `k8s/overlays/prod/kustomization.yaml`
  - **Done when**: Image digests from merged PR written to prod overlay and committed
  - **Verify**: `git log k8s/overlays/prod/kustomization.yaml | head -5`
  - _Requirements: FR-014, FR-015_

- [x] T62 [P] Add post-deploy health check/smoke test step
  - **Agent**: Parker + Kane
  - **Files**: `.github/workflows/deploy-prod.yml`
  - **Done when**: Workflow polls `/health/live` and `/health/ready` after Argo CD sync
  - **Verify**: Workflow run log shows health checks passing
  - _Requirements: FR-017_

- [x] T63 [P] Add workflow summary with production URL and Argo CD link
  - **Agent**: Parker
  - **Files**: `.github/workflows/deploy-prod.yml`
  - **Done when**: Workflow step summary includes prod URL and ArgoCD app URL
  - **Verify**: `gh run view <run-id> --log | grep argo`
  - _Requirements: FR-021, FR-022_

- [x] T64 Create PriorityClass for production pods
  - **Agent**: Parker
  - **Files**: `k8s/base/priority-class.yaml`
  - **Done when**: `production-critical` PriorityClass defined; production deployments reference it
  - **Verify**: `kubectl apply --dry-run=client -f k8s/base/priority-class.yaml`
  - _Requirements: FR-010_

- [x] T65 [P] Add SWA production deployment to deploy-prod workflow
  - **Agent**: Lambert + Parker
  - **Files**: `.github/workflows/deploy-prod.yml`
  - **Done when**: SWA production slot deployed via `Azure/static-web-apps-deploy@v1`
  - **Verify**: Workflow run log shows SWA deployment step success
  - _Requirements: FR-013_

## [VERIFY] V3 — Production Deploy Checkpoint
- [x] Merge to main → production auto-deploys within 10 minutes
- [x] Production serves merged changes
- [x] Deployment summary shows prod URL and ArgoCD link
- [x] Rollback via git revert auto-syncs through ArgoCD
- **Verify**: `gh run list --workflow deploy-prod.yml | head -3`

---

## Phase 6: US4 — Infrastructure as Code

**Goal**: Infrastructure changes flow through the pipeline with plan-on-PR and apply-on-merge.

- [x] T66 Create infrastructure workflow
  - **Agent**: Parker
  - **Files**: `.github/workflows/infra.yml`
  - **Done when**: `terraform plan` runs on PRs with output as comment; `terraform apply` runs on merge
  - **Verify**: `gh workflow view infra.yml`
  - _Requirements: FR-024, FR-025_

- [x] T67 [P] Add Terraform plan output as PR comment
  - **Agent**: Parker
  - **Files**: `.github/workflows/infra.yml`
  - **Done when**: PR comment shows `terraform plan` output when `infra/` files change
  - **Verify**: Open PR touching `infra/terraform/`; verify plan comment appears
  - _Requirements: FR-024, AC-4.1_

- [x] T68 [P] Create infrastructure deployment script
  - **Agent**: Parker
  - **Files**: `scripts/deploy-infra.ps1`
  - **Done when**: Script runs `terraform apply` with OIDC auth for manual/emergency use
  - **Verify**: `scripts/deploy-infra.ps1 --plan-only`
  - _Requirements: FR-025_

- [x] T69 [P] Configure Argo CD GitHub OIDC app credentials in Terraform
  - **Agent**: Parker
  - **Files**: `infra/terraform/environments/prod/main.tf`
  - **Done when**: Terraform manages Argo CD GitHub app credentials for Pull Request Generator
  - **Verify**: `cd infra/terraform/environments/prod && terraform plan`
  - _Requirements: FR-006_

- [x] T70 [P] Create Argo CD project configuration
  - **Agent**: Parker
  - **Files**: `k8s/argocd/` (project manifest)
  - **Done when**: `yt-summarizer` ArgoCD project defined with correct source/destination restrictions
  - **Verify**: `kubectl apply --dry-run=client -f k8s/argocd/`
  - _Requirements: FR-006_

---

## Phase 7: Polish & Validation

**Goal**: Documentation, security audit, and end-to-end validation of the complete pipeline.

- [x] T71 [P] Update quickstart.md with new preview/prod workflow
  - **Agent**: Dallas
  - **Files**: `specs/002-azure-cicd/quickstart.md`
  - **Done when**: Quickstart reflects PR preview → production flow and new architecture
  - **Verify**: File updated and mentions Gateway API + wildcard TLS architecture
  - _Requirements: FR-022_

- [x] T72 [P] Update runbooks (ArgoCD, rollback, troubleshooting)
  - **Agent**: Dallas + Parker
  - **Files**: `docs/runbooks/argocd-setup.md`, `docs/runbooks/deployment-rollback.md`, `docs/runbooks/ci-cd-troubleshooting.md`
  - **Done when**: Runbooks reflect ApplicationSet with Pull Request Generator; rollback uses git revert
  - **Verify**: Files updated with current architecture
  - _Requirements: FR-022_

- [x] T73 [P] Security audit: verify secrets not in workflow logs
  - **Agent**: Parker
  - **Files**: `.github/workflows/*.yml`
  - **Done when**: All workflows audited; `::add-mask::` used for any sensitive outputs; no plaintext secrets in logs
  - **Verify**: `grep -r "::add-mask::" .github/workflows/`
  - _Requirements: FR-019_

- [x] T74 [P] Verify RBAC least-privilege for AKS service account
  - **Agent**: Parker
  - **Files**: `k8s/` (RBAC manifests)
  - **Done when**: Service accounts scoped to minimum required permissions
  - **Verify**: `kubectl auth can-i --list --as=system:serviceaccount:yt-summarizer:default`
  - _Requirements: FR-020_

- [x] T75 [P] Verify External Secrets namespace scoping
  - **Agent**: Parker
  - **Files**: `k8s/base/externalsecret-*.yaml`
  - **Done when**: ExternalSecrets reference Key Vault scoped to their namespace
  - **Verify**: `kubectl apply --dry-run=client -f k8s/base/externalsecret-*.yaml`
  - _Requirements: FR-018_

- [x] T76 Validate CI workflow with intentional test failure (E2E)
  - **Agent**: Kane
  - **Files**: CI workflow validation (external)
  - **Done when**: PR with failing test shows CI blocked (runs 20850663682, 20850687881); after fix CI passes (run 20850765998)
  - **Verify**: `gh run view 20850765998 --log | grep -i "passed"`
  - _Requirements: FR-002, AC-1.2_

- [x] T77 Validate PR preview deploy end-to-end
  - **Agent**: Kane
  - **Files**: Preview workflow validation (external)
  - **Done when**: PR #141 preview accessible at SWA URL; E2E run 22490929040 shows 153 tests passed
  - **Verify**: `gh run view 22490929040 --log | grep -i "status"`
  - _Requirements: FR-006, FR-012, AC-2.1, AC-2.3_

- [x] T78 Validate PR preview cleanup
  - **Agent**: Kane
  - **Files**: Cleanup workflow validation (external)
  - **Done when**: PR #141 merged → `preview-cleanup.yml` ran → overlay removed → ArgoCD pruned app
  - **Verify**: `gh run list --workflow preview-cleanup.yml | head -3`
  - _Requirements: FR-011, AC-2.5_

- [ ] T79 Validate merge-to-prod auto-deploy (end-to-end)
  - **Agent**: Kane + Parker
  - **Files**: Production deployment validation (external)
  - **Done when**: Run 22271246265 confirmed all jobs succeeded: CI wait, frontend deploy, ArgoCD sync, health checks, TLS verify
  - **Verify**: `gh run view 22271246265 --log | grep -i "succeeded"`
  - _Requirements: FR-013, FR-014, AC-3.1, AC-3.2_

- [ ] T80 Validate GitOps rollback via git revert
  - **Agent**: Kane + Parker
  - **Files**: Production rollback validation (external)
  - **Done when**: Commit `41e3cdb` (revert) on main auto-synced by ArgoCD to restore previous state
  - **Verify**: `git log --oneline main | grep revert | head -3`
  - _Requirements: FR-016, AC-3.4_

- [ ] T81 Run full regression test suite
  - **Agent**: Kane
  - **Files**: All test suites
  - **Done when**: `.\scripts\run-tests.ps1` exits 0 with no failures
  - **Verify**: `.\scripts\run-tests.ps1`
  - _Requirements: FR-001_

## [VERIFY] V4 — Final Validation Checkpoint
- [ ] All validation scenarios confirmed end-to-end
- [ ] All CI checks green on main
- [ ] Production deployment functional
- [ ] Preview lifecycle (create → validate → cleanup) confirmed
- **Verify**: `gh run list --branch main | head -5`
