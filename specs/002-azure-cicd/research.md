# Research: Azure CI/CD Pipelines

**Feature**: 002-azure-cicd  
**Date**: 2026-01-08  
**Purpose**: Resolve technical unknowns and establish best practices before design

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
- Nx/Turborepo for task orchestration - Rejected: adds complexity for a 3-service monorepo
- Always run everything - Accepted for simplicity; optimize later if CI time exceeds 15 min target

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

**GitOps Flow**:
```
Developer merges PR → CI builds image → Pushes to ACR
                                           ↓
                    Argo CD detects new image tag in k8s/ manifests
                                           ↓
                    Argo CD applies changes to AKS cluster
```

**Alternatives Considered**:
- ACA - Rejected: Variable cost, multiple apps add up
- k3s on VM - Rejected: More manual management
- Full AKS multi-node - Rejected: Overkill for hobby project

---

### 3. Argo CD for GitOps

**Question**: Which GitOps tool for Kubernetes deployments?

**Decision**: Argo CD

**Rationale**:
- Web UI for monitoring deployments and troubleshooting
- Visual diff of desired vs live state
- One-click rollback
- Health status aggregation across resources
- Active community, well-documented

**Installation**: Helm chart or manifests, installed in `argocd` namespace

**Application Definition**:
```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: yt-summarizer
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/AshleyHollis/yt-summarizer
    targetRevision: main
    path: k8s/overlays/staging
  destination:
    server: https://kubernetes.default.svc
    namespace: yt-summarizer
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```

**Alternatives Considered**:
- Flux - Rejected: No UI, harder to troubleshoot

---

### 4. Kustomize for K8s Manifests

**Question**: How to manage Kubernetes manifests with environment variations?

**Decision**: Kustomize with base + overlays

**Rationale**:
- Built into kubectl (`kubectl apply -k`)
- No templating language to learn (unlike Helm)
- Simple patching for environment differences
- Native K8s - no external tool installation

**Directory Structure**:
```
k8s/
├── base/                    # Shared manifests
│   ├── kustomization.yaml
│   ├── namespace.yaml
│   ├── api-deployment.yaml
│   ├── api-service.yaml
│   ├── workers-deployment.yaml
│   └── configmap.yaml
├── overlays/
│   ├── staging/
│   │   ├── kustomization.yaml
│   │   ├── patches/
│   │   └── secrets.yaml (sealed)
│   └── production/
│       ├── kustomization.yaml
│       ├── patches/
│       └── secrets.yaml (sealed)
```

**Alternatives Considered**:
- Helm - Rejected: More complex for small project

---

### 5. Azure Static Web Apps CI/CD

**Question**: How to integrate SWA with GitHub Actions and coordinate with backend?

**Decision**: Use SWA's built-in GitHub Action with deployment slots

**Rationale**:
- Azure provides `Azure/static-web-apps-deploy@v1` action
- Staging slot for preview, production slot for live
- SWA handles build internally (Node.js, npm)
- API_LOCATION can point to Azure Functions if needed (not used here - API is separate)
- Environment variables set via Azure portal or CLI

**Alternatives Considered**:
- Build externally and upload - Rejected: loses SWA build optimizations
- Vercel - Rejected: user chose Azure-native stack

---

### 4. Terraform State Management in Azure

**Question**: How to configure Azure Storage backend for Terraform state?

**Decision**: Dedicated resource group with storage account, container, and blob lease locking

**Rationale**:
- Create `rg-ytsummarizer-tfstate` resource group (separate from app resources)
- Storage account with versioning and soft delete enabled
- Container named `tfstate` with blob for each environment
- Use `azurerm` backend in Terraform with `use_oidc = true` for GitHub Actions auth

**Configuration Pattern**:
```hcl
terraform {
  backend "azurerm" {
    resource_group_name  = "rg-ytsummarizer-tfstate"
    storage_account_name = "stytsummarizertfstate"
    container_name       = "tfstate"
    key                  = "staging.tfstate"  # or production.tfstate
    use_oidc             = true
  }
}
```

---

### 5. GitHub Actions Authentication to Azure

**Question**: How to securely authenticate GitHub Actions to Azure without storing secrets?

**Decision**: Use OpenID Connect (OIDC) federation with Azure AD

**Rationale**:
- No secrets to rotate or leak
- GitHub Actions gets short-lived tokens via OIDC
- Azure AD app registration with federated credentials
- Separate service principals per environment for least privilege
- Uses `azure/login@v2` with `client-id`, `tenant-id`, `subscription-id`

**Setup Requirements**:
1. Create Azure AD App Registration for GitHub Actions
2. Add federated credential for `repo:AshleyHollis/yt-summarizer:*`
3. Grant Contributor role on subscription or specific resource groups
4. Store client-id, tenant-id, subscription-id as GitHub secrets (non-sensitive)

---

### 6. E2E Tests in CI (Without Aspire)

**Question**: How to run Playwright E2E tests in GitHub Actions without .NET Aspire?

**Decision**: Use Docker Compose for test environment, Playwright in container

**Rationale**:
- Aspire is a dev orchestrator; CI needs containerized approach
- Create `docker-compose.ci.yml` with API, 4 Workers (transcribe, summarize, embed, relationships), MS SQL Server 2025, Azurite
- Uses same database as local dev: `mcr.microsoft.com/mssql/server:2025-latest` (native VECTOR support)
- Workers run from unified Docker image with different entrypoints, matching Aspire AppHost configuration
- Playwright tests run against containerized services
- Use `mcr.microsoft.com/playwright:v1.40.0-jammy` for Playwright container
- Health checks ensure services are ready before tests run

**Alternatives Considered**:
- Skip E2E in CI - Rejected: AGENTS.md mandates E2E for completion
- Mock external services - Rejected: loses integration value
- Run Aspire in CI - Rejected: .NET SDK overhead, complexity

---

### 7. Database Migrations in Deployment

**Question**: How to safely run Alembic migrations during deployment?

**Decision**: Run migrations as a pre-deployment step with transaction and timeout

**Rationale**:
- Migrations run from a dedicated GitHub Actions step (not inside container)
- Use connection string from Key Vault / GitHub secrets
- `alembic upgrade head` with `--sql` dry-run option for review
- Timeout of 5 minutes for migration step
- Rollback: keep previous Alembic versions; manual `alembic downgrade` if needed

**Migration Safety**:
- All migrations MUST be backward-compatible (add columns, not remove)
- Destructive changes require multi-phase deployment

---

### 8. Secrets Management Strategy

**Question**: Where to store which secrets, and how to access them?

**Decision**: Tiered approach - GitHub Secrets for CI, Azure Key Vault for runtime

**Rationale**:

| Secret Type | Storage Location | Access Method |
|-------------|------------------|---------------|
| Azure OIDC credentials | GitHub Secrets | `azure/login` action |
| Terraform state access | OIDC (no secret) | Federated identity |
| OpenAI API Key | Azure Key Vault | K8s External Secrets or Sealed Secrets |
| Database connection string | Azure Key Vault | K8s External Secrets or Sealed Secrets |
| SWA deployment token | GitHub Secrets | SWA deploy action |
| ACR pull credentials | AKS Managed Identity | Attached to node pool |

**Principle**: Deployment credentials in GitHub, runtime credentials in Key Vault, synced to K8s via External Secrets

---

### 9. Terraform Scope - Azure Infrastructure Only

**Question**: Should Terraform manage Helm releases and Kubernetes resources?

**Decision**: NO - Terraform manages Azure infrastructure only; Argo CD manages all cluster resources

**Rationale**:

| Problem with Helm in Terraform | Impact |
|--------------------------------|--------|
| **Chicken-and-egg** | Helm/K8s providers need AKS credentials that don't exist until AKS is created |
| **Two-phase applies** | Often need `terraform apply` twice (once for AKS, once for Helm) |
| **State coupling** | Terraform state becomes coupled to cluster state; manual changes cause drift |
| **Blast radius** | Destroying infrastructure also destroys all cluster state |
| **Long applies** | Helm releases can take 5-10 minutes, making iterations slow |
| **Provider churn** | Helm provider v3.x has breaking changes from v2.x (set block syntax) |

**New Architecture**:

| Layer | Tool | Manages |
|-------|------|---------|
| **Azure Infrastructure** | Terraform | AKS, ACR, SQL, KeyVault, Storage, SWA |
| **Cluster Bootstrap** | `scripts/bootstrap-argocd.ps1` | Argo CD installation (one-time) |
| **Cluster Resources** | Argo CD | ingress-nginx, external-secrets, app workloads |

**Benefits**:
- Clean separation of concerns
- Terraform runs are fast (Azure API only)
- Cluster state is managed declaratively by GitOps
- No Helm/Kubernetes provider version issues
- Argo CD provides visibility, rollback, and self-heal for cluster resources

**Bootstrap Process**:
```bash
# 1. Terraform creates Azure infrastructure
terraform apply

# 2. Get AKS credentials
az aks get-credentials --resource-group rg-ytsumm-prd --name aks-ytsumm-prd

# 3. Bootstrap Argo CD (one-time)
./scripts/bootstrap-argocd.ps1

# 4. Apply Argo CD Applications for cluster infrastructure
kubectl apply -f k8s/argocd/infra-apps.yaml
```

**Argo CD Managed Infrastructure**:
```yaml
# k8s/argocd/infra-apps.yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: ingress-nginx
  namespace: argocd
spec:
  source:
    repoURL: https://kubernetes.github.io/ingress-nginx
    chart: ingress-nginx
    targetRevision: 4.9.1
    helm:
      values: |
        controller:
          replicaCount: 1
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
  destination:
    server: https://kubernetes.default.svc
    namespace: ingress-nginx
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
---
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: external-secrets
  namespace: argocd
spec:
  source:
    repoURL: https://charts.external-secrets.io
    chart: external-secrets
    targetRevision: 0.9.13
    helm:
      values: |
        installCRDs: true
        resources:
          requests:
            cpu: 50m
            memory: 64Mi
  destination:
    server: https://kubernetes.default.svc
    namespace: external-secrets
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
```

---

## Summary of Decisions

| Area | Decision |
|------|----------|
| Monorepo CI | Path filters + always-run-all for PRs |
| Backend hosting | AKS single-node (~$30/month fixed) - *deviates from constitution ACA; justified by cost* |
| GitOps tool | Argo CD (UI, auto-sync, rollback) |
| K8s manifests | Kustomize (base + overlays) |
| Frontend hosting | Azure Static Web Apps (free tier) |
| **Terraform scope** | **Azure infrastructure ONLY - no Helm/K8s providers** |
| Cluster bootstrap | Script + Argo CD Applications for ingress-nginx, external-secrets |
| Terraform state | Azure Storage with OIDC auth |
| Azure auth | OIDC federation (no secrets) |
| E2E in CI | Docker Compose test environment |
| Database | MS SQL Server 2025 (dev/CI) → Azure SQL serverless (prod) |
| Migrations | Alembic as K8s Job (PreSync hook) |
| Secrets | GitHub Secrets (CI) + Azure Key Vault → K8s External Secrets |
| Local dev | Aspire + Docker (unchanged) |

---

## Open Items for Implementation

1. **Docker Compose CI file**: Need to create `docker-compose.ci.yml` for E2E tests
2. **Azure AD setup**: Manual step to create app registration with federated credentials
3. **Terraform state bootstrap**: Manual one-time creation of state storage account
4. **Existing Dockerfiles**: Need to verify Dockerfiles work with docker buildx (multi-platform)
5. **Argo CD bootstrap script**: `scripts/bootstrap-argocd.ps1` to install Argo CD on AKS
6. **Argo CD infra apps**: `k8s/argocd/infra-apps.yaml` for ingress-nginx and external-secrets
7. **Kustomize base manifests**: Create K8s Deployments, Services, ConfigMaps
8. **SecretStore for ESO**: Configure Azure Key Vault integration after ESO is installed
