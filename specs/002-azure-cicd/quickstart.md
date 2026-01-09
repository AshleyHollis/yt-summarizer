# Quickstart: Azure CI/CD Pipelines (AKS + GitOps)

**Feature**: 002-azure-cicd  
**Date**: 2026-01-08  
**Purpose**: Step-by-step guide to set up and use the CI/CD pipelines

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│  GitOps Flow                                                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│   PR → CI Tests → Merge → Build Images → Update k8s/ → Argo CD Syncs   │
│                              │                                          │
│                              ▼                                          │
│                    ┌─────────────────┐                                  │
│                    │  Azure ACR      │                                  │
│                    │  (images)       │                                  │
│                    └────────┬────────┘                                  │
│                             │ pulls                                     │
│                             ▼                                           │
│   ┌────────────────────────────────────────────────────────┐            │
│   │  AKS Single-Node Cluster (~$30/month)                  │            │
│   │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────────┐  │            │
│   │  │ API Pod  │ │ Workers  │ │  Redis   │ │ Argo CD   │  │            │
│   │  └──────────┘ └──────────┘ └──────────┘ └───────────┘  │            │
│   └────────────────────────────────────────────────────────┘            │
│                                                                         │
│   ┌────────────────────────────────────────────────────────┐            │
│   │  Azure Static Web Apps (free tier)                     │            │
│   │  - Next.js frontend with CDN                           │            │
│   └────────────────────────────────────────────────────────┘            │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**Estimated Monthly Cost**: ~$35/month
- AKS cluster: ~$30/month (single Standard_B2s node)
- ACR Basic: ~$5/month
- SWA: Free tier
- Azure SQL: Existing

## Prerequisites

Before using the CI/CD pipelines, complete these one-time setup steps:

### 1. Azure Subscription Setup

```powershell
# Login to Azure
az login

# Set subscription
az account set --subscription "<your-subscription-id>"

# Create resource group for Terraform state
az group create --name rg-ytsummarizer-tfstate --location eastus

# Create storage account for Terraform state
az storage account create `
  --name stytsummarizertfstate `
  --resource-group rg-ytsummarizer-tfstate `
  --sku Standard_LRS `
  --allow-blob-public-access false

# Create container for state files
az storage container create `
  --name tfstate `
  --account-name stytsummarizertfstate
```

### 2. Azure AD App Registration (OIDC)

```powershell
# Create app registration for GitHub Actions
az ad app create --display-name "github-actions-ytsummarizer"

# Get the app ID
$appId = az ad app list --display-name "github-actions-ytsummarizer" --query "[0].appId" -o tsv

# Create service principal
az ad sp create --id $appId

# Get object ID of the service principal
$spObjectId = az ad sp list --filter "appId eq '$appId'" --query "[0].id" -o tsv

# Assign Contributor role (scope to subscription or specific RGs)
az role assignment create `
  --assignee-object-id $spObjectId `
  --assignee-principal-type ServicePrincipal `
  --role Contributor `
  --scope "/subscriptions/<subscription-id>"

# Add federated credential for GitHub Actions (main branch)
az ad app federated-credential create `
  --id $appId `
  --parameters '{
    "name": "github-actions-main",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:AshleyHollis/yt-summarizer:ref:refs/heads/main",
    "audiences": ["api://AzureADTokenExchange"]
  }'

# Add federated credential for production environment
az ad app federated-credential create `
  --id $appId `
  --parameters '{
    "name": "github-actions-production",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:AshleyHollis/yt-summarizer:environment:production",
    "audiences": ["api://AzureADTokenExchange"]
  }'
```

### 3. GitHub Repository Setup

1. **Add GitHub Secrets** (Settings → Secrets and variables → Actions):

   | Secret Name | Value | Notes |
   |-------------|-------|-------|
   | `AZURE_CLIENT_ID` | App registration client ID | From step 2 |
   | `AZURE_TENANT_ID` | Azure AD tenant ID | `az account show --query tenantId` |
   | `AZURE_SUBSCRIPTION_ID` | Subscription ID | `az account show --query id` |

2. **Create GitHub Environments** (Settings → Environments):

   - **staging**: No protection rules (auto-deploy on merge)
   - **production**: Add required reviewers for approval gate

3. **Enable GitHub Actions** (Settings → Actions → General):
   - Allow all actions and reusable workflows
   - Workflow permissions: Read and write

---

## Initial Infrastructure Setup

After Terraform modules are created, deploy the infrastructure:

```powershell
# Navigate to infrastructure directory
cd infra/environments/staging

# Initialize Terraform
terraform init

# Review the plan
terraform plan

# Apply (creates AKS cluster, ACR, Key Vault)
terraform apply
```

### Install Argo CD

```powershell
# Get AKS credentials
az aks get-credentials `
  --resource-group rg-ytsummarizer-staging `
  --name aks-ytsummarizer-staging

# Create Argo CD namespace
kubectl create namespace argocd

# Install Argo CD
kubectl apply -n argocd `
  -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

# Wait for Argo CD to be ready
kubectl wait --for=condition=available deployment/argocd-server `
  -n argocd --timeout=300s

# Get initial admin password
$argoPassword = kubectl -n argocd get secret argocd-initial-admin-secret `
  -o jsonpath="{.data.password}" | 
  % { [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($_)) }

Write-Host "Argo CD admin password: $argoPassword"

# Port-forward to access UI (local only)
kubectl port-forward svc/argocd-server -n argocd 8080:443
# Then visit: https://localhost:8080
```

### Register Application with Argo CD

```powershell
# Apply the Argo CD Application manifest
kubectl apply -f k8s/argocd/application.yaml
```

---

## Usage

### Pull Request Testing

When you create or update a PR:
1. CI workflow triggers automatically
2. All tests run (shared, workers, API, frontend, E2E)
3. Results appear as PR check status
4. Merge is blocked if any test fails

**View results**: Click "Details" on the PR check or go to Actions tab

### Deploy to Staging (GitOps Flow)

When you merge to `main`:
1. **build-push.yml** triggers:
   - Builds Docker images for API and Workers
   - Pushes to Azure Container Registry with SHA tag
   - Updates `k8s/overlays/staging/kustomization.yaml` with new image tags
   - Commits change back to repository
2. **Argo CD** detects the commit and syncs:
   - Pulls new manifests from `k8s/overlays/staging/`
   - Applies changes to AKS cluster
   - Performs health checks on pods
3. **SWA Deploy** runs in parallel:
   - Builds Next.js frontend
   - Deploys to Azure Static Web Apps

**View staging**: 
- App: `https://ytsummarizer-staging.azurestaticapps.net`
- Argo CD: `kubectl port-forward svc/argocd-server -n argocd 8080:443`

### Deploy to Production

Production requires manual trigger with approval:

1. Go to **Actions** → **CD Production** workflow
2. Click **Run workflow**
3. Select the commit/tag to deploy
4. Approvers receive notification
5. Once approved:
   - Updates `k8s/overlays/production/kustomization.yaml`
   - Argo CD syncs production environment

**View production**: `https://ytsummarizer.azurestaticapps.net`

### Rollback

GitOps makes rollback simple - just revert to a previous commit:

```powershell
# Option 1: Git revert (recommended - maintains history)
git revert <commit-sha>
git push origin main
# Argo CD will sync the reverted state automatically

# Option 2: Argo CD rollback (immediate)
# In Argo CD UI: Applications → yt-summarizer → History → Rollback

# Option 3: kubectl rollback (emergency)
kubectl rollout undo deployment/api -n yt-summarizer
kubectl rollout undo deployment/workers -n yt-summarizer
```

---

## Directory Structure

```
k8s/
├── base/                      # Shared K8s resources
│   ├── kustomization.yaml
│   ├── namespace.yaml
│   ├── api-deployment.yaml
│   ├── api-service.yaml
│   ├── workers-deployment.yaml
│   └── redis-deployment.yaml
├── overlays/
│   ├── staging/               # Staging-specific patches
│   │   ├── kustomization.yaml # Image tags updated by CI
│   │   └── patches/
│   └── production/            # Production-specific patches
│       ├── kustomization.yaml
│       └── patches/
└── argocd/
    └── application.yaml       # Argo CD Application CRD
```

---

## Troubleshooting

### CI Workflow Fails

1. **Check workflow logs**: Actions → Failed workflow → Click job → Expand failed step
2. **Common issues**:
   - Test failures: Fix tests locally, push update
   - Dependency install fails: Check if package versions are pinned
   - E2E timeout: Docker services may need more startup time

### Argo CD Sync Fails

1. **Check Argo CD UI**:
   ```powershell
   kubectl port-forward svc/argocd-server -n argocd 8080:443
   # Visit https://localhost:8080
   ```
2. **Check sync status**:
   ```powershell
   kubectl get applications -n argocd
   kubectl describe application yt-summarizer -n argocd
   ```
3. **Common issues**:
   - Image not found: Check ACR push succeeded
   - Resource conflict: Check for manual changes to cluster
   - Secret missing: Verify External Secrets sync

### Pod Failures

1. **Check pod status**:
   ```powershell
   kubectl get pods -n yt-summarizer
   kubectl describe pod <pod-name> -n yt-summarizer
   ```
2. **Check logs**:
   ```powershell
   kubectl logs -f deployment/api -n yt-summarizer
   kubectl logs -f deployment/workers -n yt-summarizer
   ```
3. **Check health endpoint**:
   ```powershell
   kubectl port-forward svc/api -n yt-summarizer 8000:80
   curl http://localhost:8000/health
   ```

### OIDC Authentication Fails

1. Verify federated credentials match the workflow context
2. Check that `permissions: id-token: write` is set in workflow
3. Ensure service principal has required role assignments

---

## Maintenance

### Updating GitHub Actions

Actions are pinned to specific versions. Update periodically:
1. Check for updates: `dependabot` will create PRs
2. Review changelog for breaking changes
3. Test in feature branch before merging

### Updating Argo CD

```powershell
# Check current version
kubectl -n argocd get deployment argocd-server -o jsonpath='{.spec.template.spec.containers[0].image}'

# Update to latest stable
kubectl apply -n argocd `
  -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml
```

### Rotating Secrets

Azure Key Vault secrets are synced via External Secrets:
1. Update secret in Key Vault
2. External Secrets Operator syncs automatically (default: 1 hour)
3. Force immediate sync:
   ```powershell
   kubectl annotate externalsecret <name> -n yt-summarizer force-sync=$(date +%s)
   ```

### Scaling the Cluster

If you need more capacity:
```powershell
# Add a second node (increases cost to ~$60/month)
az aks scale `
  --resource-group rg-ytsummarizer-staging `
  --name aks-ytsummarizer-staging `
  --node-count 2
```
