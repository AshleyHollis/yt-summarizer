# Quickstart: Azure CI/CD Pipelines (AKS + GitOps)

**Feature**: 002-azure-cicd  
**Date**: 2026-01-08 (Updated 2026-01-09)  
**Purpose**: Step-by-step guide to set up and use the CI/CD pipelines

## Quick Start: Daily Developer Workflow

### Creating a PR with Preview Environment

```bash
# 1. Create feature branch
git checkout -b feature/my-feature

# 2. Make changes and commit
git add .
git commit -m "feat: add new feature"

# 3. Push and create PR
git push origin feature/my-feature
gh pr create --title "feat: add new feature" --body "Description of changes"

# 4. Wait for CI to pass, then Preview workflow will:
#    - Build Docker images with PR SHA tag
#    - Create preview namespace (preview-pr-<number>)
#    - Argo CD syncs preview environment
#    - Comment posted with preview URL
```

### Merging to Production

```bash
# 1. After PR is approved and CI passes, merge
gh pr merge --squash

# 2. Automatically:
#    - deploy-prod.yml updates k8s/overlays/prod with image digests
#    - Argo CD syncs production namespace
#    - Health check runs against production API
#    - Preview environment is cleaned up
```

### Checking Deployment Status

```bash
# View Argo CD applications
argocd app list

# Check production status
argocd app get yt-summarizer-prod

# Check preview status
argocd app get preview-pr-<number>
```

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│  GitOps Flow: PR Preview + Auto-Production                              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─── Pull Request ───┐      ┌─── Merge to main ───┐                    │
│  │                    │      │                     │                    │
│  │  1. CI Tests       │      │  1. Update prod     │                    │
│  │  2. Build Images   │      │     overlay with    │                    │
│  │  3. Push to ACR    │      │     image digests   │                    │
│  │  4. Create preview │      │  2. Argo CD syncs   │                    │
│  │     overlay        │      │     production      │                    │
│  │  5. Argo CD syncs  │      │                     │                    │
│  │     preview env    │      └─────────────────────┘                    │
│  │  6. Post URL to PR │                                                 │
│  └────────────────────┘                                                 │
│                                                                         │
│   ┌────────────────────────────────────────────────────────────────┐    │
│   │  AKS Single-Node Cluster (~$30/month)                          │    │
│   │  ┌──────────────────────────┐  ┌─────────────────────────────┐ │    │
│   │  │  Production Namespace    │  │  Preview Namespaces (1-3)   │ │    │
│   │  │  ┌─────┐ ┌───────┐       │  │  preview-pr-123/            │ │    │
│   │  │  │ API │ │Workers│       │  │  preview-pr-456/            │ │    │
│   │  │  └─────┘ └───────┘       │  │  (ephemeral, auto-cleaned)  │ │    │
│   │  └──────────────────────────┘  └─────────────────────────────┘ │    │
│   │  ┌───────────────┐                                              │    │
│   │  │   Argo CD     │ ← Syncs from k8s/overlays/prod/ + previews/  │    │
│   │  └───────────────┘                                              │    │
│   └────────────────────────────────────────────────────────────────┘    │
│                                                                         │
│   ┌────────────────────────────────────────────────────────┐            │
│   │  Azure Static Web Apps (free tier)                     │            │
│   │  - Next.js frontend with CDN                           │            │
│   └────────────────────────────────────────────────────────┘            │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

**Key Design Points**:
- **No permanent staging environment** — PR previews are the validation surface
- **Auto-production deploy** — Merges to `main` automatically deploy to production
- **Max 3 concurrent previews** — Resource quotas protect production namespace

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

2. **Create GitHub Environment** (Settings → Environments):

   - **production**: No approval gate (auto-deploy on merge to main)
   - Preview environments are ephemeral namespaces in AKS (no GitHub Environment needed)

3. **Enable GitHub Actions** (Settings → Actions → General):
   - Allow all actions and reusable workflows
   - Workflow permissions: Read and write

---

## Initial Infrastructure Setup

After Terraform modules are created, deploy the infrastructure:

```powershell
# Navigate to infrastructure directory
cd infra/terraform/environments/prod

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
  --resource-group rg-ytsummarizer-prod `
  --name aks-ytsummarizer-prod

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

### Register Applications with Argo CD

```powershell
# Apply the Production Application manifest
kubectl apply -f k8s/argocd/prod-app.yaml

# Apply the Preview ApplicationSet (discovers PR overlays automatically)
kubectl apply -f k8s/argocd/preview-appset.yaml

# Apply the repo secret (for private repo access)
kubectl apply -f k8s/argocd/repo-secret.yaml
```

---

## Usage

### Pull Request: CI Testing

When you create or update a PR:
1. **ci.yml** triggers automatically
2. All tests run (shared, workers, API, frontend, E2E)
3. Results appear as PR check status
4. Merge is blocked if any test fails

**View results**: Click "Details" on the PR check or go to Actions tab

### Pull Request: Preview Environment

After CI passes, a preview environment is deployed:
1. **preview.yml** triggers:
   - Builds Docker images for API and Workers
   - Pushes to ACR with commit SHA tag and digest
   - Generates `k8s/overlays/previews/pr-<number>/` overlay
   - Commits overlay to repository
2. **Argo CD ApplicationSet** detects the new overlay:
   - Creates `preview-pr-<number>` Application
   - Deploys to `preview-pr-<number>` namespace
   - Performs health checks
3. **preview.yml** posts status to PR:
   - Deploy status (deploying/ready/failed)
   - Preview URL
   - Link to Argo CD sync status

**View preview**:
- URL posted as PR comment (e.g., `https://api-pr-123.yt-summarizer.apps.ashleyhollis.com`)
- Argo CD: `kubectl port-forward svc/argocd-server -n argocd 8080:443`

### Preview TLS Architecture

Preview environments use **HTTPS by default** via a shared wildcard certificate — no per-PR certificate provisioning required.

**How it works**:
1. **Wildcard DNS**: Cloudflare wildcard record `*.yt-summarizer.apps.ashleyhollis.com` points to the cluster's Load Balancer IP. Preview URLs follow the pattern `https://api-pr-<num>.yt-summarizer.apps.ashleyhollis.com`.
2. **Shared TLS certificate**: cert-manager manages a single wildcard certificate (`yt-summarizer-wildcard-tls`) using DNS-01 challenge via the `letsencrypt-cloudflare` ClusterIssuer. This secret is shared across all preview namespaces.
3. **Gateway API routing**: The cluster gateway terminates TLS using the wildcard secret and routes traffic to the correct preview namespace based on hostname. No Ingress TLS annotations needed per preview.
4. **URL injection**: The `compute-preview-urls` action (`.github/actions/compute-preview-urls/`) calculates the HTTPS preview URL and injects it as `REAL_BACKEND_URL` into the SWA frontend build.
5. **TLS verification**: After deployment, the `verify-certificate` action (`.github/actions/verify-certificate/`) confirms the TLS secret is available before marking the preview as ready.

**Key files**:
- `k8s/argocd/cert-manager/clusterissuer-cloudflare.yaml` — DNS-01 ClusterIssuer for wildcard cert
- `.github/actions/compute-preview-urls/` — Computes preview hostname + HTTPS URL
- `.github/actions/verify-certificate/` — Validates TLS secret is provisioned

### Pull Request: Cleanup

When a PR is closed or merged:
1. **preview-cleanup.yml** triggers
2. Deletes `k8s/overlays/previews/pr-<number>/` directory
3. Commits deletion to repository
4. Argo CD detects removal and prunes:
   - Deletes `preview-pr-<number>` Application
   - Deletes namespace and all resources

**Timeline**: Preview is cleaned up within 5 minutes of PR close

### Merge to Main: Auto-Production Deploy

When you merge a PR to `main`:
1. **deploy-prod.yml** triggers automatically:
   - Retrieves image digests from the merged commit
   - Updates `k8s/overlays/prod/kustomization.yaml` with pinned digests
   - Commits change to repository
2. **Argo CD** detects the commit and syncs:
   - Pulls new manifests from `k8s/overlays/prod/`
   - Applies changes to production namespace
   - Performs health checks on pods
3. **SWA Deploy** runs in parallel:
   - Builds Next.js frontend
   - Deploys to Azure Static Web Apps production

**View production**:
- App: `https://ytsummarizer.azurestaticapps.net`
- Argo CD: `kubectl port-forward svc/argocd-server -n argocd 8080:443`

**Key benefit**: Same image digests validated in preview are promoted (no rebuild)

### Production Rollback

GitOps makes rollback simple - just revert to a previous commit:

```powershell
# Option 1: Git revert (recommended - maintains history)
git revert <commit-sha>
git push origin main
# Argo CD will sync the reverted state automatically

# Option 2: Argo CD rollback (immediate)
# In Argo CD UI: Applications → yt-summarizer-prod → History → Rollback

# Option 3: kubectl rollback (emergency)
kubectl rollout undo deployment/api -n yt-summarizer
kubectl rollout undo deployment/workers -n yt-summarizer
```

### Preview Rollback

To redeploy a preview environment:

```powershell
# Push a new commit to the PR branch
git commit --allow-empty -m "Redeploy preview"
git push origin <branch-name>
# CI will rebuild and redeploy the preview

# Or close and reopen the PR to force a fresh preview
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
│   ├── api-ingress.yaml
│   ├── *-worker-deployment.yaml
│   ├── configmap.yaml
│   ├── externalsecret-*.yaml
│   └── migration-job.yaml
├── overlays/
│   ├── prod/                  # Production overlay (pinned digests)
│   │   ├── kustomization.yaml # Image digests updated by deploy-prod.yml
│   │   └── patches/
│   └── previews/              # Ephemeral PR overlays (auto-generated)
│       └── pr-<number>/       # Created by preview.yml, deleted by preview-cleanup.yml
│           ├── kustomization.yaml
│           ├── namespace.yaml
│           └── patches/
└── argocd/
    ├── prod-app.yaml          # Production Argo Application
    ├── preview-appset.yaml    # ApplicationSet for preview discovery
    └── repo-secret.yaml       # Git credentials (sealed)

.github/workflows/
├── ci.yml                     # PR: Run all tests
├── preview.yml                # PR: Build images, create preview overlay
├── deploy-prod.yml            # Merge: Pin prod overlay to image digests
└── preview-cleanup.yml        # PR closed: Delete preview overlay
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
   kubectl describe application yt-summarizer-prod -n argocd
   # For previews:
   kubectl get applications -n argocd -l app.kubernetes.io/instance=yt-summarizer-previews
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
  --resource-group rg-ytsummarizer-prod `
  --name aks-ytsummarizer-prod `
  --node-count 2
```

### Preview Environment Limits

Max 3 concurrent preview environments are allowed to protect production resources:

```powershell
# Check current preview count
kubectl get namespaces | grep preview-pr

# If limit reached, close old PRs or wait for cleanup
# Previews are auto-cleaned within 5 minutes of PR close
```
