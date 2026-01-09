# AKS Setup Guide

This guide covers the setup of Azure Kubernetes Service (AKS) and Argo CD for the YT Summarizer GitOps deployment.

## Prerequisites

- Azure CLI installed and authenticated
- kubectl installed
- Terraform installed (>= 1.5.0)
- GitHub repository access

## Initial Azure Setup

### 1. Create Resource Groups

```bash
# Terraform state storage
az group create --name rg-ytsummarizer-tfstate --location eastus

# Create storage account for Terraform state
az storage account create \
  --name stytsummarizertfstate \
  --resource-group rg-ytsummarizer-tfstate \
  --sku Standard_LRS \
  --allow-blob-public-access false

az storage container create \
  --name tfstate \
  --account-name stytsummarizertfstate
```

### 2. Create Azure AD App Registration (OIDC)

```bash
# Create app registration for GitHub Actions
az ad app create --display-name "github-actions-ytsummarizer"

# Get the app ID
APP_ID=$(az ad app list --display-name "github-actions-ytsummarizer" --query "[0].appId" -o tsv)

# Create service principal
az ad sp create --id $APP_ID

# Get object ID of the service principal
SP_OBJECT_ID=$(az ad sp list --filter "appId eq '$APP_ID'" --query "[0].id" -o tsv)

# Assign Contributor role
az role assignment create \
  --assignee-object-id $SP_OBJECT_ID \
  --assignee-principal-type ServicePrincipal \
  --role Contributor \
  --scope "/subscriptions/<subscription-id>"
```

### 3. Configure GitHub OIDC Federated Credentials

```bash
# For main branch (staging deployments)
az ad app federated-credential create \
  --id $APP_ID \
  --parameters '{
    "name": "github-actions-main",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:AshleyHollis/yt-summarizer:ref:refs/heads/main",
    "audiences": ["api://AzureADTokenExchange"]
  }'

# For pull requests (CI)
az ad app federated-credential create \
  --id $APP_ID \
  --parameters '{
    "name": "github-actions-pr",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:AshleyHollis/yt-summarizer:pull_request",
    "audiences": ["api://AzureADTokenExchange"]
  }'

# For production environment
az ad app federated-credential create \
  --id $APP_ID \
  --parameters '{
    "name": "github-actions-production",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:AshleyHollis/yt-summarizer:environment:production",
    "audiences": ["api://AzureADTokenExchange"]
  }'
```

### 4. Configure GitHub Secrets

Add the following secrets to your GitHub repository:

| Secret Name | Value |
|------------|-------|
| `AZURE_CLIENT_ID` | App registration client ID |
| `AZURE_TENANT_ID` | Azure AD tenant ID |
| `AZURE_SUBSCRIPTION_ID` | Azure subscription ID |
| `AZURE_STATIC_WEB_APPS_API_TOKEN_STAGING` | SWA deployment token (staging) |
| `AZURE_STATIC_WEB_APPS_API_TOKEN_PRODUCTION` | SWA deployment token (production) |
| `STAGING_API_URL` | https://api-staging.yt-summarizer.example.com |
| `PRODUCTION_API_URL` | https://api.yt-summarizer.example.com |

## Terraform Infrastructure Deployment

### 1. Initialize Terraform

```bash
cd infra/terraform/environments/staging

terraform init \
  -backend-config="resource_group_name=rg-ytsummarizer-tfstate" \
  -backend-config="storage_account_name=stytsummarizertfstate" \
  -backend-config="container_name=tfstate" \
  -backend-config="key=staging.tfstate"
```

### 2. Deploy Infrastructure

```bash
# Create terraform.tfvars
cat > terraform.tfvars <<EOF
environment = "staging"
location = "eastus"
sql_admin_password = "YourSecurePassword123!"
EOF

# Plan
terraform plan -var-file=terraform.tfvars -out=tfplan

# Apply
terraform apply tfplan
```

## Argo CD Installation

### 1. Install Argo CD on AKS

```bash
# Get AKS credentials
az aks get-credentials \
  --resource-group rg-ytsumm-stg \
  --name aks-ytsumm-stg

# Create argocd namespace
kubectl create namespace argocd

# Install Argo CD
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

# Wait for Argo CD to be ready
kubectl wait --for=condition=available --timeout=300s deployment/argocd-server -n argocd
```

### 2. Access Argo CD UI

```bash
# Get initial admin password
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d

# Port forward to access UI
kubectl port-forward svc/argocd-server -n argocd 8080:443
```

Access the UI at https://localhost:8080 with username `admin` and the password from above.

### 3. Configure GitHub Repository Access

For public repositories, no additional configuration is needed.

For private repositories, create a deploy key or GitHub App:

```bash
# Apply repository secret
kubectl apply -f k8s/argocd/repo-secret.yaml
```

### 4. Deploy Argo CD Applications

```bash
# Deploy staging application
kubectl apply -f k8s/argocd/staging-app.yaml

# Deploy production application (manual sync)
kubectl apply -f k8s/argocd/production-app.yaml
```

## Verification

### Check Application Status

```bash
# Check Argo CD applications
kubectl get applications -n argocd

# Check deployed pods
kubectl get pods -n yt-summarizer

# Check services
kubectl get svc -n yt-summarizer

# Check ingress
kubectl get ingress -n yt-summarizer
```

### Test the Deployment

```bash
# Get the ingress IP
INGRESS_IP=$(kubectl get ingress api-ingress -n yt-summarizer -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

# Test health endpoint
curl http://$INGRESS_IP/health/live
```

## Rollback Procedure

### GitOps Rollback (Preferred)

```bash
# Find the commit to revert to
git log --oneline k8s/overlays/staging/kustomization.yaml

# Revert the manifest change
git revert <commit-sha>
git push origin main

# Argo CD will automatically sync the reverted state
```

### Emergency Rollback (Immediate)

```bash
kubectl rollout undo deployment/api -n yt-summarizer
kubectl rollout undo deployment/transcribe-worker -n yt-summarizer
kubectl rollout undo deployment/summarize-worker -n yt-summarizer
kubectl rollout undo deployment/embed-worker -n yt-summarizer
kubectl rollout undo deployment/relationships-worker -n yt-summarizer
```

## Cost Management

The single-node AKS configuration uses:

- **AKS Control Plane**: Free tier
- **Node (Standard_B2s)**: ~$30/month
- **ACR (Basic)**: ~$5/month
- **Total**: ~$35/month

To reduce costs further during development:

```bash
# Stop the AKS cluster (saves compute costs)
az aks stop --name aks-ytsumm-stg --resource-group rg-ytsumm-stg

# Start the cluster
az aks start --name aks-ytsumm-stg --resource-group rg-ytsumm-stg
```
