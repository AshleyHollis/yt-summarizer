# Argo CD Setup Runbook

This runbook covers the installation, configuration, and operation of Argo CD in the yt-summarizer AKS cluster.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Initial Configuration](#initial-configuration)
4. [GitHub Repository Access](#github-repository-access)
5. [Application Management](#application-management)
6. [Troubleshooting](#troubleshooting)
7. [Maintenance](#maintenance)

## Prerequisites

- AKS cluster is running and accessible
- `kubectl` configured with cluster credentials
- `argocd` CLI installed locally (optional but recommended)
- GitHub repository access (SSH key or OIDC token)

### Install Argo CD CLI

```powershell
# Windows (using Scoop)
scoop install argocd

# Or download directly
$version = (Invoke-RestMethod -Uri "https://api.github.com/repos/argoproj/argo-cd/releases/latest").tag_name
Invoke-WebRequest -Uri "https://github.com/argoproj/argo-cd/releases/download/$version/argocd-windows-amd64.exe" -OutFile argocd.exe
Move-Item argocd.exe $env:USERPROFILE\bin\argocd.exe
```

## Installation

Argo CD is installed via bootstrap script after Terraform deploys the AKS cluster:

```powershell
# 1. Deploy infrastructure (creates AKS cluster)
cd infra/terraform/environments/prod
terraform init
terraform apply

# 2. Get AKS credentials
az aks get-credentials --resource-group rg-ytsumm-prd --name aks-ytsumm-prd

# 3. Bootstrap Argo CD (installs Argo CD + infrastructure apps)
.\scripts\bootstrap-argocd.ps1
```

The bootstrap script:
1. Installs Argo CD from official Helm chart
2. Configures GitHub repository access
3. Applies infrastructure apps (ingress-nginx, external-secrets)
4. Sets up production and preview ApplicationSets

### Manual Installation (if needed)

```bash
# Create namespace
kubectl create namespace argocd

# Install Argo CD
kubectl apply -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

# Wait for pods
kubectl wait --for=condition=available --timeout=300s deployment/argocd-server -n argocd
```

## Initial Configuration

### Get Initial Admin Password

```bash
# The initial password is the server pod name
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" | base64 -d
```

### Access the Dashboard

```bash
# Port forward (development only)
kubectl port-forward svc/argocd-server -n argocd 8080:443

# Access at https://localhost:8080
```

### Change Admin Password

```bash
argocd login localhost:8080 --username admin --password <initial-password> --insecure
argocd account update-password
```

### Configure via Ingress

For production, Argo CD is exposed via nginx ingress:

```yaml
# Ingress is configured by Terraform at: argocd.<domain>
# Example: https://argocd.staging.yt-summarizer.com
```

## GitHub Repository Access

### Option 1: SSH Deploy Key (Recommended)

```bash
# Generate SSH key
ssh-keygen -t ed25519 -C "argocd-deploy-key" -f argocd-deploy-key -N ""

# Add public key to GitHub repository as Deploy Key (read-only)
# Settings > Deploy Keys > Add deploy key

# Create secret in Argo CD
kubectl create secret generic github-repo \
  --namespace=argocd \
  --from-literal=type=git \
  --from-literal=url=git@github.com:AshleyHollis/yt-summarizer.git \
  --from-file=sshPrivateKey=argocd-deploy-key

kubectl label secret github-repo -n argocd argocd.argoproj.io/secret-type=repository
```

### Option 3: GitHub Personal Access Token (for ApplicationSet PR Generator)

The ApplicationSet PR generator requires a GitHub PAT to query the GitHub API for open pull requests.

```powershell
# Create a GitHub PAT with 'repo' scope at:
# https://github.com/settings/tokens/new

# Create the secret in argocd namespace
kubectl create secret generic github-token \
  --namespace=argocd \
  --from-literal=token=<YOUR_GITHUB_PAT>

# Or using gh CLI (if authenticated)
$token = (gh auth token)
kubectl create secret generic github-token -n argocd --from-literal=token=$token
```

**Required Scopes:**
- `repo` - Full control of private repositories (required to list PRs)
- Or `public_repo` - Access public repositories (if repository is public)

**Note:** The ApplicationSet uses this token only to query the GitHub API for open PRs. It does NOT use it to clone the repository (repository access is configured separately via SSH/OIDC).



```bash
# Create GitHub App with repository read access
# Configure in Argo CD settings

argocd repo add https://github.com/AshleyHollis/yt-summarizer.git \
  --github-app-id <app-id> \
  --github-app-installation-id <installation-id> \
  --github-app-private-key-path <private-key.pem>
```

## Application Management

### ApplicationSet for Preview Environments

Preview environments are managed by an ApplicationSet that automatically creates/deletes applications based on preview overlay directories:

```yaml
# k8s/argocd/preview-appset.yaml
apiVersion: argoproj.io/v1alpha1
kind: ApplicationSet
metadata:
  name: preview-environments
spec:
  generators:
  - pullRequest:
      github:
        owner: AshleyHollis
        repo: yt-summarizer
      requeueAfterSeconds: 60
  template:
    metadata:
      name: 'preview-pr-{{number}}'
    spec:
      project: default
      source:
        repoURL: https://github.com/AshleyHollis/yt-summarizer.git
        targetRevision: '{{head_sha}}'
        path: k8s/overlays/preview
      destination:
        server: https://kubernetes.default.svc
        namespace: 'preview-pr-{{number}}'
      syncPolicy:
        automated:
          prune: true
          selfHeal: true
        syncOptions:
          - CreateNamespace=true
```

### Deploy Production Application

```bash
# Apply production app (single prod environment)
kubectl apply -f k8s/argocd/prod-app.yaml

# Or via CLI
argocd app create yt-summarizer-prod \
  --repo git@github.com:AshleyHollis/yt-summarizer.git \
  --path k8s/overlays/prod \
  --dest-server https://kubernetes.default.svc \
  --dest-namespace yt-summarizer \
  --sync-policy automated \
  --auto-prune
```

### Apply Preview ApplicationSet

```bash
kubectl apply -f k8s/argocd/preview-appset.yaml
```

### Sync Application

```bash
# Manual sync
argocd app sync yt-summarizer-staging

# Force sync (overwrite diverged state)
argocd app sync yt-summarizer-staging --force
```

### View Application Status

```bash
# List all applications
argocd app list

# Get details
argocd app get yt-summarizer-staging

# View resources
argocd app resources yt-summarizer-staging
```

### Rollback

```bash
# View history
argocd app history yt-summarizer-staging

# Rollback to specific revision
argocd app rollback yt-summarizer-staging <revision>

# Or rollback to previous
argocd app rollback yt-summarizer-staging
```

## Troubleshooting

### Application Stuck in Syncing

```bash
# Check sync status
argocd app get yt-summarizer-staging

# View sync operation
argocd app sync-status yt-summarizer-staging

# Check resource health
argocd app resources yt-summarizer-staging --output wide
```

### Repository Connection Failed

```bash
# Test repository access
argocd repo list
argocd repo get git@github.com:AshleyHollis/yt-summarizer.git

# Check repository secret
kubectl get secret -n argocd -l argocd.argoproj.io/secret-type=repository

# View Argo CD logs
kubectl logs -n argocd -l app.kubernetes.io/name=argocd-repo-server
```

### Application OutOfSync

```bash
# View diff
argocd app diff yt-summarizer-staging

# Refresh from Git
argocd app refresh yt-summarizer-staging

# Hard refresh (clear cache)
argocd app get yt-summarizer-staging --hard-refresh
```

### Pod Not Starting

```bash
# Check pod status
kubectl get pods -n yt-summarizer

# Describe pod
kubectl describe pod <pod-name> -n yt-summarizer

# Check events
kubectl get events -n yt-summarizer --sort-by='.lastTimestamp'
```

## Maintenance

### Upgrade Argo CD

Update the Helm chart version in Terraform and apply:

```hcl
# infra/terraform/modules/argocd/main.tf
variable "chart_version" {
  default = "5.51.6"  # Update this version
}
```

```powershell
.\scripts\deploy-infra.ps1 -Environment staging
```

### Backup Configuration

```bash
# Export all applications
argocd app list -o yaml > argocd-apps-backup.yaml

# Export secrets
kubectl get secrets -n argocd -o yaml > argocd-secrets-backup.yaml
```

### Disaster Recovery

```bash
# Reinstall Argo CD
terraform apply -target=module.argocd

# Restore applications
kubectl apply -f argocd-apps-backup.yaml

# Restore repository credentials
kubectl apply -f argocd-secrets-backup.yaml
```

### Monitoring

```bash
# Check Argo CD health
kubectl get pods -n argocd

# View metrics (if enabled)
kubectl port-forward svc/argocd-metrics -n argocd 8082:8082
# Access at http://localhost:8082/metrics
```

## Best Practices

1. **Use ApplicationSets** for managing multiple environments with a single definition
2. **Enable auto-pruning** to remove orphaned resources
3. **Set sync windows** for production to control deployment times
4. **Use projects** to isolate team access and permissions
5. **Configure notifications** for sync failures and degraded health
6. **Regular backups** of Argo CD configuration and secrets
