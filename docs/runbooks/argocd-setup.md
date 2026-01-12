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

### Option 3: GitHub App (Recommended for ApplicationSet PR Generator)

**⚠️ RECOMMENDED**: GitHub Apps provide better security, don't expire, and have higher rate limits than PATs.

#### Create GitHub App

1. **Create the GitHub App**: https://github.com/settings/apps/new
   - **GitHub App name**: `yt-summarizer-argocd-previews`
   - **Homepage URL**: `https://argocd.yt-summarizer.com` (your ArgoCD URL)
   - **Webhook**: Uncheck "Active"
   - **Repository permissions**:
     - Pull requests: `Read-only`
     - Contents: `Read-only` (for reading repository files)
     - Metadata: `Read-only` (automatically selected)
   - **Where can this GitHub App be installed?**: `Only on this account`

2. **Install the App**:
   - After creation, click "Install App"
   - Select `AshleyHollis/yt-summarizer` repository
   - Note the **Installation ID** from the URL: `https://github.com/settings/installations/{INSTALLATION_ID}`

3. **Generate Private Key**:
   - In the app settings, scroll to "Private keys"
   - Click "Generate a private key"
   - Download the `.pem` file

4. **Create Kubernetes Secret**:
   ```powershell
   # Note your App ID from the app settings page
   $APP_ID = "123456"  # Replace with your App ID
   $INSTALLATION_ID = "789012"  # From installation URL

   # Create secret with private key
   kubectl create secret generic github-app \
     --namespace=argocd \
     --from-literal=appID=$APP_ID \
     --from-literal=installationID=$INSTALLATION_ID \
     --from-file=privateKey=path/to/your-app.private-key.pem
   ```

5. **Update ApplicationSet**:
   ```yaml
   # k8s/argocd/preview-appset.yaml
   generators:
     - pullRequest:
         github:
           owner: AshleyHollis
           repo: yt-summarizer
           appSecretName: github-app  # Use GitHub App instead of token
   ```

**Benefits over PAT:**
- ✅ Private key doesn't expire
- ✅ 5000 API requests/hour (vs 60 for PAT)
- ✅ Scoped to specific repository
- ✅ Survives team member changes
- ✅ Better audit logging

### Option 4: External Secrets with GitHub PAT (Auto-Rotation)

If you must use a GitHub PAT, store it in Azure Key Vault for automatic rotation:

```powershell
# 1. Store token in Azure Key Vault
az keyvault secret set \
  --vault-name kv-ytsumm-prd \
  --name github-argocd-token \
  --value "<YOUR_GITHUB_PAT>"

# 2. Create ExternalSecret (syncs from Key Vault to k8s secret)
kubectl apply -f - <<EOF
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: github-token
  namespace: argocd
spec:
  refreshInterval: 1h  # Sync from Key Vault every hour
  secretStoreRef:
    name: cluster-secretstore  # Your existing ClusterSecretStore
    kind: ClusterSecretStore
  target:
    name: github-token
    creationPolicy: Owner
  data:
    - secretKey: token
      remoteRef:
        key: github-argocd-token
EOF
```

**Token Rotation Process:**
1. Generate new GitHub PAT
2. Update Azure Key Vault secret
3. External Secrets Operator automatically updates k8s secret within 1 hour
4. ArgoCD picks up new token on next sync

**⚠️ PAT Expiration Reminder:**
- Set calendar reminder 2 weeks before PAT expires
- Rotate token by updating Key Vault secret
- Consider GitHub App instead for zero-maintenance



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
