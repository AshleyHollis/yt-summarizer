<#
.SYNOPSIS
    Bootstrap Argo CD on a fresh AKS cluster.

.DESCRIPTION
    This script installs Argo CD on the AKS cluster using the official Helm chart.
    Run this ONCE after terraform apply creates the AKS cluster.

.NOTES
    Prerequisites:
    - kubectl configured with AKS credentials
    - helm v3 installed
    - az cli logged in

.EXAMPLE
    # First, get AKS credentials
    az aks get-credentials --resource-group rg-ytsumm-prd --name aks-ytsumm-prd
    
    # Then run this script
    ./scripts/bootstrap-argocd.ps1
#>

param(
    [string]$Namespace = "argocd",
    [string]$ChartVersion = "7.3.11",  # Argo CD 2.12.x
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

Write-Host "╔═══════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║ Argo CD Bootstrap Script                                                   ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# Check prerequisites
Write-Host "Checking prerequisites..." -ForegroundColor Yellow

# Check kubectl
try {
    $kubeContext = kubectl config current-context 2>&1
    Write-Host "  ✓ kubectl context: $kubeContext" -ForegroundColor Green
} catch {
    Write-Error "kubectl not configured. Run: az aks get-credentials --resource-group <rg> --name <aks>"
    exit 1
}

# Check helm
try {
    $helmVersion = helm version --short 2>&1
    Write-Host "  ✓ helm version: $helmVersion" -ForegroundColor Green
} catch {
    Write-Error "helm not installed. Install from: https://helm.sh/docs/intro/install/"
    exit 1
}

Write-Host ""

# Add Argo CD Helm repository
Write-Host "Adding Argo CD Helm repository..." -ForegroundColor Yellow
helm repo add argo https://argoproj.github.io/argo-helm 2>&1 | Out-Null
helm repo update 2>&1 | Out-Null
Write-Host "  ✓ Argo Helm repo added and updated" -ForegroundColor Green

# Create namespace if it doesn't exist
Write-Host ""
Write-Host "Creating namespace '$Namespace'..." -ForegroundColor Yellow
kubectl create namespace $Namespace --dry-run=client -o yaml | kubectl apply -f - 2>&1 | Out-Null
Write-Host "  ✓ Namespace ready" -ForegroundColor Green

# Install Argo CD
Write-Host ""
Write-Host "Installing Argo CD (chart version $ChartVersion)..." -ForegroundColor Yellow

$helmArgs = @(
    "upgrade", "--install", "argocd",
    "argo/argo-cd",
    "--namespace", $Namespace,
    "--version", $ChartVersion,
    "--set", "configs.params.server\.insecure=true",  # We'll use ingress for TLS
    "--set", "server.service.type=ClusterIP",
    "--set", "controller.resources.requests.cpu=100m",
    "--set", "controller.resources.requests.memory=256Mi",
    "--set", "controller.resources.limits.cpu=500m",
    "--set", "controller.resources.limits.memory=512Mi",
    "--set", "server.resources.requests.cpu=50m",
    "--set", "server.resources.requests.memory=128Mi",
    "--set", "server.resources.limits.cpu=200m",
    "--set", "server.resources.limits.memory=256Mi",
    "--set", "repoServer.resources.requests.cpu=50m",
    "--set", "repoServer.resources.requests.memory=128Mi",
    "--set", "repoServer.resources.limits.cpu=200m",
    "--set", "repoServer.resources.limits.memory=256Mi",
    "--set", "redis.resources.requests.cpu=25m",
    "--set", "redis.resources.requests.memory=64Mi",
    "--set", "redis.resources.limits.cpu=100m",
    "--set", "redis.resources.limits.memory=128Mi",
    "--wait",
    "--timeout", "5m"
)

if ($DryRun) {
    $helmArgs += "--dry-run"
    Write-Host "  (DRY RUN - no changes will be made)" -ForegroundColor Yellow
}

& helm @helmArgs

if ($LASTEXITCODE -ne 0) {
    Write-Error "Argo CD installation failed"
    exit 1
}

Write-Host "  ✓ Argo CD installed successfully" -ForegroundColor Green

# Get the initial admin password
Write-Host ""
Write-Host "Retrieving admin password..." -ForegroundColor Yellow

$maxRetries = 10
$retryCount = 0
$password = $null

while ($retryCount -lt $maxRetries -and -not $password) {
    try {
        $secret = kubectl -n $Namespace get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" 2>&1
        if ($secret -and $secret -notmatch "Error") {
            $password = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($secret))
        }
    } catch {
        # Secret might not be ready yet
    }
    if (-not $password) {
        $retryCount++
        Write-Host "  Waiting for admin secret... ($retryCount/$maxRetries)" -ForegroundColor Gray
        Start-Sleep -Seconds 3
    }
}

if (-not $password) {
    Write-Warning "Could not retrieve admin password. Check manually with:"
    Write-Host "  kubectl -n $Namespace get secret argocd-initial-admin-secret -o jsonpath='{.data.password}' | base64 -d"
} else {
    Write-Host "  ✓ Admin password retrieved" -ForegroundColor Green
}

# Output summary
Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║ Argo CD Bootstrap Complete!                                                ║" -ForegroundColor Green
Write-Host "╠═══════════════════════════════════════════════════════════════════════════╣" -ForegroundColor Green
Write-Host "║                                                                            ║" -ForegroundColor Green
Write-Host "║ Username: admin                                                            ║" -ForegroundColor Green
if ($password) {
    Write-Host "║ Password: $password                                              ║" -ForegroundColor Green
}
Write-Host "║                                                                            ║" -ForegroundColor Green
Write-Host "║ Access via port-forward:                                                   ║" -ForegroundColor Green
Write-Host "║   kubectl port-forward svc/argocd-server -n argocd 8080:443                ║" -ForegroundColor Green
Write-Host "║   Then open: https://localhost:8080                                        ║" -ForegroundColor Green
Write-Host "║                                                                            ║" -ForegroundColor Green
Write-Host "║ NEXT STEPS:                                                                ║" -ForegroundColor Green
Write-Host "║ 1. Apply infrastructure apps (ingress-nginx, external-secrets):            ║" -ForegroundColor Green
Write-Host "║    kubectl apply -f k8s/argocd/infra-apps.yaml                             ║" -ForegroundColor Green
Write-Host "║                                                                            ║" -ForegroundColor Green
Write-Host "║ 2. Apply production and preview apps:                                      ║" -ForegroundColor Green
Write-Host "║    kubectl apply -f k8s/argocd/prod-app.yaml                               ║" -ForegroundColor Green
Write-Host "║    kubectl apply -f k8s/argocd/preview-appset.yaml                         ║" -ForegroundColor Green
Write-Host "╚═══════════════════════════════════════════════════════════════════════════╝" -ForegroundColor Green
