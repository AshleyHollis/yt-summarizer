#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Setup GitHub App for ArgoCD ApplicationSet PR generator

.DESCRIPTION
    Creates a GitHub App with minimal permissions for ArgoCD to query PRs,
    installs it on the repository, and creates the Kubernetes secret.

.PARAMETER AppName
    Name for the GitHub App (default: yt-summarizer-argocd-previews)

.PARAMETER Repository
    Repository in format owner/repo (default: AshleyHollis/yt-summarizer)

.EXAMPLE
    .\setup-argocd-github-app.ps1
    
.NOTES
    Requires: gh CLI, kubectl with AKS context configured
#>

param(
    [string]$AppName = "yt-summarizer-argocd-previews",
    [string]$Repository = "AshleyHollis/yt-summarizer"
)

$ErrorActionPreference = "Stop"

Write-Host "🚀 Setting up GitHub App for ArgoCD ApplicationSet" -ForegroundColor Cyan
Write-Host ""

# Check prerequisites
Write-Host "Checking prerequisites..." -ForegroundColor Yellow
if (!(Get-Command gh -ErrorAction SilentlyContinue)) {
    Write-Error "gh CLI not found. Install from: https://cli.github.com/"
}
if (!(Get-Command kubectl -ErrorAction SilentlyContinue)) {
    Write-Error "kubectl not found. Install from: https://kubernetes.io/docs/tasks/tools/"
}

# Verify kubectl context
$context = kubectl config current-context 2>$null
if (!$context) {
    Write-Error "kubectl not configured. Run: az aks get-credentials --resource-group rg-ytsumm-prd --name aks-ytsumm-prd"
}
Write-Host "✓ kubectl context: $context" -ForegroundColor Green

# Verify gh auth
$authStatus = gh auth status 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "gh CLI not authenticated. Run: gh auth login"
}
Write-Host "✓ gh CLI authenticated" -ForegroundColor Green
Write-Host ""

# Step 1: Create GitHub App via manifest
Write-Host "📝 Step 1: Create GitHub App" -ForegroundColor Cyan
Write-Host "Opening browser to create GitHub App..."
Write-Host ""
Write-Host "IMPORTANT: After app creation:" -ForegroundColor Yellow
Write-Host "  1. Click 'Generate a private key' and download the .pem file" -ForegroundColor Yellow
Write-Host "  2. Note the App ID from the settings page" -ForegroundColor Yellow
Write-Host "  3. Install the app on your repository" -ForegroundColor Yellow
Write-Host "  4. Note the Installation ID from the URL" -ForegroundColor Yellow
Write-Host ""

$manifestPath = Join-Path $PSScriptRoot "github-app-argocd-manifest.json"
if (!(Test-Path $manifestPath)) {
    Write-Error "Manifest file not found: $manifestPath"
}

# Open GitHub app creation page
$owner = $Repository.Split('/')[0]
$manifestUrl = "https://github.com/settings/apps/new"
Write-Host "Opening: $manifestUrl" -ForegroundColor Gray
Start-Process $manifestUrl

Write-Host ""
Write-Host "Press Enter after you have:" -ForegroundColor Yellow
Write-Host "  - Created the app" -ForegroundColor Yellow
Write-Host "  - Generated and downloaded the private key" -ForegroundColor Yellow
Write-Host "  - Installed the app on $Repository" -ForegroundColor Yellow
Read-Host

# Step 2: Collect information
Write-Host ""
Write-Host "📋 Step 2: Collect App Information" -ForegroundColor Cyan

$appId = Read-Host "Enter the App ID (from app settings page)"
$installationId = Read-Host "Enter the Installation ID (from installation URL)"
$privateKeyPath = Read-Host "Enter path to private key .pem file"

# Verify private key exists
if (!(Test-Path $privateKeyPath)) {
    Write-Error "Private key file not found: $privateKeyPath"
}

Write-Host "✓ App ID: $appId" -ForegroundColor Green
Write-Host "✓ Installation ID: $installationId" -ForegroundColor Green
Write-Host "✓ Private key: $privateKeyPath" -ForegroundColor Green

# Step 3: Create Kubernetes secret
Write-Host ""
Write-Host "🔐 Step 3: Create Kubernetes Secret" -ForegroundColor Cyan

# Delete existing secret if present
kubectl delete secret github-app -n argocd --ignore-not-found=true

# Create new secret
kubectl create secret generic github-app `
    --namespace=argocd `
    --from-literal=appID=$appId `
    --from-literal=installationID=$installationId `
    --from-file=privateKey=$privateKeyPath

if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to create Kubernetes secret"
}

Write-Host "✓ Secret created: github-app (namespace: argocd)" -ForegroundColor Green

# Step 4: Update ApplicationSet
Write-Host ""
Write-Host "📝 Step 4: Update ApplicationSet Configuration" -ForegroundColor Cyan
Write-Host ""
Write-Host "To use the GitHub App, update k8s/argocd/preview-appset.yaml:" -ForegroundColor Yellow
Write-Host ""
Write-Host "Replace:" -ForegroundColor Gray
Write-Host "  tokenRef:" -ForegroundColor Gray
Write-Host "    secretName: github-token" -ForegroundColor Gray
Write-Host "    key: token" -ForegroundColor Gray
Write-Host ""
Write-Host "With:" -ForegroundColor Green
Write-Host "  appSecretName: github-app" -ForegroundColor Green
Write-Host ""
Write-Host "Then apply the change:" -ForegroundColor Yellow
Write-Host "  kubectl apply -f k8s/argocd/preview-appset.yaml" -ForegroundColor Gray
Write-Host ""

Write-Host "✅ Setup Complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Update k8s/argocd/preview-appset.yaml to use appSecretName" -ForegroundColor White
Write-Host "  2. Apply: kubectl apply -f k8s/argocd/preview-appset.yaml" -ForegroundColor White
Write-Host "  3. Verify: kubectl get applicationset yt-summarizer-previews -n argocd" -ForegroundColor White
Write-Host "  4. Open a test PR to verify preview environment creation" -ForegroundColor White
Write-Host ""
