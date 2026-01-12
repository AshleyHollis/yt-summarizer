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

Write-Host ""
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "  GitHub App Setup for ArgoCD ApplicationSet" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
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
Write-Host "  [OK] kubectl context: $context" -ForegroundColor Green

# Verify gh auth
$authStatus = gh auth status 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "gh CLI not authenticated. Run: gh auth login"
}
Write-Host "  [OK] gh CLI authenticated" -ForegroundColor Green
Write-Host ""

# Step 1: Create GitHub App
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host " Step 1: Create GitHub App" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "I'll guide you through creating a GitHub App with the correct permissions." -ForegroundColor White
Write-Host ""
Write-Host "Opening GitHub App creation page in your browser..." -ForegroundColor Yellow
Start-Sleep -Seconds 2

$owner = $Repository.Split('/')[0]
$createUrl = "https://github.com/settings/apps/new"
Start-Process $createUrl

Write-Host ""
Write-Host "Fill in the form with these values:" -ForegroundColor Cyan
Write-Host ""
Write-Host "  GitHub App name: " -NoNewline -ForegroundColor Gray
Write-Host "$AppName" -ForegroundColor Green
Write-Host "  Homepage URL: " -NoNewline -ForegroundColor Gray
Write-Host "https://argocd.yt-summarizer.com" -ForegroundColor Green
Write-Host "  Webhook: " -NoNewline -ForegroundColor Gray
Write-Host "Uncheck 'Active'" -ForegroundColor Green
Write-Host ""
Write-Host "  Repository permissions:" -ForegroundColor Gray
Write-Host "    - Contents: " -NoNewline -ForegroundColor Gray
Write-Host "Read-only" -ForegroundColor Green
Write-Host "    - Pull requests: " -NoNewline -ForegroundColor Gray
Write-Host "Read-only" -ForegroundColor Green
Write-Host "    - Metadata: " -NoNewline -ForegroundColor Gray
Write-Host "Read-only (auto-selected)" -ForegroundColor Green
Write-Host ""
Write-Host "  Where can this GitHub App be installed?" -ForegroundColor Gray
Write-Host "    - Select: " -NoNewline -ForegroundColor Gray
Write-Host "Only on this account" -ForegroundColor Green
Write-Host ""
Write-Host "Then click 'Create GitHub App'" -ForegroundColor Yellow
Write-Host ""
Write-Host "---------------------------------------------------------------------" -ForegroundColor DarkGray
Read-Host "Press Enter after creating the app"

# Step 1b: Generate private key
Write-Host ""
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host " Step 1b: Generate Private Key" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "In the app settings page:" -ForegroundColor White
Write-Host "  1. Scroll down to 'Private keys' section" -ForegroundColor Gray
Write-Host "  2. Click 'Generate a private key'" -ForegroundColor Gray
Write-Host "  3. Save the downloaded .pem file" -ForegroundColor Gray
Write-Host ""
Write-Host "Also note the App ID (shown at the top of the settings page)" -ForegroundColor Yellow
Write-Host ""
Write-Host "---------------------------------------------------------------------" -ForegroundColor DarkGray
Read-Host "Press Enter after downloading the private key"

# Step 1c: Install app
Write-Host ""
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host " Step 1c: Install App on Repository" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "In the app settings page:" -ForegroundColor White
Write-Host "  1. Click 'Install App' in the left sidebar" -ForegroundColor Gray
Write-Host "  2. Click 'Install' next to your account" -ForegroundColor Gray
Write-Host "  3. Select 'Only select repositories'" -ForegroundColor Gray
Write-Host "  4. Choose: " -NoNewline -ForegroundColor Gray
Write-Host "$Repository" -ForegroundColor Green
Write-Host "  5. Click 'Install'" -ForegroundColor Gray
Write-Host ""
Write-Host "After installation, note the Installation ID from the URL:" -ForegroundColor Yellow
Write-Host "  Example: https://github.com/settings/installations/12345678" -ForegroundColor DarkGray
Write-Host "  Installation ID: " -NoNewline -ForegroundColor DarkGray
Write-Host "12345678" -ForegroundColor Green
Write-Host ""
Write-Host "---------------------------------------------------------------------" -ForegroundColor DarkGray
Read-Host "Press Enter after installing the app"

# Step 2: Collect information
Write-Host ""
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host " Step 2: Collect App Information" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""

$appId = Read-Host "Enter the App ID (from app settings page)"
$installationId = Read-Host "Enter the Installation ID (from installation URL)"
$privateKeyPath = Read-Host "Enter path to private key .pem file"

# Verify private key exists
if (!(Test-Path $privateKeyPath)) {
    Write-Error "Private key file not found: $privateKeyPath"
}

Write-Host ""
Write-Host "  [OK] App ID: $appId" -ForegroundColor Green
Write-Host "  [OK] Installation ID: $installationId" -ForegroundColor Green
Write-Host "  [OK] Private key: $privateKeyPath" -ForegroundColor Green

# Step 3: Create Kubernetes secret
Write-Host ""
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host " Step 3: Create Kubernetes Secret" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""

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

Write-Host "  [OK] Secret created: github-app (namespace: argocd)" -ForegroundColor Green

# Step 4: Update ApplicationSet
Write-Host ""
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host " Step 4: Update ApplicationSet Configuration" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
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

Write-Host "=====================================================================" -ForegroundColor Green
Write-Host " Setup Complete!" -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Update k8s/argocd/preview-appset.yaml to use appSecretName" -ForegroundColor White
Write-Host "  2. Apply: kubectl apply -f k8s/argocd/preview-appset.yaml" -ForegroundColor White
Write-Host "  3. Verify: kubectl get applicationset yt-summarizer-previews -n argocd" -ForegroundColor White
Write-Host "  4. Open a test PR to verify preview environment creation" -ForegroundColor White
Write-Host ""
