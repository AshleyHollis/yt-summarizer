#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Recreate GitHub App secret with ArgoCD-compatible format

.DESCRIPTION
    Creates the github-app secret with proper structure for ArgoCD ApplicationSet.
    ArgoCD requires specific fields including githubAppID, githubAppInstallationID,
    and githubAppPrivateKey (not just appID/installationID/privateKey).

.EXAMPLE
    .\recreate-github-app-secret.ps1 -AppID 2639539 -InstallationID 103781003 -PrivateKeyPath "path\to\key.pem"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$AppID,

    [Parameter(Mandatory=$true)]
    [string]$InstallationID,

    [Parameter(Mandatory=$true)]
    [string]$PrivateKeyPath
)

$ErrorActionPreference = "Stop"

Write-Host "Recreating GitHub App secret for ArgoCD..." -ForegroundColor Cyan

# Verify private key exists
if (!(Test-Path $PrivateKeyPath)) {
    Write-Error "Private key file not found: $PrivateKeyPath"
}

# Delete existing secret if present
Write-Host "  Deleting old secret (if exists)..." -ForegroundColor Yellow
kubectl delete secret github-app -n argocd --ignore-not-found=true

# Create secret with ArgoCD-compatible format
Write-Host "  Creating new secret with correct format..." -ForegroundColor Yellow
kubectl create secret generic github-app `
    --namespace=argocd `
    --from-literal=githubAppID=$AppID `
    --from-literal=githubAppInstallationID=$InstallationID `
    --from-file=githubAppPrivateKey=$PrivateKeyPath

if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to create Kubernetes secret"
}

# Add ArgoCD label
Write-Host "  Adding ArgoCD label..." -ForegroundColor Yellow
kubectl label secret github-app -n argocd argocd.argoproj.io/secret-type=repository

Write-Host ""
Write-Host "  [OK] Secret recreated successfully!" -ForegroundColor Green
Write-Host ""
Write-Host "Verifying secret structure..." -ForegroundColor Cyan
kubectl get secret github-app -n argocd -o jsonpath='{.data}' | ConvertFrom-Json | Get-Member -MemberType NoteProperty | Select-Object Name | Format-Table -HideTableHeaders

Write-Host "Waiting for ApplicationSet controller to pick up changes..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

Write-Host ""
Write-Host "Checking ApplicationSet controller logs..." -ForegroundColor Cyan
kubectl logs -n argocd -l app.kubernetes.io/name=argocd-applicationset-controller --tail=5 --since=10s
