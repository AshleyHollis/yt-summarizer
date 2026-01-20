#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Verifies that all DEPLOYMENT-AUDIT-FINDINGS.md recommendations have been implemented.

.DESCRIPTION
    This script checks:
    - Dead code has been removed
    - Required workflow steps exist in both pipelines
    - Environment variables are defined
    - Actions are properly configured
    - HTTP polling consolidation is complete

.EXAMPLE
    .\scripts\verify-audit-completion.ps1
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Write-Host "🔍 Verifying Deployment Audit Completion..." -ForegroundColor Cyan
Write-Host ""

$allPassed = $true
$checks = @()

# Helper function to add check result
function Add-Check {
    param(
        [string]$Name,
        [bool]$Passed,
        [string]$Details = ""
    )

    $script:checks += [PSCustomObject]@{
        Name = $Name
        Passed = $Passed
        Details = $Details
    }

    if (-not $Passed) {
        $script:allPassed = $false
    }
}

# =============================================================================
# Check 1: Dead code removed
# =============================================================================

Write-Host "Checking dead code removal..." -ForegroundColor Yellow

$deadFile1 = ".github/actions/verify-deployment/run-verification.sh"
$deadFile2 = ".github/actions/verify-deployment/check-argocd-readiness.sh"

$file1Missing = -not (Test-Path $deadFile1)
$file2Missing = -not (Test-Path $deadFile2)

Add-Check -Name "Dead code: run-verification.sh removed" -Passed $file1Missing
Add-Check -Name "Dead code: check-argocd-readiness.sh removed" -Passed $file2Missing

# =============================================================================
# Check 2: Environment variables defined
# =============================================================================

Write-Host "Checking environment variables..." -ForegroundColor Yellow

$prodWorkflow = Get-Content ".github/workflows/deploy-prod.yml" -Raw
$previewWorkflow = Get-Content ".github/workflows/preview.yml" -Raw

$requiredEnvVars = @(
    'ACR_NAME',
    'API_IMAGE_NAME',
    'WORKERS_IMAGE_NAME',
    'NAMESPACE_ARGOCD',
    'WORKER_DEPLOYMENTS',
    'HEALTH_CHECK_PATH',
    'ARGOCD_SYNC_TIMEOUT',
    'HEALTH_CHECK_MAX_ATTEMPTS',
    'KUSTOMIZE_VERSION',
    'TERRAFORM_VERSION'
)

foreach ($envVar in $requiredEnvVars) {
    $inProd = $prodWorkflow -match "$envVar\s*:"
    $inPreview = $previewWorkflow -match "$envVar\s*:"

    Add-Check -Name "Env var $envVar in production" -Passed $inProd
    Add-Check -Name "Env var $envVar in preview" -Passed $inPreview
}

# =============================================================================
# Check 3: Production pipeline features
# =============================================================================

Write-Host "Checking production pipeline features..." -ForegroundColor Yellow

$prodFeatures = @{
    'TLS certificate validation' = 'verify-certificate'
    'External health check' = 'external.*health.*check|health-check.*External'
    'K8s pull test' = 'run-k8s-pull-test'
    'Image tag validation' = 'validate-image-tag'
    'ArgoCD readiness check' = 'check-argocd-readiness'
    'Deployment diagnostics' = 'deployment-diagnostics'
}

foreach ($feature in $prodFeatures.GetEnumerator()) {
    $found = $prodWorkflow -match $feature.Value
    Add-Check -Name "Production: $($feature.Key)" -Passed $found
}

# =============================================================================
# Check 4: Preview pipeline features
# =============================================================================

Write-Host "Checking preview pipeline features..." -ForegroundColor Yellow

$previewFeatures = @{
    'ArgoCD readiness check' = 'check-argocd-readiness'
    'Deployment diagnostics' = 'deployment-diagnostics'
    'TLS certificate validation' = 'verify-certificate'
}

foreach ($feature in $previewFeatures.GetEnumerator()) {
    $found = $previewWorkflow -match $feature.Value
    Add-Check -Name "Preview: $($feature.Key)" -Passed $found
}

# =============================================================================
# Check 5: Worker verification consistency
# =============================================================================

Write-Host "Checking worker verification consistency..." -ForegroundColor Yellow

$prodWorkerFail = $prodWorkflow -match "fail-on-mismatch:\s*'true'"
$previewWorkerFail = $previewWorkflow -match "fail-on-mismatch:\s*'true'"

Add-Check -Name "Production workers fail-on-mismatch" -Passed $prodWorkerFail
Add-Check -Name "Preview workers fail-on-mismatch" -Passed $previewWorkerFail

# =============================================================================
# Check 6: HTTP polling consolidation
# =============================================================================

Write-Host "Checking HTTP polling consolidation..." -ForegroundColor Yellow

$healthCheckPreviewAction = Get-Content ".github/actions/health-check-preview/action.yml" -Raw
$usesHealthCheck = $healthCheckPreviewAction -match "uses:\s*./.github/actions/health-check"

Add-Check -Name "health-check-preview uses health-check action" -Passed $usesHealthCheck

# Check for old external health script
$oldScriptExists = Test-Path ".github/actions/health-check-preview/check-external-health.sh.old"
Add-Check -Name "Old external health script archived" -Passed $oldScriptExists

# =============================================================================
# Check 7: Required actions exist
# =============================================================================

Write-Host "Checking required actions exist..." -ForegroundColor Yellow

$requiredActions = @(
    'check-argocd-readiness',
    'health-check',
    'health-check-preview',
    'verify-certificate',
    'verify-deployment',
    'verify-workers',
    'validate-image-tag',
    'validate-acr-image'
)

foreach ($action in $requiredActions) {
    $actionPath = ".github/actions/$action/action.yml"
    $exists = Test-Path $actionPath
    Add-Check -Name "Action exists: $action" -Passed $exists
}

# =============================================================================
# Summary
# =============================================================================

Write-Host ""
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "Audit Verification Summary" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""

$passed = ($checks | Where-Object { $_.Passed }).Count
$total = $checks.Count
$failed = $total - $passed

Write-Host "Total Checks: $total" -ForegroundColor White
Write-Host "Passed: $passed" -ForegroundColor Green
Write-Host "Failed: $failed" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
Write-Host ""

if ($failed -gt 0) {
    Write-Host "Failed Checks:" -ForegroundColor Red
    $checks | Where-Object { -not $_.Passed } | ForEach-Object {
        Write-Host "  ❌ $($_.Name)" -ForegroundColor Red
        if ($_.Details) {
            Write-Host "     $($_.Details)" -ForegroundColor Gray
        }
    }
    Write-Host ""
}

if ($allPassed) {
    Write-Host "✅ All audit findings have been successfully implemented!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "❌ Some audit findings are not yet complete." -ForegroundColor Red
    exit 1
}
