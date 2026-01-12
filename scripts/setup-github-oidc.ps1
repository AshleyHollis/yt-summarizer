<#
.SYNOPSIS
    Sets up Azure OIDC federation for GitHub Actions

.DESCRIPTION
    This script creates:
    1. An Azure AD App Registration for GitHub Actions
    2. Federated credentials for the main branch and PRs
    3. Role assignments for the subscription/resource group
    4. Outputs the values needed for GitHub Secrets

.PARAMETER SubscriptionId
    Azure subscription ID

.PARAMETER ResourceGroupName
    Name of the resource group (for role assignment scope)

.PARAMETER GitHubOrg
    GitHub organization or username

.PARAMETER GitHubRepo
    GitHub repository name

.EXAMPLE
    .\setup-github-oidc.ps1 -SubscriptionId "xxx" -ResourceGroupName "rg-ytsumm-prd" -GitHubOrg "AshleyHollis" -GitHubRepo "yt-summarizer"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$SubscriptionId,
    
    [Parameter(Mandatory=$true)]
    [string]$ResourceGroupName,
    
    [Parameter(Mandatory=$true)]
    [string]$GitHubOrg,
    
    [Parameter(Mandatory=$true)]
    [string]$GitHubRepo
)

$ErrorActionPreference = "Stop"

Write-Host "[SETUP] Setting up Azure OIDC for GitHub Actions" -ForegroundColor Cyan
Write-Host ""

# Check if logged in to Azure
$account = az account show 2>$null | ConvertFrom-Json
if (-not $account) {
    Write-Host "Not logged in to Azure. Running 'az login'..." -ForegroundColor Yellow
    az login
    $account = az account show | ConvertFrom-Json
}

Write-Host "[OK] Logged in as: $($account.user.name)" -ForegroundColor Green
Write-Host "[OK] Subscription: $($account.name) ($($account.id))" -ForegroundColor Green
Write-Host ""

# Set the subscription
az account set --subscription $SubscriptionId

# Get tenant ID
$tenantId = (az account show | ConvertFrom-Json).tenantId

# Create App Registration
$appName = "github-actions-$GitHubRepo"
Write-Host "Creating App Registration: $appName..." -ForegroundColor Yellow

$existingApp = az ad app list --display-name $appName 2>$null | ConvertFrom-Json
if ($existingApp -and $existingApp.Count -gt 0) {
    Write-Host "  App already exists, using existing app" -ForegroundColor Yellow
    $app = $existingApp[0]
} else {
    $app = az ad app create --display-name $appName | ConvertFrom-Json
    Write-Host "  [OK] Created app: $($app.appId)" -ForegroundColor Green
}

$clientId = $app.appId

# Create Service Principal
Write-Host "Creating Service Principal..." -ForegroundColor Yellow
$existingSp = az ad sp list --filter "appId eq '$clientId'" 2>$null | ConvertFrom-Json
if ($existingSp -and $existingSp.Count -gt 0) {
    Write-Host "  Service principal already exists" -ForegroundColor Yellow
    $sp = $existingSp[0]
} else {
    $sp = az ad sp create --id $clientId | ConvertFrom-Json
    Write-Host "  [OK] Created service principal" -ForegroundColor Green
}

# Create Federated Credentials
Write-Host "Creating Federated Credentials..." -ForegroundColor Yellow

# Main branch credential
$mainCredName = "github-main"
$existingCreds = az ad app federated-credential list --id $clientId 2>$null | ConvertFrom-Json
$mainCredExists = $existingCreds | Where-Object { $_.name -eq $mainCredName }
if (-not $mainCredExists) {
    $mainCredential = @{
        name = $mainCredName
        issuer = "https://token.actions.githubusercontent.com"
        subject = "repo:${GitHubOrg}/${GitHubRepo}:ref:refs/heads/main"
        audiences = @("api://AzureADTokenExchange")
    } | ConvertTo-Json -Compress

    az ad app federated-credential create --id $clientId --parameters $mainCredential
    Write-Host "  [OK] Created credential for main branch" -ForegroundColor Green
} else {
    Write-Host "  Main branch credential already exists" -ForegroundColor Yellow
}

# PR credential (for pull request events)
$prCredName = "github-pr"
$prCredExists = $existingCreds | Where-Object { $_.name -eq $prCredName }
if (-not $prCredExists) {
    $prCredential = @{
        name = $prCredName
        issuer = "https://token.actions.githubusercontent.com"
        subject = "repo:${GitHubOrg}/${GitHubRepo}:pull_request"
        audiences = @("api://AzureADTokenExchange")
    } | ConvertTo-Json -Compress

    az ad app federated-credential create --id $clientId --parameters $prCredential
    Write-Host "  [OK] Created credential for pull requests" -ForegroundColor Green
} else {
    Write-Host "  PR credential already exists" -ForegroundColor Yellow
}

# Environment credential (for environment deployments)
$envCredName = "github-env-production"
$envCredExists = $existingCreds | Where-Object { $_.name -eq $envCredName }
if (-not $envCredExists) {
    $envCredential = @{
        name = $envCredName
        issuer = "https://token.actions.githubusercontent.com"
        subject = "repo:${GitHubOrg}/${GitHubRepo}:environment:production"
        audiences = @("api://AzureADTokenExchange")
    } | ConvertTo-Json -Compress

    az ad app federated-credential create --id $clientId --parameters $envCredential
    Write-Host "  [OK] Created credential for production environment" -ForegroundColor Green
} else {
    Write-Host "  Environment credential already exists" -ForegroundColor Yellow
}

# Repo-wide credential (for workflow_dispatch from any branch)
$repoCredName = "github-repo"
$repoCredExists = $existingCreds | Where-Object { $_.name -eq $repoCredName }
if (-not $repoCredExists) {
    $repoCredential = @{
        name = $repoCredName
        issuer = "https://token.actions.githubusercontent.com"
        subject = "repo:${GitHubOrg}/${GitHubRepo}"
        audiences = @("api://AzureADTokenExchange")
    } | ConvertTo-Json -Compress

    az ad app federated-credential create --id $clientId --parameters $repoCredential
    Write-Host "  [OK] Created credential for repo-wide access" -ForegroundColor Green
} else {
    Write-Host "  Repo-wide credential already exists" -ForegroundColor Yellow
}

# Assign Contributor role on subscription
Write-Host "Assigning Contributor role on subscription..." -ForegroundColor Yellow
$roleAssignments = az role assignment list --assignee $clientId --scope "/subscriptions/$SubscriptionId" 2>$null | ConvertFrom-Json
$roleExists = $roleAssignments | Where-Object { $_.roleDefinitionName -eq "Contributor" }
if (-not $roleExists) {
    az role assignment create --assignee $clientId --role "Contributor" --scope "/subscriptions/$SubscriptionId"
    Write-Host "  [OK] Assigned Contributor role" -ForegroundColor Green
} else {
    Write-Host "  Contributor role already assigned" -ForegroundColor Yellow
}

# Output the values for GitHub Secrets
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "[DONE] Setup Complete! Add these secrets to your GitHub repository:" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Go to: https://github.com/$GitHubOrg/$GitHubRepo/settings/secrets/actions" -ForegroundColor Yellow
Write-Host ""
Write-Host "Add the following repository secrets:" -ForegroundColor White
Write-Host ""
Write-Host "  AZURE_CLIENT_ID:        " -ForegroundColor Cyan -NoNewline
Write-Host $clientId -ForegroundColor White
Write-Host "  AZURE_TENANT_ID:        " -ForegroundColor Cyan -NoNewline
Write-Host $tenantId -ForegroundColor White
Write-Host "  AZURE_SUBSCRIPTION_ID:  " -ForegroundColor Cyan -NoNewline
Write-Host $SubscriptionId -ForegroundColor White
Write-Host "  SQL_ADMIN_PASSWORD:     " -ForegroundColor Cyan -NoNewline
Write-Host "(your secure password)" -ForegroundColor White
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan

# Copy to clipboard if available
$secretsOutput = @"
AZURE_CLIENT_ID=$clientId
AZURE_TENANT_ID=$tenantId
AZURE_SUBSCRIPTION_ID=$SubscriptionId
"@

try {
    $secretsOutput | Set-Clipboard
    Write-Host "[CLIPBOARD] Values copied to clipboard!" -ForegroundColor Green
} catch {
    # Clipboard not available
}
