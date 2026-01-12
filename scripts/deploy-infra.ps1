<#
.SYNOPSIS
    Deploy infrastructure using Terraform
.DESCRIPTION
    Initializes and applies Terraform configuration for the specified environment
.PARAMETER Environment
    Target environment (staging or production)
.PARAMETER Plan
    Generate plan only, do not apply
.PARAMETER AutoApprove
    Skip interactive approval (for CI/CD)
.EXAMPLE
    .\scripts\deploy-infra.ps1 -Environment staging
    .\scripts\deploy-infra.ps1 -Environment production -Plan
    .\scripts\deploy-infra.ps1 -Environment staging -AutoApprove
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("staging", "production")]
    [string]$Environment,

    [switch]$Plan,
    [switch]$AutoApprove,
    [switch]$Destroy
)

$ErrorActionPreference = "Stop"
$scriptPath = Split-Path -Parent $MyInvocation.MyCommand.Path
$repoRoot = Split-Path -Parent $scriptPath
$terraformDir = Join-Path $repoRoot "infra" "terraform" "environments" $Environment

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Infrastructure Deployment Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Environment: $Environment" -ForegroundColor Yellow
Write-Host "Terraform Directory: $terraformDir" -ForegroundColor Yellow
Write-Host ""

# Validate Terraform is installed
if (-not (Get-Command terraform -ErrorAction SilentlyContinue)) {
    Write-Error "Terraform is not installed or not in PATH"
    exit 1
}

# Validate directory exists
if (-not (Test-Path $terraformDir)) {
    Write-Error "Terraform directory not found: $terraformDir"
    exit 1
}

# Change to Terraform directory
Push-Location $terraformDir

try {
    # Initialize Terraform
    Write-Host "`n📦 Initializing Terraform..." -ForegroundColor Cyan
    terraform init -input=false
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Terraform init failed"
        exit 1
    }

    # Validate configuration
    Write-Host "`n✅ Validating Terraform configuration..." -ForegroundColor Cyan
    terraform validate
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Terraform validation failed"
        exit 1
    }

    if ($Destroy) {
        Write-Host "`n🔴 DESTROYING INFRASTRUCTURE..." -ForegroundColor Red
        Write-Host "Environment: $Environment" -ForegroundColor Red

        if ($AutoApprove) {
            terraform destroy -auto-approve
        } else {
            terraform destroy
        }

        if ($LASTEXITCODE -ne 0) {
            Write-Error "Terraform destroy failed"
            exit 1
        }

        Write-Host "`n✅ Infrastructure destroyed successfully!" -ForegroundColor Green
        exit 0
    }

    # Generate plan
    $planFile = "tfplan-$Environment-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Write-Host "`n📋 Generating Terraform plan..." -ForegroundColor Cyan
    terraform plan -out="$planFile" -input=false
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Terraform plan failed"
        exit 1
    }

    # Show plan summary
    Write-Host "`n📊 Plan Summary:" -ForegroundColor Cyan
    terraform show -no-color $planFile | Select-String -Pattern "Plan:|No changes"

    if ($Plan) {
        Write-Host "`n📄 Plan generated: $planFile" -ForegroundColor Green
        Write-Host "Run without -Plan to apply" -ForegroundColor Yellow
        exit 0
    }

    # Apply
    Write-Host "`n🚀 Applying Terraform plan..." -ForegroundColor Cyan
    if ($AutoApprove) {
        terraform apply -auto-approve $planFile
    } else {
        Write-Host "Review the plan above and confirm to proceed..." -ForegroundColor Yellow
        terraform apply $planFile
    }

    if ($LASTEXITCODE -ne 0) {
        Write-Error "Terraform apply failed"
        exit 1
    }

    # Output key values
    Write-Host "`n📤 Terraform Outputs:" -ForegroundColor Cyan
    terraform output

    Write-Host "`n========================================" -ForegroundColor Green
    Write-Host "✅ Infrastructure deployment complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green

} finally {
    Pop-Location
}
