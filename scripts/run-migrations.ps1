<#
.SYNOPSIS
    Runs Alembic database migrations with timeout and error handling.

.DESCRIPTION
    This script runs Alembic migrations for the YT Summarizer application.
    It includes proper error handling, timeout support, and logging.

.PARAMETER Environment
    The target environment (staging, production)

.PARAMETER Timeout
    Maximum time in seconds to wait for migrations (default: 300)

.PARAMETER DryRun
    Show what migrations would be run without executing them

.EXAMPLE
    .\run-migrations.ps1 -Environment staging

.EXAMPLE
    .\run-migrations.ps1 -Environment production -DryRun
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet("staging", "production")]
    [string]$Environment,

    [Parameter(Mandatory = $false)]
    [int]$Timeout = 300,

    [Parameter(Mandatory = $false)]
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"

Write-Host "=== Database Migration Script ===" -ForegroundColor Cyan
Write-Host "Environment: $Environment"
Write-Host "Timeout: $Timeout seconds"
Write-Host "Dry Run: $DryRun"
Write-Host ""

# Change to the shared package directory (where alembic.ini is located)
$sharedDir = Join-Path $PSScriptRoot ".." "services" "shared"
Push-Location $sharedDir

try {
    # Check if alembic is available
    $alembicPath = Get-Command alembic -ErrorAction SilentlyContinue
    if (-not $alembicPath) {
        Write-Error "Alembic is not installed. Please install it with: pip install alembic"
        exit 1
    }

    # Show current migration status
    Write-Host "Current migration status:" -ForegroundColor Yellow
    alembic current

    # Show pending migrations
    Write-Host ""
    Write-Host "Pending migrations:" -ForegroundColor Yellow
    alembic history --indicate-current

    if ($DryRun) {
        Write-Host ""
        Write-Host "DRY RUN - No migrations will be applied" -ForegroundColor Yellow
        Write-Host "To apply migrations, run without -DryRun flag"
        exit 0
    }

    # Run migrations with timeout
    Write-Host ""
    Write-Host "Running migrations..." -ForegroundColor Green

    $job = Start-Job -ScriptBlock {
        param($dir)
        Set-Location $dir
        alembic upgrade head
    } -ArgumentList $sharedDir

    $completed = Wait-Job $job -Timeout $Timeout

    if (-not $completed) {
        Stop-Job $job
        Remove-Job $job
        Write-Error "Migration timed out after $Timeout seconds"
        exit 1
    }

    $result = Receive-Job $job
    $exitCode = $job.ChildJobs[0].JobStateInfo.Reason.ExitCode
    Remove-Job $job

    Write-Host $result

    if ($LASTEXITCODE -ne 0 -and $null -ne $LASTEXITCODE) {
        Write-Error "Migration failed with exit code: $LASTEXITCODE"
        exit 1
    }

    # Show final status
    Write-Host ""
    Write-Host "Final migration status:" -ForegroundColor Yellow
    alembic current

    Write-Host ""
    Write-Host "✅ Migrations completed successfully!" -ForegroundColor Green

} catch {
    Write-Error "Migration failed: $_"
    exit 1
} finally {
    Pop-Location
}
