<#
.SYNOPSIS
    Cleans up all development containers and data for a fresh start.

.DESCRIPTION
    Stops and removes all Aspire-managed containers (SQL, Azurite storage),
    optionally removes Docker volumes for a completely fresh state.
    Use this when you have orphaned containers or want to start completely fresh.

.PARAMETER All
    Also removes Docker volumes (blob data, queue data). Without this flag,
    only containers are removed and volume data is preserved.

.PARAMETER Force
    Skip confirmation prompts.

.EXAMPLE
    .\clean-dev.ps1
    # Removes containers only, preserves volume data

.EXAMPLE
    .\clean-dev.ps1 -All
    # Removes containers AND all volume data (complete fresh start)

.EXAMPLE
    .\clean-dev.ps1 -All -Force
    # Complete cleanup without confirmation
#>

param(
    [switch]$All,
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host ""
Write-Host "[CLEANUP] Development Environment Cleanup" -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

# Find Aspire-managed containers
$sqlContainers = docker ps -a --filter "name=sql-" --format "{{.Names}}" 2>$null
$storageContainers = docker ps -a --filter "name=storage-" --format "{{.Names}}" 2>$null

$containerCount = 0
if ($sqlContainers) { $containerCount += ($sqlContainers | Measure-Object).Count }
if ($storageContainers) { $containerCount += ($storageContainers | Measure-Object).Count }

Write-Host "Found containers:" -ForegroundColor Yellow
if ($sqlContainers) {
    $sqlContainers | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }
} else {
    Write-Host "  (no SQL containers)" -ForegroundColor DarkGray
}
if ($storageContainers) {
    $storageContainers | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray }
} else {
    Write-Host "  (no storage containers)" -ForegroundColor DarkGray
}

if ($All) {
    Write-Host ""
    Write-Host "[WARNING] -All flag specified: Will also remove Docker volumes" -ForegroundColor Yellow
}

if (-not $Force -and $containerCount -gt 0) {
    Write-Host ""
    $confirm = Read-Host "Proceed with cleanup? (y/N)"
    if ($confirm -ne "y" -and $confirm -ne "Y") {
        Write-Host "Cancelled." -ForegroundColor Yellow
        exit 0
    }
}

# Stop and remove SQL containers
if ($sqlContainers) {
    Write-Host ""
    Write-Host "[REMOVE] Removing SQL containers..." -ForegroundColor Yellow
    $sqlContainers | ForEach-Object {
        Write-Host "  Stopping $_..." -ForegroundColor Gray
        docker stop $_ 2>$null | Out-Null
        docker rm $_ 2>$null | Out-Null
    }
    Write-Host "  [OK] SQL containers removed" -ForegroundColor Green
}

# Stop and remove storage containers
if ($storageContainers) {
    Write-Host ""
    Write-Host "[REMOVE] Removing storage containers..." -ForegroundColor Yellow
    $storageContainers | ForEach-Object {
        Write-Host "  Stopping $_..." -ForegroundColor Gray
        docker stop $_ 2>$null | Out-Null
        docker rm $_ 2>$null | Out-Null
    }
    Write-Host "  [OK] Storage containers removed" -ForegroundColor Green
}

# Remove volumes if -All specified
if ($All) {
    Write-Host ""
    Write-Host "[REMOVE] Removing Docker volumes..." -ForegroundColor Yellow

    # Find and remove Aspire-related volumes
    $volumes = docker volume ls --format "{{.Name}}" | Where-Object {
        $_ -match "sql|storage|azurite|ytsummarizer"
    }

    if ($volumes) {
        $volumes | ForEach-Object {
            Write-Host "  Removing volume $_..." -ForegroundColor Gray
            docker volume rm $_ 2>$null | Out-Null
        }
        Write-Host "  [OK] Volumes removed" -ForegroundColor Green
    } else {
        Write-Host "  (no matching volumes found)" -ForegroundColor DarkGray
    }
}

# Kill any orphaned Aspire/AppHost processes
Write-Host ""
Write-Host "[CHECK] Checking for orphaned processes..." -ForegroundColor Yellow
$appHostProcesses = Get-Process -Name "AppHost" -ErrorAction SilentlyContinue
if ($appHostProcesses) {
    $appHostProcesses | ForEach-Object {
        Write-Host "  Stopping AppHost process (PID: $($_.Id))..." -ForegroundColor Gray
        Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    }
    Write-Host "  [OK] Orphaned processes stopped" -ForegroundColor Green
} else {
    Write-Host "  (no orphaned processes)" -ForegroundColor DarkGray
}

Write-Host ""
Write-Host "[DONE] Cleanup complete!" -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Run 'aspire run' to start fresh" -ForegroundColor White
Write-Host "  2. Migrations will run automatically on API startup" -ForegroundColor White
Write-Host ""
