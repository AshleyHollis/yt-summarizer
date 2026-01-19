<#
.SYNOPSIS
    Local CI validation script - runs checks before push to catch issues early.

.DESCRIPTION
    Mimics CI workflow locally to catch issues before pushing to remote.
    Runs TypeScript compilation, linting, tests, and builds for frontend.

    This script is automatically run by the pre-push hook, but can also be
    run manually with: npm run validate

.PARAMETER SkipTests
    Skip running tests (faster, but less comprehensive)

.PARAMETER SkipBuild
    Skip build validation (faster, but less comprehensive)

.EXAMPLE
    # Full validation (recommended before push)
    .\scripts\validate-local.ps1

.EXAMPLE
    # Quick validation without tests
    .\scripts\validate-local.ps1 -SkipTests

.EXAMPLE
    # Via npm script
    npm run validate
#>

param(
    [switch]$SkipTests,
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$script:allPassed = $true
$webDir = "apps/web"

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Error', 'Warning')]
        [string]$Type = 'Info'
    )

    $colors = @{
        'Info' = 'Cyan'
        'Success' = 'Green'
        'Error' = 'Red'
        'Warning' = 'Yellow'
    }

    $symbols = @{
        'Info' = '🔍'
        'Success' = '✅'
        'Error' = '❌'
        'Warning' = '⚠️'
    }

    Write-Host "$($symbols[$Type]) $Message" -ForegroundColor $colors[$Type]
}

function Invoke-Check {
    param(
        [string]$Name,
        [scriptblock]$Command
    )

    Write-Host ""
    Write-Status "Running: $Name" -Type Info
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray

    try {
        & $Command
        if ($LASTEXITCODE -ne 0) {
            throw "Command failed with exit code $LASTEXITCODE"
        }
        Write-Status "$Name passed" -Type Success
        return $true
    }
    catch {
        Write-Status "$Name failed: $_" -Type Error
        $script:allPassed = $false
        return $false
    }
}

Write-Host ""
Write-Host "╔═══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║         YT Summarizer - Local CI Validation              ║" -ForegroundColor Cyan
Write-Host "╚═══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# 1. TypeScript Check
Invoke-Check "TypeScript Compilation" {
    Set-Location $webDir
    npx tsc --noEmit
    Set-Location ../..
}

# 2. ESLint
Invoke-Check "ESLint" {
    Set-Location $webDir
    npm run lint
    Set-Location ../..
}

# 3. Prettier Check
Invoke-Check "Prettier Format Check" {
    Set-Location $webDir
    npx prettier --check .
    Set-Location ../..
}

# 4. Tests (optional)
if (-not $SkipTests) {
    Invoke-Check "Frontend Tests" {
        Set-Location $webDir
        npm run test:run
        Set-Location ../..
    }
} else {
    Write-Status "Skipping tests (--SkipTests flag)" -Type Warning
}

# 5. Build (optional)
if (-not $SkipBuild) {
    Invoke-Check "Production Build" {
        Set-Location $webDir
        npm run build:dev
        Set-Location ../..
    }
} else {
    Write-Status "Skipping build (--SkipBuild flag)" -Type Warning
}

# Summary
Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
Write-Host ""

if ($script:allPassed) {
    Write-Status "All checks passed! Safe to push." -Type Success
    exit 0
} else {
    Write-Status "Some checks failed. Please fix before pushing." -Type Error
    exit 1
}
