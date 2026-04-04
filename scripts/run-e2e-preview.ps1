#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Run Playwright E2E tests locally against a deployed preview environment.

.DESCRIPTION
    Fetches Auth0 config from Azure Key Vault, reads test credentials from a local
    secrets file (.env.e2e.local), then runs Playwright against the preview URLs for
    the specified PR. No local server needed — USE_EXTERNAL_SERVER=true is set.

.PARAMETER PrNumber
    The pull request number whose preview environment to test against.

.PARAMETER TestPattern
    Optional Playwright --grep pattern to run specific tests.
    Example: "rbac-admin" to run only RBAC admin tests.

.PARAMETER AllTests
    If set, removes the maxFailures limit (runs every test even after failures).
    Equivalent to MAX_FAILURES=0.

.PARAMETER ApiUrl
    Override the API URL. Defaults to https://api-pr-{PrNumber}.yt-summarizer.apps.ashleyhollis.com

.PARAMETER FrontendUrl
    Override the frontend (SWA) URL. Auto-detected from the latest PR preview comment if not set.

.EXAMPLE
    # Run all E2E tests against PR #186
    ./scripts/run-e2e-preview.ps1 186

    # Run only RBAC tests, no failure limit
    ./scripts/run-e2e-preview.ps1 186 -TestPattern "rbac" -AllTests

    # Run a specific spec file
    ./scripts/run-e2e-preview.ps1 186 -TestPattern "rbac-admin-access"
#>

param(
    [Parameter(Mandatory = $true)]
    [int]$PrNumber,

    [string]$TestPattern = "",

    [switch]$AllTests,

    [string]$ApiUrl = "",

    [string]$FrontendUrl = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$KV = "kv-ytsumm-prd-ci"
$AppsBaseDomain = "yt-summarizer.apps.ashleyhollis.com"

Write-Host "`n🚀 E2E Preview Runner — PR #$PrNumber`n" -ForegroundColor Cyan

# ---------------------------------------------------------------------------
# 1. Resolve URLs
# ---------------------------------------------------------------------------
if (-not $ApiUrl) {
    $ApiUrl = "https://api-pr-$PrNumber.$AppsBaseDomain"
}

if (-not $FrontendUrl) {
    Write-Host "🔍 Looking up frontend URL from PR #$PrNumber comments..." -ForegroundColor Yellow
    try {
        # The pipeline posts a comment containing the SWA preview URL
        $comments = gh pr view $PrNumber --repo AshleyHollis/yt-summarizer --json comments --jq '.comments[].body' 2>$null
        $swaLine = $comments | Select-String "azurestaticapps\.net" | Select-Object -Last 1
        if ($swaLine) {
            # Extract URL from markdown: e.g. [Preview](https://...)  or  https://...azurestaticapps.net
            $match = [regex]::Match($swaLine.Line, 'https://[^\s\)>"]+azurestaticapps\.net[^\s\)>"]*')
            if ($match.Success) {
                $FrontendUrl = $match.Value.TrimEnd('/')
                Write-Host "  ✅ Found: $FrontendUrl" -ForegroundColor Green
            }
        }
    } catch {
        # gh CLI not available or no comments yet
    }

    if (-not $FrontendUrl) {
        Write-Host "  ⚠  Could not auto-detect frontend URL." -ForegroundColor Yellow
        $FrontendUrl = Read-Host "  Enter the SWA preview URL for PR #$PrNumber (e.g. https://proud-hill-0940e7300-186.eastasia.6.azurestaticapps.net)"
        $FrontendUrl = $FrontendUrl.TrimEnd('/')
    }
}

Write-Host "  Frontend : $FrontendUrl"
Write-Host "  API      : $ApiUrl`n"

# ---------------------------------------------------------------------------
# 2. Load local secrets file (.env.e2e.local in repo root)
# ---------------------------------------------------------------------------
$envFile = Join-Path $PSScriptRoot ".." ".env.e2e.local"
if (Test-Path $envFile) {
    Write-Host "📂 Loading secrets from .env.e2e.local..." -ForegroundColor Yellow
    Get-Content $envFile | ForEach-Object {
        if ($_ -match '^\s*([^#][^=]+)=(.*)$') {
            $key = $Matches[1].Trim()
            $val = $Matches[2].Trim().Trim('"').Trim("'")
            [System.Environment]::SetEnvironmentVariable($key, $val, 'Process')
        }
    }
    Write-Host "  ✅ Loaded`n"
}

# ---------------------------------------------------------------------------
# 3. Fetch Auth0 config from Azure Key Vault (if not already set)
# ---------------------------------------------------------------------------
$kvSecrets = @{
    "AUTH0_DOMAIN"        = "auth0-domain"
    "AUTH0_CLIENT_ID"     = "auth0-client-id"
    "AUTH0_CLIENT_SECRET" = "auth0-client-secret"
}

$needsKv = $kvSecrets.Keys | Where-Object { -not [System.Environment]::GetEnvironmentVariable($_) }
if ($needsKv) {
    Write-Host "🔑 Fetching Auth0 config from Key Vault ($KV)..." -ForegroundColor Yellow
    foreach ($envKey in $needsKv) {
        $kvName = $kvSecrets[$envKey]
        try {
            $val = az keyvault secret show --vault-name $KV --name $kvName --query "value" -o tsv 2>$null
            if ($val) {
                [System.Environment]::SetEnvironmentVariable($envKey, $val.Trim(), 'Process')
                Write-Host "  ✅ $envKey"
            } else {
                Write-Host "  ⚠  $envKey — not found in Key Vault" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "  ❌ $envKey — Key Vault fetch failed: $_" -ForegroundColor Red
        }
    }
    Write-Host ""
}

# ---------------------------------------------------------------------------
# 4. Validate required secrets
# ---------------------------------------------------------------------------
$required = @(
    @{ Var = "AUTH0_DOMAIN";          Hint = "Auth0 tenant domain (e.g. your-tenant.us.auth0.com)" },
    @{ Var = "AUTH0_CLIENT_ID";       Hint = "Auth0 application client ID" },
    @{ Var = "AUTH0_ADMIN_TEST_EMAIL";    Hint = "Admin test user email" },
    @{ Var = "AUTH0_ADMIN_TEST_PASSWORD"; Hint = "Admin test user password" },
    @{ Var = "AUTH0_USER_TEST_EMAIL";     Hint = "Normal test user email" },
    @{ Var = "AUTH0_USER_TEST_PASSWORD";  Hint = "Normal test user password" }
)

$missing = $required | Where-Object { -not [System.Environment]::GetEnvironmentVariable($_.Var) }
if ($missing) {
    Write-Host "❌ Missing required credentials:" -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "   $($_.Var) — $($_.Hint)" -ForegroundColor Red }
    Write-Host "`n  Create $(Resolve-Path (Join-Path $PSScriptRoot '..'))\.env.e2e.local with these values."
    Write-Host "  See scripts/.env.e2e.local.example for the template.`n"
    exit 1
}
Write-Host "✅ All credentials present`n"

# ---------------------------------------------------------------------------
# 5. Set Playwright env vars
# ---------------------------------------------------------------------------
$auth0Domain = [System.Environment]::GetEnvironmentVariable("AUTH0_DOMAIN")

$env:USE_EXTERNAL_SERVER  = "true"
$env:BASE_URL             = $FrontendUrl
$env:FRONTEND_URL         = $FrontendUrl
$env:API_URL              = $ApiUrl
$env:NEXT_PUBLIC_API_URL  = $ApiUrl
$env:AUTH0_ISSUER_BASE_URL = if ($auth0Domain.StartsWith("https://")) { $auth0Domain } else { "https://$auth0Domain" }
$env:AUTH0_CLIENT_ID      = [System.Environment]::GetEnvironmentVariable("AUTH0_CLIENT_ID")
$env:AUTH0_CLIENT_SECRET  = [System.Environment]::GetEnvironmentVariable("AUTH0_CLIENT_SECRET")
$env:AUTH0_ADMIN_TEST_EMAIL    = [System.Environment]::GetEnvironmentVariable("AUTH0_ADMIN_TEST_EMAIL")
$env:AUTH0_ADMIN_TEST_PASSWORD = [System.Environment]::GetEnvironmentVariable("AUTH0_ADMIN_TEST_PASSWORD")
$env:AUTH0_USER_TEST_EMAIL     = [System.Environment]::GetEnvironmentVariable("AUTH0_USER_TEST_EMAIL")
$env:AUTH0_USER_TEST_PASSWORD  = [System.Environment]::GetEnvironmentVariable("AUTH0_USER_TEST_PASSWORD")

$ytApiKey = [System.Environment]::GetEnvironmentVariable("YT_SUMMARIZER_API_KEY")
if ($ytApiKey) { $env:YT_SUMMARIZER_API_KEY = $ytApiKey }

if ($AllTests) {
    $env:MAX_FAILURES = "0"
    Write-Host "⚠  Running ALL tests (no failure limit)`n" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 6. Build Playwright args
# ---------------------------------------------------------------------------
$playwrightArgs = @("test", "--reporter=html,list")

if ($TestPattern) {
    $playwrightArgs += "--grep", $TestPattern
    Write-Host "🔍 Test filter: $TestPattern`n" -ForegroundColor Cyan
}

# ---------------------------------------------------------------------------
# 7. Run from apps/web
# ---------------------------------------------------------------------------
$webDir = Join-Path $PSScriptRoot ".." "apps" "web"
Push-Location $webDir

try {
    Write-Host "▶  npx playwright $($playwrightArgs -join ' ')`n" -ForegroundColor White
    npx playwright @playwrightArgs
    $exitCode = $LASTEXITCODE
} finally {
    Pop-Location
}

if ($exitCode -ne 0) {
    Write-Host "`n❌ Tests failed (exit $exitCode). Open the report with:" -ForegroundColor Red
    Write-Host "   npx playwright show-report apps/web/playwright-report" -ForegroundColor Yellow
} else {
    Write-Host "`n✅ All tests passed!" -ForegroundColor Green
}

exit $exitCode
