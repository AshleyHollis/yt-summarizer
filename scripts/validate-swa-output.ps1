param()

$ErrorActionPreference = "Stop"

$repoRoot = git rev-parse --show-toplevel 2>$null
if (-not $repoRoot) {
    $repoRoot = Split-Path -Parent $PSScriptRoot
}

$checks = @(
    @{ Path = ".github/workflows/deploy-prod.yml"; Expected = '""' },
    @{ Path = ".github/workflows/swa-baseline-deploy.yml"; Expected = '""' }
)

function Get-OutputLocationValues {
    param(
        [string]$FilePath
    )

    $matches = Select-String -Path $FilePath -Pattern '^\s*output_location:\s*(.+)$'
    if (-not $matches) {
        throw "No output_location entries found in $FilePath"
    }

    return $matches | ForEach-Object {
        $_.Matches[0].Groups[1].Value.Trim()
    }
}

foreach ($check in $checks) {
    $fullPath = Join-Path $repoRoot $check.Path
    if (-not (Test-Path $fullPath)) {
        throw "Missing workflow file: $($check.Path)"
    }

    $values = Get-OutputLocationValues -FilePath $fullPath
    foreach ($value in $values) {
        if ($value -ne $check.Expected) {
            throw "Invalid output_location in $($check.Path). Expected $($check.Expected), found $value"
        }
    }
}

$deployWorkflowPath = Join-Path $repoRoot ".github\workflows\deploy-prod.yml"
$tokenMatches = Select-String -Path $deployWorkflowPath -Pattern '^\s*azure_static_web_apps_api_token:\s*\${{\s*secrets\.([^\s}]+)\s*}}'
$tokenInputMatches = Select-String -Path $deployWorkflowPath -Pattern '^\s*swa-token:\s*\${{\s*secrets\.([^\s}]+)\s*}}'
$allTokenMatches = @()
if ($tokenMatches) {
    $allTokenMatches += $tokenMatches
}
if ($tokenInputMatches) {
    $allTokenMatches += $tokenInputMatches
}

if (-not $allTokenMatches) {
    throw "Missing SWA deployment token configuration in deploy-prod.yml"
}

foreach ($match in $allTokenMatches) {
    $tokenName = $match.Matches[0].Groups[1].Value.Trim()
    if ($tokenName -ne "SWA_DEPLOYMENT_TOKEN") {
        throw "Invalid SWA token in deploy-prod.yml. Expected SWA_DEPLOYMENT_TOKEN, found $tokenName."
    }
}

$packageJsonPath = Join-Path $repoRoot "apps\web\package.json"
if (-not (Test-Path $packageJsonPath)) {
    throw "Missing package.json: apps/web/package.json"
}

$packageJson = Get-Content $packageJsonPath -Raw | ConvertFrom-Json
$buildScript = $packageJson.scripts.build
if (-not $buildScript) {
    throw "Missing build script in apps/web/package.json"
}

if (-not ($buildScript -match "^next build --webpack")) {
    throw "Invalid build script in apps/web/package.json. Expected to start with 'next build --webpack' to match SWA baseline."
}

Write-Host "[SWA] output_location, token, and build script validated." -ForegroundColor Green

$rootPackageJson = Join-Path $repoRoot "package.json"
if (Test-Path $rootPackageJson) {
    throw "Root package.json detected. Remove root lockfiles to avoid Next.js output tracing issues in SWA."
}

$rootPackageLock = Join-Path $repoRoot "package-lock.json"
if (Test-Path $rootPackageLock) {
    throw "Root package-lock.json detected. Remove root lockfiles to avoid Next.js output tracing issues in SWA."
}

Write-Host "[SWA] root lockfiles check passed." -ForegroundColor Green
