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

Write-Host "[SWA] output_location validated (expected empty string)." -ForegroundColor Green
