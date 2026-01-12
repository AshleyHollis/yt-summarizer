<#
.SYNOPSIS
Pre-commit wrapper that handles Windows UTF-8 encoding issues

.DESCRIPTION
This script runs pre-commit hooks with proper UTF-8 encoding support on Windows.
It sets PYTHONUTF8 environment variable to avoid encoding issues with yamllint.
#>

param(
    [string[]]$Files,
    [switch]$AllFiles,
    [switch]$HookStage
)

$ErrorActionPreference = "Stop"

# Set UTF-8 encoding for Python (fixes yamllint on Windows)
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"

# Pre-commit executable path
$precommitCmd = Get-Command python -ErrorAction SilentlyContinue |
    Where-Object { $_.Source -like "*Python314*" } |
    Select-Object -FirstProperty Source

if (-not $precommitCmd) {
    # Try to find pre-commit in AppData/Roaming
    $precommitPath = "$env:APPDATA\Python\Python314\Scripts\pre-commit.exe"
    if (Test-Path $precommitPath) {
        $precommitCmd = $precommitPath
    }
    else {
        # Try C:\Python314
        $precommitPath = "C:\Python314\Scripts\pre-commit.exe"
        if (Test-Path $precommitPath) {
            $precommitCmd = $precommitPath
        }
        else {
            # Fallback to python -m
            $precommitCmd = "C:\Python314\python.exe -m pre_commit"
        }
    }
}

# Build arguments
$argsList = @()

if ($AllFiles) {
    $argsList += "run", "--all-files"
}
elseif ($Files) {
    $argsList += "run", "--files", $Files
}
elseif ($HookStage) {
    # Run as git hook
    $argsList += "run"
}
else {
    $argsList += "run", "--all-files"
}

# Show what we're running
Write-Host "Running pre-commit..." -ForegroundColor Cyan
Write-Host "Command: $precommitCmd $($argsList -join ' ')" -ForegroundColor Gray

# Execute
if ($precommitCmd -match "python.exe") {
    & C:\Python314\python.exe -m pre_commit $argsList
}
else {
    & $precommitCmd $argsList
}

exit $LASTEXITCODE
