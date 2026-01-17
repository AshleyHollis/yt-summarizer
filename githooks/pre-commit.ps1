#!/usr/bin/env pwsh
# Pre-commit hook for yt-summarizer
# ALWAYS runs pre-commit validation in both CI and local environments
# Blocks commits if pre-commit checks fail
# Use --no-verify to bypass (not recommended)

$ErrorActionPreference = "Stop"

# Color codes for terminal output
$Colors = @{
    Red = 'Red'
    Green = 'Green'
    Cyan = 'Cyan'
    Yellow = 'Yellow'
}

function Write-ColorHost {
    param([string]$Message, [string]$Color = 'White')
    Write-Host $Message -ForegroundColor $Color
}

# Go to repository root
$RepoRoot = git rev-parse --show-toplevel 2>$null
if (-not $RepoRoot) {
    Write-ColorHost "ERROR: Could not find repository root" $Colors.Red
    exit 1
}

Set-Location $RepoRoot

Write-Host ""
Write-ColorHost "========================================" $Colors.Cyan
Write-ColorHost "RUNNING PRE-COMMIT VALIDATION" $Colors.Cyan
Write-ColorHost "========================================" $Colors.Cyan
Write-Host ""

# Check if Python exists
$Python = Get-Command python -ErrorAction SilentlyContinue
if (-not $Python) {
    Write-ColorHost "ERROR: python not found on PATH" $Colors.Red
    Write-ColorHost "Install Python or add it to PATH." $Colors.Yellow
    exit 1
}

# Run pre-commit with auto-fix via Python module
Write-ColorHost "Running python -m pre_commit run --all-files --verbose..." $Colors.Cyan
$process = Start-Process -FilePath "python" -ArgumentList "-m", "pre_commit", "run", "--all-files", "--verbose" -NoNewWindow -Wait -PassThru
$ExitCode = $process.ExitCode

if ($ExitCode -ne 0) {
    Write-Host ""
    Write-ColorHost "========================================" $Colors.Red
    Write-ColorHost "PRE-COMMIT VALIDATION FAILED" $Colors.Red
    Write-ColorHost "========================================" $Colors.Red
    Write-Host ""
    Write-ColorHost "Your commit has been BLOCKED." $Colors.Red
    Write-Host ""
    Write-ColorHost "The pre-commit checks found issues that must be fixed before committing." $Colors.Red
    Write-Host ""
    Write-ColorHost "How to fix:" $Colors.Yellow
    Write-ColorHost "  1. Review error messages above" $Colors.White
    Write-ColorHost "  2. Run 'pre-commit run --all-files --verbose' to auto-fix issues" $Colors.White
    Write-ColorHost "  3. Review fixes with 'git diff'" $Colors.White
    Write-ColorHost "  4. Add fixed files: git add ." $Colors.White
    Write-ColorHost "  5. Commit again: git commit ..." $Colors.White
    Write-Host ""
    Write-ColorHost "To bypass ALL git hooks (not recommended):" $Colors.Red
    Write-ColorHost "  git commit --no-verify ..." $Colors.Yellow
    Write-Host ""
    exit $ExitCode
} else {
    Write-Host ""
    Write-ColorHost "========================================" $Colors.Green
    Write-ColorHost "PRE-COMMIT VALIDATION PASSED" $Colors.Green
    Write-ColorHost "========================================" $Colors.Green
    Write-Host ""
    exit 0
}
