#!/usr/bin/env pwsh
# Pre-push hook for yt-summarizer
# ALWAYS runs pre-commit validation before allowing push
# Blocks push if pre-commit checks would fail
# Bypass with --no-verify (not recommended)

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
    exit 0  # Allow push if repo root not found (fallback to CI)
}

Set-Location $RepoRoot

Write-Host ""
Write-ColorHost "========================================" $Colors.Cyan
Write-ColorHost "PRE-PUSH: VALIDATING PRE-COMMIT" $Colors.Cyan
Write-ColorHost "========================================" $Colors.Cyan
Write-Host ""
Write-ColorHost "Running pre-commit to ensure no issues before pushing..." $Colors.Cyan
Write-ColorHost "This prevents you from pushing code that will fail in CI." $Colors.Cyan
Write-Host ""

# Check if pre-commit command exists
$PreCommit = Get-Command pre-commit -ErrorAction SilentlyContinue
if (-not $PreCommit) {
    Write-ColorHost "ERROR: pre-commit not found on PATH" $Colors.Red
    Write-ColorHost "Install pre-commit: pip install pre-commit" $Colors.Yellow
    Write-ColorHost "Push blocked to enforce local auto-fix." $Colors.Red
    exit 1
}

# Run pre-commit local validation (no auto-fix)
Write-ColorHost "Running pre-commit --all-files --verbose..." $Colors.Cyan
$process = Start-Process -FilePath "pre-commit" -ArgumentList "run", "--all-files", "--verbose" -NoNewWindow -Wait -PassThru
$ExitCode = $process.ExitCode

if ($ExitCode -ne 0) {
    Write-Host ""
    Write-ColorHost "========================================" $Colors.Red
    Write-ColorHost "PRE-PUSH VALIDATION FAILED" $Colors.Red
    Write-ColorHost "========================================" $Colors.Red
    Write-Host ""
    Write-ColorHost "Your PUSH has been BLOCKED." $Colors.Red
    Write-Host ""
    Write-ColorHost "Issues found that must be fixed before pushing" $Colors.Red
    Write-Host ""
    Write-ColorHost "How to fix:" $Colors.Yellow
    Write-ColorHost "  1. Run 'pre-commit run --all-files --verbose' to auto-fix issues" $Colors.White
    Write-ColorHost "  2. Review fixes: git diff" $Colors.White
    Write-ColorHost "  3. Add fixes: git add ." $Colors.White
    Write-ColorHost "  4. Commit: git commit -m 'fix: apply pre-commit fixes'" $Colors.White
    Write-ColorHost "  5. Push again" $Colors.White
    Write-Host ""
    Write-ColorHost "To bypass PRE-PUSH check (not recommended):" $Colors.Red
    Write-ColorHost "  git push --no-verify ..." $Colors.Yellow
    Write-Host ""
    exit $ExitCode
} else {
    Write-Host ""
    Write-ColorHost "========================================" $Colors.Green
    Write-ColorHost "PRE-PUSH VALIDATION PASSED" $Colors.Green
    Write-ColorHost "========================================" $Colors.Green
    Write-Host ""
    Write-ColorHost "Safe to push!" $Colors.Green
    Write-Host ""
    exit 0
}
