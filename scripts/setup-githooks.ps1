#!/usr/bin/env pwsh
# Git Hooks Setup Script
# Copies hooks from githooks/ directory to .git/hooks/
# Makes hooks available to git automatically

param(
    [string]$HooksDir = "githooks",
    [string]$GitHooksDir = ".git/hooks"
)

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "GIT HOOKS SETUP" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Get repository root
$RepoRoot = git rev-parse --show-toplevel 2>$null
if (-not $RepoRoot) {
    Write-Error "ERROR: Not in a Git repository"
    exit 1
}

Write-Host "Repository root: $RepoRoot" -ForegroundColor Gray
Write-Host ""

# Check if githooks directory exists
$HooksPath = Join-Path $RepoRoot $HooksDir
if (-not (Test-Path $HooksPath)) {
    Write-Error "ERROR: githooks directory not found at $HooksPath"
    exit 1
}

# Check if .git/hooks directory exists
$GitHooksPath = Join-Path $RepoRoot $GitHooksDir
if (-not (Test-Path $GitHooksPath)) {
    Write-Error "ERROR: .git/hooks directory not found at $GitHooksPath"
    exit 1
}

Write-Host "Source hooks: $HooksPath" -ForegroundColor Gray
Write-Host "Target hooks: $GitHooksPath" -ForegroundColor Gray
Write-Host ""

# List of hooks to install
$hooksToInstall = @("pre-commit", "pre-push")

# Install each hook
foreach ($hook in $hooksToInstall) {
    $sourceHook = Join-Path $HooksPath $hook
    $targetHook = Join-Path $GitHooksPath $hook

    if (-not (Test-Path $sourceHook)) {
        Write-Warning "Hook not found: $sourceHook (skipping)"
        continue
    }

    Write-Host "Installing $hook..." -ForegroundColor Cyan

    # Copy hook
    Copy-Item -Path $sourceHook -Destination $targetHook -Force

    # Make executable (Unix line endings)
    # On Windows, Git handles line endings automatically
    $hookContent = Get-Content $targetHook -Raw
    $hookContent = $hookContent -replace "`r`n", "`n"
    Set-Content -Path $targetHook -Value $hookContent -NoNewline

    Write-Host "  ✓ Copied $hook to .git/hooks/$hook" -ForegroundColor Green
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "GIT HOOKS SETUP COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Installed hooks:" -ForegroundColor Cyan
Write-Host "  - pre-commit" -ForegroundColor White
Write-Host "  - pre-push" -ForegroundColor White
Write-Host ""
Write-Host "These hooks will automatically:" -ForegroundColor Cyan
Write-Host "  - Run pre-commit on every commit (blocks bad commits)" -ForegroundColor White
Write-Host "  - Run pre-commit on every push (blocks bad pushes)" -ForegroundColor White
Write-Host "  - Auto-fix issues on commit (not on push)" -ForegroundColor White
Write-Host ""
Write-Host "To bypass hooks (not recommended):" -ForegroundColor Yellow
Write-Host "  - git commit --no-verify" -ForegroundColor White
Write-Host "  - git push --no-verify" -ForegroundColor White
Write-Host ""
Write-Host "For more information, see:" -ForegroundColor Cyan
Write-Host '  githooks/README.md' -ForegroundColor White

exit 0
