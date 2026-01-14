#!/usr/bin/env pwsh
# Git Hooks Setup Script
# Copies hooks from githooks/ directory to .git/hooks/
# Makes hooks available to git automatically
# Hooks are PowerShell scripts for cross-platform compatibility

param(
    [string]$HooksDir = "githooks",
    [string]$GitHooksDir = ".git/hooks"
    )

$ErrorActionPreference = "Stop"

# Detect OS - compatible with PowerShell 5.1+
$IsWindowsOS = if ($PSVersionTable.PSVersion.Major -lt 6) {
    $env:OS -eq "Windows_NT"
} else {
    $IsWindows
}

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

# List of hooks to install (without extensions)
$hooksToInstall = @("pre-commit", "pre-push")

# Install each hook
foreach ($hook in $hooksToInstall) {
    $sourcePs1 = Join-Path $HooksPath "$hook.ps1"
    $sourceBat = Join-Path $HooksPath "$hook.bat"
    $targetHook = Join-Path $GitHooksPath $hook

    if (-not (Test-Path $sourcePs1)) {
        Write-Warning "Hook not found: $sourcePs1 (skipping)"
        continue
    }

    Write-Host "Installing $hook..." -ForegroundColor Cyan

    # On Windows, use .bat wrapper for cross-platform compatibility
    # On Unix-like systems, use .ps1 (Unix line ending + shebang)
    if ($IsWindowsOS) {
        if (-not (Test-Path $sourceBat)) {
            Write-Warning "Batch wrapper not found: $sourceBat (skipping)"
            continue
        }

        # Copy batch wrapper
        Copy-Item -Path $sourceBat -Destination "$targetHook.bat" -Force

        # Copy PowerShell script alongside it
        Copy-Item -Path $sourcePs1 -Destination "$GitHooksPath\$hook.ps1" -Force

        Write-Host "  Installed $hook.bat + $hook.ps1" -ForegroundColor Green
    } else {
        # Unix-like: use .ps1 with shebang and Unix line endings
        $hookContent = Get-Content $sourcePs1 -Raw

        # Normalize line endings to LF (Unix-style) for Git compatibility
        $hookContent = $hookContent -replace "`r`n", "`n"

        # Write hook to target
        Set-Content -Path $targetHook -Value $hookContent -NoNewline

        # Make executable
        chmod +x $targetHook

        Write-Host "  Installed $hook (PowerShell, executable)" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "GIT HOOKS SETUP COMPLETE" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Installed hooks (PowerShell, cross-platform):" -ForegroundColor Cyan
Write-Host "  - pre-commit" -ForegroundColor White
Write-Host "  - pre-push" -ForegroundColor White
Write-Host ""
Write-Host "These hooks will automatically:" -ForegroundColor Cyan
Write-Host "  - Run pre-commit on every commit (blocks bad commits)" -ForegroundColor White
Write-Host "  - Run pre-commit on every push (blocks bad pushes)" -ForegroundColor White
Write-Host "  - Auto-fix issues on commit (not on push)" -ForegroundColor White
Write-Host ""
Write-Host "Hooks work on:" -ForegroundColor Cyan
Write-Host "  - Windows (PowerShell 5.1+ or pwsh) via .bat wrapper" -ForegroundColor White
Write-Host "  - Linux/macOS (PowerShell Core/pwsh) via .ps1 + shebang" -ForegroundColor White
Write-Host ""
Write-Host "To bypass hooks (not recommended):" -ForegroundColor Yellow
Write-Host "  - git commit --no-verify" -ForegroundColor White
Write-Host "  - git push --no-verify" -ForegroundColor White
Write-Host ""
Write-Host "For more information, see:" -ForegroundColor Cyan
Write-Host "  githooks/README.md" -ForegroundColor White

exit 0
