#!/usr/bin/env pwsh
# Validates local git hook setup for yt-summarizer.

$ErrorActionPreference = "Stop"

function Write-Status {
    param(
        [string]$Message,
        [ConsoleColor]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

$repoRoot = git rev-parse --show-toplevel 2>$null
if (-not $repoRoot) {
    Write-Status "ERROR: Not inside a git repository." Red
    exit 1
}

Set-Location $repoRoot

Write-Host ""
Write-Status "========================================" Cyan
Write-Status "GIT HOOKS HEALTH CHECK" Cyan
Write-Status "========================================" Cyan
Write-Host ""

$hooksPath = git config --get core.hooksPath
if (-not $hooksPath) {
    Write-Status "ERROR: core.hooksPath is not set." Red
    Write-Status "Fix: git config core.hooksPath githooks" Yellow
    exit 1
}

if ($hooksPath -ne "githooks") {
    Write-Status "ERROR: core.hooksPath is '$hooksPath' (expected 'githooks')." Red
    Write-Status "Fix: git config core.hooksPath githooks" Yellow
    exit 1
}

$hookFiles = @(
    "githooks/pre-commit.ps1",
    "githooks/pre-commit.bat",
    "githooks/pre-push.ps1",
    "githooks/pre-push.bat"
)

$missingHooks = $hookFiles | Where-Object { -not (Test-Path $_) }
if ($missingHooks.Count -gt 0) {
    Write-Status "ERROR: Missing hook files:" Red
    $missingHooks | ForEach-Object { Write-Status " - $_" Red }
    exit 1
}

$preCommit = Get-Command pre-commit -ErrorAction SilentlyContinue
if (-not $preCommit) {
    Write-Status "ERROR: pre-commit not found on PATH." Red
    Write-Status "Fix: pip install pre-commit" Yellow
    exit 1
}

Write-Status "OK: core.hooksPath is set to githooks." Green
Write-Status "OK: Hook files are present." Green
Write-Status "OK: pre-commit is installed." Green
Write-Host ""
Write-Status "Hook checks passed." Green
