<#
.SYNOPSIS
Pull pre-commit.ci automatic fixes before pushing

.DESCRIPTION
This script handles the common issue where pre-commit.ci GitHub app
automatically commits fixes, causing your push to be blocked.

Pulls remote changes and rebases them on top of your commits.
#>

param(
    [switch]$Merge,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

# Check if we're in a git repo
$gitRepo = git rev-parse --git-dir 2>$null
if (-not $gitRepo) {
    Write-Error "Not in a git repository"
    exit 1
}

# Check if there's anything to push
$status = git status --porcelain
if ($status) {
    Write-Warning "You have uncommitted changes. Please commit or stash them first."
    Write-Host "  Use: git stash"
    Write-Host "  Then: git stash pop after pulling"
    exit 1
}

# Check if we're ahead of remote
$branch = git rev-parse --abbrev-ref HEAD

# Fetch remote changes
Write-Host "Fetching remote changes..." -ForegroundColor Cyan
git fetch origin

# Check if we have local commits not on remote
$localAhead = git rev-list --count "@{u}..@" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "No remote tracking branch for '$branch'. Skipping." -ForegroundColor Yellow
    exit 0
}

if ($localAhead -eq 0) {
    Write-Host "No local commits to push. Nothing to do." -ForegroundColor Green
    exit 0
}

Write-Host "You have $localAhead local commit(s) ahead of remote." -ForegroundColor Yellow

# Check if remote has commits we don't have
$remoteAhead = git rev-list --count "..@{u}" 2>$null
if ($LASTEXITCODE -eq 0 -and $remoteAhead -gt 0) {
    Write-Host "Remote has $remoteAhead commit(s) you don't have (likely from pre-commit.ci)." -ForegroundColor Yellow
    Write-Host ""

    # Show what they are
    Write-Host "Remote commits:" -ForegroundColor Cyan
    git log --oneline @{u}..HEAD 2>$null
    Write-Host ""

    if ($DryRun) {
        Write-Host "[DRY RUN] Would pull remote changes..." -ForegroundColor Yellow
        if ($Merge) {
            Write-Host "[DRY RUN] Command: git pull --no-rebase origin $branch"
        } else {
            Write-Host "[DRY RUN] Command: git pull --rebase origin $branch"
        }
        exit 0
    }

    # Pull the changes
    if ($Merge) {
        Write-Host "Pulling with merge..." -ForegroundColor Cyan
        git pull --no-rebase origin $branch
    } else {
        Write-Host "Pulling with rebase (recommended)..." -ForegroundColor Cyan
        git pull --rebase origin $branch

        # Check if rebase had conflicts
        $status = git status --porcelain
        if ($status -match '^[ADU]') {
            Write-Host "Rebase conflicts detected!" -ForegroundColor Red
            Write-Host "Please resolve conflicts manually and run:" -ForegroundColor Yellow
            Write-Host "  git add ." -ForegroundColor White
            Write-Host "  git rebase --continue" -ForegroundColor White
            exit 1
        }
    }

    Write-Host "Successfully pulled remote changes!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Now you can push with: git push" -ForegroundColor Green
} else {
    Write-Host "No remote changes. Safe to push." -ForegroundColor Green
}

exit 0
