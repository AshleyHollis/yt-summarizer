#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Detects which components changed in a git commit or PR

.DESCRIPTION
    Analyzes git diff to determine which parts of the codebase changed.
    Outputs JSON indicating which pipeline stages should run.

.PARAMETER BaseSha
    Base commit SHA to compare against (defaults to HEAD~1)

.PARAMETER HeadSha
    Head commit SHA to compare (defaults to HEAD)

.PARAMETER PrNumber
    PR number to analyze (will fetch PR files from GitHub API)

.PARAMETER OutputFormat
    Output format: json, github-actions, or text (default: github-actions)

.EXAMPLE
    ./detect-changes.ps1 -BaseSha main -HeadSha HEAD

.EXAMPLE
    ./detect-changes.ps1 -PrNumber 123 -OutputFormat json
#>

param(
    [string]$BaseSha = "HEAD~1",
    [string]$HeadSha = "HEAD",
    [int]$PrNumber = 0,
    [ValidateSet("json", "github-actions", "text")]
    [string]$OutputFormat = "github-actions"
)

$ErrorActionPreference = "Stop"

# Initialize change detection results
$changes = @{
    api = $false
    workers = $false
    shared = $false
    frontend = $false
    kubernetes = $false
    terraform = $false
    docker = $false
    docs = $false
    ci = $false
    tests_only = $false
    code_changes = $false
}

# Path patterns for each component
$patterns = @{
    api = @("services/api/**", "!services/api/tests/**")
    workers = @("services/workers/**", "!services/workers/tests/**")
    shared = @("services/shared/**", "!services/shared/tests/**")
    frontend = @("apps/web/**", "!apps/web/e2e/**", "!apps/web/playwright-report/**")
    kubernetes = @("k8s/**", "!k8s/overlays/previews/**")
    terraform = @("infra/terraform/**")
    docker = @("**/*.Dockerfile", "**/Dockerfile", "docker-compose*.yml")
    docs = @("docs/**", "*.md", "specs/**")
    ci = @(".github/**")
    api_tests = @("services/api/tests/**")
    workers_tests = @("services/workers/tests/**")
    shared_tests = @("services/shared/tests/**")
    frontend_tests = @("apps/web/e2e/**", "apps/web/**/*.test.*", "apps/web/**/*.spec.*")
}

function Get-ChangedFiles {
    param(
        [string]$Base,
        [string]$Head,
        [int]$PR
    )

    if ($PR -gt 0) {
        Write-Host "Fetching changed files from PR #$PR via GitHub API..."

        $repo = $env:GITHUB_REPOSITORY
        if (-not $repo) {
            # Try to get from git remote
            $remoteUrl = git remote get-url origin 2>$null
            if ($remoteUrl -match "github\.com[:/]([^/]+/[^/\.]+)") {
                $repo = $matches[1]
            } else {
                throw "Could not determine repository. Set GITHUB_REPOSITORY environment variable."
            }
        }

        $token = $env:GITHUB_TOKEN ?? $env:GH_TOKEN
        $headers = @{}
        if ($token) {
            $headers["Authorization"] = "Bearer $token"
        }

        $apiUrl = "https://api.github.com/repos/$repo/pulls/$PR/files?per_page=100"

        try {
            $response = Invoke-RestMethod -Uri $apiUrl -Headers $headers -Method Get
            return $response | ForEach-Object { $_.filename }
        } catch {
            Write-Warning "Failed to fetch PR files via API: $_"
            Write-Host "Falling back to git diff..."
            # Fall through to git diff
        }
    }

    # Use git diff
    Write-Host "Analyzing changes between $Base and $Head..."
    $files = git diff --name-only "$Base" "$Head" 2>$null

    if ($LASTEXITCODE -ne 0) {
        Write-Warning "git diff failed, using git show for HEAD"
        $files = git show --name-only --pretty=format: HEAD
    }

    return $files | Where-Object { $_ }
}

function Test-PathMatch {
    param(
        [string]$Path,
        [string[]]$Patterns
    )

    foreach ($pattern in $Patterns) {
        $isNegative = $pattern.StartsWith("!")
        $cleanPattern = if ($isNegative) { $pattern.Substring(1) } else { $pattern }

        # Convert glob pattern to regex
        $regex = $cleanPattern `
            -replace '\*\*/', '.*' `
            -replace '/\*\*', '/.*' `
            -replace '\*', '[^/]*' `
            -replace '\.', '\.'

        $regex = "^$regex$"

        if ($Path -match $regex) {
            return -not $isNegative
        }
    }

    return $false
}

# Get changed files
$changedFiles = Get-ChangedFiles -Base $BaseSha -Head $HeadSha -PR $PrNumber

if (-not $changedFiles) {
    Write-Host "No changes detected"
} else {
    Write-Host "Changed files:"
    $changedFiles | ForEach-Object { Write-Host "  $_" }

    # Check each file against patterns
    foreach ($file in $changedFiles) {
        # Check code components
        if (Test-PathMatch $file $patterns.api) {
            $changes.api = $true
            $changes.code_changes = $true
        }
        if (Test-PathMatch $file $patterns.workers) {
            $changes.workers = $true
            $changes.code_changes = $true
        }
        if (Test-PathMatch $file $patterns.shared) {
            $changes.shared = $true
            $changes.code_changes = $true
        }
        if (Test-PathMatch $file $patterns.frontend) {
            $changes.frontend = $true
            $changes.code_changes = $true
        }

        # Check infrastructure
        if (Test-PathMatch $file $patterns.kubernetes) {
            $changes.kubernetes = $true
            $changes.code_changes = $true
        }
        if (Test-PathMatch $file $patterns.terraform) {
            $changes.terraform = $true
            $changes.code_changes = $true
        }
        if (Test-PathMatch $file $patterns.docker) {
            $changes.docker = $true
            $changes.code_changes = $true
        }

        # Check docs and CI
        if (Test-PathMatch $file $patterns.docs) {
            $changes.docs = $true
        }
        if (Test-PathMatch $file $patterns.ci) {
            $changes.ci = $true
            $changes.code_changes = $true
        }
    }

    # Determine if only tests changed
    $testFiles = $changedFiles | Where-Object {
        (Test-PathMatch $_ $patterns.api_tests) -or
        (Test-PathMatch $_ $patterns.workers_tests) -or
        (Test-PathMatch $_ $patterns.shared_tests) -or
        (Test-PathMatch $_ $patterns.frontend_tests)
    }

    $changes.tests_only = ($testFiles.Count -eq $changedFiles.Count) -and ($changedFiles.Count -gt 0)
}

# Determine pipeline stages to run
$stages = @{
    lint_python = $changes.api -or $changes.workers -or $changes.shared
    lint_frontend = $changes.frontend
    test_api = $changes.api -or $changes.shared
    test_workers = $changes.workers -or $changes.shared
    test_shared = $changes.shared
    test_frontend = $changes.frontend
    build_images = ($changes.api -or $changes.workers -or $changes.docker) -and -not $changes.tests_only
    validate_kubernetes = $changes.kubernetes
    validate_terraform = $changes.terraform
    deploy_preview = $changes.code_changes -and -not $changes.tests_only
    deploy_prod = $changes.code_changes -and -not $changes.tests_only
    run_e2e = $changes.frontend -or $changes.api
}

# Add summary
$summary = @{
    has_code_changes = $changes.code_changes
    has_docs_only = $changes.docs -and -not $changes.code_changes
    has_tests_only = $changes.tests_only
    requires_build = $stages.build_images
    requires_deployment = $stages.deploy_preview -or $stages.deploy_prod
}

# Output results
switch ($OutputFormat) {
    "json" {
        $output = @{
            changes = $changes
            stages = $stages
            summary = $summary
        }
        $output | ConvertTo-Json -Depth 3
    }

    "github-actions" {
        Write-Host "Setting GitHub Actions outputs..."
        foreach ($key in $changes.Keys) {
            Write-Output "$key=$($changes[$key].ToString().ToLower())" >> $env:GITHUB_OUTPUT
        }
        foreach ($key in $stages.Keys) {
            Write-Output "stage_$key=$($stages[$key].ToString().ToLower())" >> $env:GITHUB_OUTPUT
        }
        foreach ($key in $summary.Keys) {
            Write-Output "$key=$($summary[$key].ToString().ToLower())" >> $env:GITHUB_OUTPUT
        }

        Write-Host ""
        Write-Host "Changes detected:"
        $changes.GetEnumerator() | Where-Object { $_.Value } | ForEach-Object {
            Write-Host "  ✓ $($_.Key)"
        }

        Write-Host ""
        Write-Host "Pipeline stages to run:"
        $stages.GetEnumerator() | Where-Object { $_.Value } | ForEach-Object {
            Write-Host "  ✓ $($_.Key)"
        }
    }

    "text" {
        Write-Host ""
        Write-Host "=== Change Detection Results ==="
        Write-Host ""
        Write-Host "Components Changed:"
        $changes.GetEnumerator() | Sort-Object Key | ForEach-Object {
            $status = if ($_.Value) { "✓" } else { "○" }
            Write-Host "  $status $($_.Key)"
        }

        Write-Host ""
        Write-Host "Pipeline Stages:"
        $stages.GetEnumerator() | Sort-Object Key | ForEach-Object {
            $status = if ($_.Value) { "RUN" } else { "SKIP" }
            Write-Host "  [$status] $($_.Key)"
        }

        Write-Host ""
        Write-Host "Summary:"
        Write-Host "  Code changes: $($summary.has_code_changes)"
        Write-Host "  Docs only: $($summary.has_docs_only)"
        Write-Host "  Tests only: $($summary.has_tests_only)"
        Write-Host "  Requires build: $($summary.requires_build)"
        Write-Host "  Requires deployment: $($summary.requires_deployment)"
    }
}
