#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Detects which paths in the codebase have changed to enable conditional CI execution.

.DESCRIPTION
    Analyzes git changes and outputs a list of changed top-level directories/areas.
    Pipeline jobs then decide for themselves whether to run based on that data.
    This decouples change detection from pipeline logic, making it more maintainable.

    To add a new component/service:
    1. Add it to the $areaPatterns below
    2. Jobs can check: if: contains(needs.detect-changes.outputs.changed_areas, 'your/path')

.PARAMETER BaseSha
    Base commit SHA to compare against (defaults to main branch or HEAD~1)

.PARAMETER HeadSha
    Head commit SHA to compare (defaults to HEAD)

.PARAMETER OutputFormat
    Output format: github-actions (default), json, or text

.EXAMPLE
    .\detect-changes.ps1
    Outputs changed_areas for GitHub Actions

.EXAMPLE
    .\detect-changes.ps1 -OutputFormat json
    Outputs JSON with array of changed areas
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$BaseSha = "",

    [Parameter()]
    [string]$HeadSha = "HEAD",

    [Parameter()]
    [ValidateSet('github-actions', 'json', 'text')]
    [string]$OutputFormat = 'github-actions'
)

$ErrorActionPreference = "Stop"

# =============================================================================
# CHANGE DETECTION OVERRIDE - ALWAYS DEPLOY
# =============================================================================
# TEMPORARY: Change detection disabled to avoid deployment skipping issues
# All areas are marked as changed, forcing full deployment every time
# =============================================================================
$FORCE_ALL_CHANGES = $true

# =============================================================================
# Area Detection Patterns
# =============================================================================
# Define detectable areas that jobs can check against.
#
# ADDING A NEW AREA:
# 1. Add pattern here (e.g., 'services/new' = @('services/new/**'))
# 2. Jobs can immediately check: contains(changed_areas, 'services/new')
# 3. Add to validate-ci-results action if validation needed
#
# PATTERN SYNTAX:
# - **/ matches zero or more path segments
# - * matches anything except /
# - Multiple patterns per area (e.g., docker matches Dockerfiles everywhere)
#
# BEST PRACTICE: Use hierarchical names matching directory structure
# - Good: 'services/api', 'apps/web', 'infra/terraform'
# - Avoid: 'backend', 'frontend' (ambiguous)
# =============================================================================
$areaPatterns = @{
    'services/api'        = @('services/api/**')
    'services/workers'    = @('services/workers/**')
    'services/shared'     = @('services/shared/**')
    'services/aspire'     = @('services/aspire/**')
    'apps/web'            = @('apps/web/**')
    'k8s/argocd'          = @('k8s/argocd/**')
    'k8s'                 = @('k8s/**')
    'infra/terraform'     = @('infra/terraform/**')
    'docker'              = @('**/Dockerfile*', 'docker-compose*.yml', '.dockerignore')
    'docs'                = @('docs/**', 'specs/**', '*.md')
    'ci'                  = @('.github/**', 'scripts/ci/**')
}

# Determine base ref if not specified
if (-not $BaseSha) {
    if ($env:GITHUB_EVENT_NAME -eq 'pull_request' -and $env:GITHUB_BASE_REF) {
        $BaseSha = "origin/$env:GITHUB_BASE_REF"
    }
    elseif ($env:GITHUB_EVENT_NAME -eq 'push' -and $env:GITHUB_EVENT_BEFORE) {
        $BaseSha = $env:GITHUB_EVENT_BEFORE
    }
    else {
        # Default to main branch or previous commit
        $BaseSha = if (git rev-parse --verify origin/main 2>$null) { "origin/main" } else { "HEAD~1" }
    }
}

Write-Host "Comparing: $BaseSha...$HeadSha"

# Get changed files
try {
    $changedFiles = git diff --name-only "$BaseSha" "$HeadSha" 2>&1

    if ($LASTEXITCODE -ne 0) {
        Write-Warning "git diff failed: $changedFiles"
        Write-Host "Falling back to git show HEAD"
        $changedFiles = git show --name-only --pretty=format: HEAD 2>&1
    }

    $changedFiles = @($changedFiles | Where-Object { $_ -and $_.Trim() })
}
catch {
    Write-Warning "Failed to get changed files: $_"
    $changedFiles = @()
}

if ($changedFiles.Count -eq 0) {
    Write-Host "No changed files detected"
}
else {
    Write-Host "`nChanged files ($($changedFiles.Count)):"
    $changedFiles | Select-Object -First 20 | ForEach-Object { Write-Host "  $_" }
    if ($changedFiles.Count -gt 20) {
        Write-Host "  ... and $($changedFiles.Count - 20) more"
    }
}

# Match files to areas
$changedAreas = New-Object System.Collections.Generic.HashSet[string]

# OVERRIDE: If forced, mark all areas as changed
if ($FORCE_ALL_CHANGES) {
    Write-Host "`n⚠️  CHANGE DETECTION DISABLED - Forcing all areas as changed" -ForegroundColor Yellow
    foreach ($area in $areaPatterns.Keys) {
        [void]$changedAreas.Add($area)
    }
    $changedAreasArray = @($changedAreas | Sort-Object)
} else {
    # Original change detection logic
    function ConvertTo-RegexPattern {
        param([string]$GlobPattern)

        # Escape special regex chars except * and ?
        $pattern = [regex]::Escape($GlobPattern)

        # Convert glob wildcards to regex
        $pattern = $pattern -replace '\\\*\\\*/', '([^/]+/)*'  # **/ matches zero or more path segments
        $pattern = $pattern -replace '/\\\*\\\*', '(/.*)?'      # /** matches / followed by anything (optional)
        $pattern = $pattern -replace '\\\*\\\*', '.*'           # ** matches anything
        $pattern = $pattern -replace '\\\*', '[^/]*'            # * matches anything except /
        $pattern = $pattern -replace '\\\?', '.'                # ? matches single char

        return "^$pattern$"
    }

    foreach ($file in $changedFiles) {
        foreach ($area in $areaPatterns.Keys) {
            foreach ($pattern in $areaPatterns[$area]) {
                $regexPattern = ConvertTo-RegexPattern -GlobPattern $pattern

                if ($file -match $regexPattern) {
                    [void]$changedAreas.Add($area)
                    break
                }
            }
        }
    }

    # Convert to sorted array
    $changedAreasArray = @($changedAreas | Sort-Object)
}

Write-Host "`nDetected Areas ($($changedAreasArray.Count)):"
if ($changedAreasArray.Count -eq 0) {
    Write-Host "  (none - all changes in untracked paths)" -ForegroundColor Gray
}
else {
    foreach ($area in $changedAreasArray) {
        Write-Host "  + $area" -ForegroundColor Green
    }
}

# =============================================================================
# IMPORTANT: Output Strategy
# =============================================================================
# This script outputs:
#   1. changed_areas - space-separated list of changed areas
#   2. has_code_changes - boolean flag (excludes docs-only changes)
#   3. needs_image_build - whether changes require new Docker images
#   4. needs_deployment - whether any deployment is needed
#
# WHY NOT stage_* OUTPUTS?
# - Too brittle: every new job requires script changes
# - Harder to maintain: decision logic spread across script and workflows
# - Less flexible: can't easily create complex conditions in workflows
#
# BEST PRACTICE: Let jobs decide for themselves using contains() checks
# Example: if: contains(needs.detect-changes.outputs.changed_areas, 'apps/web')
#
# IMAGE BUILD vs DEPLOYMENT:
# - needs_image_build=true: Changes in services/api, services/workers, services/shared, apps/web, or docker
# - needs_deployment=true: Any changes that affect deployment (includes k8s-only changes)
# =============================================================================

# Determine if changes require image building
$imageAreas = @('services/api', 'services/workers', 'services/shared', 'apps/web', 'docker')
$needsImageBuild = $false
foreach ($area in $imageAreas) {
    if ($changedAreasArray -contains $area) {
        $needsImageBuild = $true
        break
    }
}

# Determine if changes require deployment
$deploymentAreas = @('services/api', 'services/workers', 'services/shared', 'apps/web', 'docker', 'k8s/argocd', 'k8s', 'infra/terraform')
$needsDeployment = $false
foreach ($area in $deploymentAreas) {
    if ($changedAreasArray -contains $area) {
        $needsDeployment = $true
        break
    }
}

# Output in requested format
switch ($OutputFormat) {
    'github-actions' {
        # Space-separated string for easy contains() checks in workflow conditions
        $areasString = $changedAreasArray -join ' '

        if ($env:GITHUB_OUTPUT) {
            Add-Content -Path $env:GITHUB_OUTPUT -Value "changed_areas=$areasString"
        }
        else {
            Write-Host "::set-output name=changed_areas::$areasString"
        }

        Write-Host "`nGitHub Actions Output:"
        Write-Host "  changed_areas=$areasString"

        # Convenience flag: has_code_changes (excludes docs-only changes)
        $hasCodeChanges = ($changedAreasArray | Where-Object { $_ -ne 'docs' }).Count -gt 0

        if ($env:GITHUB_OUTPUT) {
            Add-Content -Path $env:GITHUB_OUTPUT -Value "has_code_changes=$($hasCodeChanges.ToString().ToLower())"
        }
        else {
            Write-Host "::set-output name=has_code_changes::$($hasCodeChanges.ToString().ToLower())"
        }

        Write-Host "  has_code_changes=$($hasCodeChanges.ToString().ToLower())"

        # Image build and deployment flags
        if ($env:GITHUB_OUTPUT) {
            Add-Content -Path $env:GITHUB_OUTPUT -Value "needs_image_build=$($needsImageBuild.ToString().ToLower())"
            Add-Content -Path $env:GITHUB_OUTPUT -Value "needs_deployment=$($needsDeployment.ToString().ToLower())"
        }
        else {
            Write-Host "::set-output name=needs_image_build::$($needsImageBuild.ToString().ToLower())"
            Write-Host "::set-output name=needs_deployment::$($needsDeployment.ToString().ToLower())"
        }

        Write-Host "  needs_image_build=$($needsImageBuild.ToString().ToLower())"
        Write-Host "  needs_deployment=$($needsDeployment.ToString().ToLower())"
    }

    'json' {
        $output = @{
            changed_areas = $changedAreasArray
            has_code_changes = ($changedAreasArray | Where-Object { $_ -ne 'docs' }).Count -gt 0
            needs_image_build = $needsImageBuild
            needs_deployment = $needsDeployment
            total_files = $changedFiles.Count
        }

        $output | ConvertTo-Json -Depth 10
    }

    'text' {
        Write-Host "`nSummary:"
        Write-Host "  Changed files: $($changedFiles.Count)"
        Write-Host "  Changed areas: $($changedAreasArray -join ', ')"

        $hasCodeChanges = ($changedAreasArray | Where-Object { $_ -ne 'docs' }).Count -gt 0
        Write-Host "  Has code changes: $hasCodeChanges"
        Write-Host "  Needs image build: $needsImageBuild"
        Write-Host "  Needs deployment: $needsDeployment"
    }
}
