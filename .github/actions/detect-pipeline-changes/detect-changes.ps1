# =============================================================================
# Detect Pipeline Changes - Smart Change Detection Script
# =============================================================================
# PURPOSE:
#   Detects which parts of the codebase have changed to optimize pipeline
#   execution. This is a wrapper around scripts/ci/detect-changes.ps1 that
#   normalizes inputs for GitHub Actions composite action invocation.
#
# INPUTS (via environment variables):
#   BASE_SHA_INPUT      Base commit SHA (optional, auto-detected if empty)
#   HEAD_SHA_INPUT      Head commit SHA (defaults to HEAD)
#
# OUTPUTS (via $GITHUB_OUTPUT):
#   changed_areas       Space-separated list of changed paths
#   has_code_changes    Boolean flag indicating if code changes exist
#
# LOGIC:
#   1. Receive inputs via environment variables
#   2. Build parameters hashtable for detection script
#   3. Call scripts/ci/detect-changes.ps1 with appropriate params
#   4. Outputs are automatically written to $GITHUB_OUTPUT
#
# =============================================================================

param(
    [string]$OutputFormat = 'github-actions'
)

$params = @{ OutputFormat = $OutputFormat }

if ($env:BASE_SHA_INPUT) {
    $params['BaseSha'] = $env:BASE_SHA_INPUT
}

if ($env:HEAD_SHA_INPUT) {
    $params['HeadSha'] = $env:HEAD_SHA_INPUT
}

# Call the main detection script
& .\scripts\ci\detect-changes.ps1 @params
