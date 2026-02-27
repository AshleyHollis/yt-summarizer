#!/bin/bash
# =============================================================================
# Detect changed areas for CI workflow
# =============================================================================
# Used by: .github/workflows/ci.yml (detect-changes job, line 95)
# Purpose: Determine which areas of codebase changed to enable smart skipping
#
# Inputs:
#   - $MAIN_BRANCH: 'true' if main branch, 'false' if PR
#
# Outputs:
#   - changed_areas: Space-separated list (e.g., "services/api k8s")
#   - has_code_changes: 'true' if code changed (not just docs/CI), 'false' otherwise
#
# Execution:
#   MAIN BRANCH: All areas forced (full validation)
#     → "services/api services/workers services/shared apps/web k8s infra/terraform docker"
#   PR BRANCH (pull_request event): All areas forced (full validation to catch workflow edge cases)
#     → "services/api services/workers services/shared apps/web k8s infra/terraform docker"
#   PR BRANCH (push/other): Actual change detection via PowerShell script
#     → Calls: pwsh -File ./scripts/ci/detect-changes.ps1 -OutputFormat github-actions
#     → Outputs: Only changed areas
#
# RATIONALE: Always build/test for PRs to avoid edge cases where workflow changes
#            cause deployment issues but aren't caught by change detection.
#
# Exit: Always succeeds (no failures)
# =============================================================================

set -e  # Exit on error

main_branch="${MAIN_BRANCH:-${IS_MAIN_BRANCH:-false}}"
force_full="${FORCE_FULL:-false}"
event_name="${GITHUB_EVENT_NAME:-}"

# Always run full validation for main branch, forced full runs, or pull_request events
if [[ "$main_branch" == "true" || "$force_full" == "true" || "$event_name" == "pull_request" ]]; then
  # Force ALL areas to run full validation
  echo "changed_areas=services/api services/workers services/shared apps/web k8s infra/terraform docker" >> "$GITHUB_OUTPUT"
  echo "has_code_changes=true" >> "$GITHUB_OUTPUT"

  if [[ "$event_name" == "pull_request" ]]; then
    echo "✓ Pull request: All validation and build jobs will run (avoids workflow edge cases)"
  elif [[ "$force_full" == "true" && "$main_branch" != "true" ]]; then
    echo "✓ Forced full validation: All validation jobs will run"
  else
    echo "✓ Main branch: All validation jobs will run"
  fi
else
  # Other cases: Use actual change detection
  echo "✓ Running targeted change detection"
  cd "$GITHUB_WORKSPACE"
  pwsh -File ./scripts/ci/detect-changes.ps1 -OutputFormat github-actions
fi
