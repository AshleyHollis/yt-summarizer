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
#   PR BRANCH: Actual change detection via PowerShell script
#     → Calls: pwsh -File ./scripts/ci/detect-changes.ps1 -OutputFormat github-actions
#     → Outputs: Only changed areas
#
# Exit: Always succeeds (no failures)
# =============================================================================

set -e  # Exit on error

if [[ "$MAIN_BRANCH" == "true" ]]; then
  # Main branch: Force ALL areas to run full validation
  echo "changed_areas=services/api services/workers services/shared apps/web k8s infra/terraform docker" >> $GITHUB_OUTPUT
  echo "has_code_changes=true" >> $GITHUB_OUTPUT
  echo "✓ Main branch: All validation jobs will run"
else
  # PR branch: Use actual change detection
  echo "✓ PR branch: Running change detection"
  # Run the actual change detection action
  cd "$GITHUB_WORKSPACE"
  pwsh -File ./scripts/ci/detect-changes.ps1 -OutputFormat github-actions
fi
