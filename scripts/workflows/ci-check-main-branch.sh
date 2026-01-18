#!/bin/bash
# =============================================================================
# Check if current ref is main branch
# =============================================================================
# Used by: .github/workflows/ci.yml (detect-changes job, line 83)
# Purpose: Determine if workflow is running on main branch for full validation
#
# Outputs:
#   - is_main_branch: 'true' if main branch, 'false' otherwise
#
# Main branch detection rules:
#   - github.ref == refs/heads/main
#   - github.event_name == 'push' AND github.ref_name == 'main'
#
# Exit: Always succeeds (no failures)
# =============================================================================

set -e  # Exit on error

# Check if this is the main branch
if [[ "${{ github.ref }}" == "refs/heads/main" ]] || [[ "${{ github.event_name }}" == "push" && "${{ github.ref_name }}" == "main" ]]; then
  echo "is_main_branch=true" >> $GITHUB_OUTPUT
  echo "✓ Main branch detected - FULL validation mode"
else
  echo "is_main_branch=false" >> $GITHUB_OUTPUT
  echo "✓ PR/branch detected - Smart change detection mode"
fi
