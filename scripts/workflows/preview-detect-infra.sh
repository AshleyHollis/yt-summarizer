#!/bin/bash
# =============================================================================
# Detect infrastructure changes in preview workflow
# =============================================================================
# Used by: .github/workflows/preview.yml (detect-changes job, lines 197-209)
# Purpose: Check if infra/terraform directory changed (gates terraform job)
#
# Inputs:
#   - BASE_SHA: Base branch commit SHA
#   - HEAD_SHA: PR head commit SHA
#
# Outputs:
#   - infra_changed: 'true' if infra/terraform files changed, 'false' otherwise
#
# Exit: Always succeeds
# =============================================================================

set -e  # Exit on error

BASE_SHA="${1}"
HEAD_SHA="${2}"
INFRA_CHANGED=false

if git diff --name-only "$BASE_SHA" "$HEAD_SHA" | grep -q '^infra/terraform/'; then
  INFRA_CHANGED=true
fi

echo "infra_changed=$INFRA_CHANGED" >> "$GITHUB_OUTPUT"
