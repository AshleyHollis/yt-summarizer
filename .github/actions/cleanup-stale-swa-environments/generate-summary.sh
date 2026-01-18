#!/bin/bash

# =============================================================================
# Generate SWA Cleanup Summary - Create GitHub Step Summary
# =============================================================================
#
# PURPOSE:
#   Generates a markdown summary of the SWA environment cleanup operation
#   and writes it to the GitHub Step Summary for workflow visibility.
#
# INPUTS (via environment variables):
#   DELETED_COUNT - Number of environments deleted (default: '0')
#   STALE_COUNT - Number of stale environments found (default: '0')
#   STALE_PRS - Comma-separated PR numbers or 'none'
#   DRY_RUN - Whether operation was a dry run ('true' or 'false')
#   MIN_AGE_HOURS - Minimum age threshold in hours (from inputs)
#
# OUTPUTS:
#   Writes to $GITHUB_STEP_SUMMARY for GitHub workflow display
#
# LOGIC:
#   1. Determine operation mode (Dry Run vs Active Deletion)
#   2. Format stale PR list (either PR numbers or "no stale environments")
#   3. Create markdown summary with key metrics
#   4. Append to GitHub Step Summary for visibility in workflow logs
#
# =============================================================================

set -euo pipefail

# Input validation with defaults
DELETED_COUNT="${DELETED_COUNT:-0}"
STALE_COUNT="${STALE_COUNT:-0}"
STALE_PRS="${STALE_PRS:-none}"
DRY_RUN="${DRY_RUN:-false}"
MIN_AGE_HOURS="${MIN_AGE_HOURS:-1}"

# Determine mode label
if [ "$DRY_RUN" == "true" ]; then
  MODE="🔍 Dry Run"
else
  MODE="🗑️ Active Deletion"
fi

# Determine PR list display
if [ "$STALE_COUNT" != "0" ] && [ "$STALE_PRS" != "none" ]; then
  PR_DISPLAY="**PR Numbers:** $STALE_PRS"
else
  PR_DISPLAY="_No stale environments detected_"
fi

# Build and append summary
cat >> "$GITHUB_STEP_SUMMARY" << EOF
## 🗑️ SWA Environment Cleanup Report

**Mode:** $MODE
**Stale Environments Found:** $STALE_COUNT
**Environments Processed:** $DELETED_COUNT

$PR_DISPLAY

> **Note:** Stale environments are from PRs closed more than $MIN_AGE_HOURS hour(s)
> ago.
EOF

echo "✅ Cleanup summary generated successfully"
