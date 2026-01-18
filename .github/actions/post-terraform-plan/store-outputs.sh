#!/bin/bash
# =============================================================================
# Store Terraform Plan Outputs
# =============================================================================
# PURPOSE:
#   Stores the terraform plan comment ID in GitHub Actions output
#
# INPUTS:
#   Via step outputs from previous steps
#   - steps.post-pr.outputs.comment-id: Comment ID from PR post step
#
# OUTPUTS (via $GITHUB_OUTPUT):
#   comment-id: ID of the created or updated PR comment
#
# LOGIC:
#   1. Check if comment-id output exists from post-pr step
#   2. If exists, store it in GITHUB_OUTPUT for downstream consumption
#
# =============================================================================

set -euo pipefail

# Store comment-id if available (from PR post step)
COMMENT_ID="${POST_PR_COMMENT_ID:-}"
if [ -n "$COMMENT_ID" ]; then
  echo "comment-id=${COMMENT_ID}" >> "$GITHUB_OUTPUT"
  echo "✅ Stored comment-id: ${COMMENT_ID}"
else
  echo "ℹ️  No comment-id to store (skipped PR comment or not pull_request event)"
fi
