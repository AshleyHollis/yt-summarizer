#!/bin/bash
# =============================================================================
# Emit PR Metadata
# =============================================================================
# PURPOSE:
#   Extract and emit PR metadata for workflow use
#
# INPUTS:
#   None (reads from GitHub context)
#
# OUTPUTS (via $GITHUB_OUTPUT):
#   pr_number       Pull request number
#   pr_head_ref     PR head branch reference
#   pr_head_sha     PR head commit SHA
#
# LOGIC:
#   1. Extract PR number from pull_request or workflow_run event
#   2. Extract PR head ref from pull_request or workflow_run event
#   3. Extract PR head SHA from pull_request or workflow_run event
#   4. Output all values via GITHUB_OUTPUT
#
# =============================================================================
set -euo pipefail

# These values come from GitHub Actions context - using placeholder syntax
# that gets replaced by the calling step's environment variables
{
  echo "pr_number=${PR_NUMBER}"
  echo "pr_head_ref=${PR_HEAD_REF}"
  echo "pr_head_sha=${PR_HEAD_SHA}"
} >> "$GITHUB_OUTPUT"
