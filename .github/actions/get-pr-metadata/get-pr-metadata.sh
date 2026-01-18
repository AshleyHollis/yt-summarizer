#!/bin/bash
# Purpose: Extracts PR number, head ref, and head SHA from events
# Inputs:
#   EVENT_NAME: GitHub event name (pull_request or workflow_dispatch)
#   PR_NUMBER_CONTEXT: PR number from pull_request context
#   PR_HEAD_REF_CONTEXT: PR head ref from pull_request context
#   PR_HEAD_SHA_CONTEXT: PR head SHA from pull_request context
#   PR_BASE_SHA_CONTEXT: PR base SHA from pull_request context
#   CURRENT_REF: Current ref name (for workflow_dispatch)
#   CURRENT_SHA: Current SHA (for workflow_dispatch)
# Outputs:
#   pr_number: PR number
#   pr_head_ref: PR head ref
#   pr_head_sha: PR head SHA
#   base_sha: Base SHA for comparison
# Logic:
#   1. Check EVENT_NAME to determine source
#   2. If pull_request: extract from context variables
#   3. If workflow_dispatch: use current ref/sha and manual PR number
#   4. For workflow_dispatch, base_sha defaults to origin/main

set -euo pipefail

EVENT_NAME="${EVENT_NAME:-}"

if [ "$EVENT_NAME" = "pull_request" ]; then
  echo "pr_number=${PR_NUMBER_CONTEXT}" >> $GITHUB_OUTPUT
  echo "pr_head_ref=${PR_HEAD_REF_CONTEXT}" >> $GITHUB_OUTPUT
  echo "pr_head_sha=${PR_HEAD_SHA_CONTEXT}" >> $GITHUB_OUTPUT
  echo "base_sha=${PR_BASE_SHA_CONTEXT}" >> $GITHUB_OUTPUT
elif [ "$EVENT_NAME" = "workflow_dispatch" ]; then
  PR_NUM="${PR_NUMBER_INPUT:-}"
  if [ -n "$PR_NUM" ]; then
    echo "pr_number=$PR_NUM" >> $GITHUB_OUTPUT
  else
    echo "pr_number=" >> $GITHUB_OUTPUT
  fi
  echo "pr_head_ref=${CURRENT_REF}" >> $GITHUB_OUTPUT
  echo "pr_head_sha=${CURRENT_SHA}" >> $GITHUB_OUTPUT
  echo "base_sha=origin/main" >> $GITHUB_OUTPUT
fi
