#!/bin/bash
# =============================================================================
# Create Infrastructure Summary
# =============================================================================
# PURPOSE:
#   Creates a GitHub Actions step summary for infrastructure deployments
#
# INPUTS (via environment variables):
#   TERRAFORM_CHANGED       Whether terraform files changed (true/false)
#   TERRAFORM_RESULT        Result of terraform job
#   GITHUB_EVENT_NAME       Name of the GitHub event
#
# OUTPUTS:
#   Writes to $GITHUB_STEP_SUMMARY with markdown summary
#
# LOGIC:
#   1. Write header to summary
#   2. If no terraform changes, display skipped message
#   3. If changes, show job status table and add context about PR comments
#
# =============================================================================
set -euo pipefail

{
  echo "## 🏗️ Infrastructure Deployment Summary"
  echo ""

  if [ "${TERRAFORM_CHANGED}" != "true" ]; then
    echo "⏭️ **Skipped** - No terraform changes in this commit"
  else
    echo "### Pipeline Status"
    echo ""
    echo "| Job | Status |"
    echo "|-----|--------|"
    echo "| Terraform | ${TERRAFORM_RESULT} |"
    echo ""
    echo "*Note: Detailed terraform plan results are available in the step " \
      "summary above*"
    if [ "${GITHUB_EVENT_NAME}" == "pull_request" ]; then
      echo ""
      echo "*PR comments with full plan details are also posted on the " \
        "pull request*"
    fi
  fi
} >> "$GITHUB_STEP_SUMMARY"
