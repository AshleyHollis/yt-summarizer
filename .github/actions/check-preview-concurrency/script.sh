#!/bin/bash

################################################################################
# Action: check-preview-concurrency / script.sh
#
# Purpose: Check if preview deployment is allowed based on concurrent preview limit.
#          Counts open PRs and determines if a new preview can be deployed.
#
# Inputs (Environment Variables):
#   GH_TOKEN      - GitHub token for API access
#   MAX_PREVIEWS  - Maximum number of concurrent previews allowed (default: 10)
#   REPOSITORY    - GitHub repository (owner/repo format)
#
# Outputs (via $GITHUB_OUTPUT):
#   can_deploy    - "true" if preview slot available, "false" if limit reached
#
# Logic Flow:
#   1. Count all open PRs using GitHub API (each gets a preview)
#   2. Compare open PR count with max-previews limit
#   3. Allow deployment if count <= max (current PR already in open count)
#   4. Output warning if limit reached
#
################################################################################

# Count open PRs (each gets a preview via ApplicationSet PR Generator)
OPEN_PRS=$(gh api repos/$GITHUB_REPOSITORY/pulls --jq 'length')

echo "Open PRs: ${OPEN_PRS}"
echo "Max previews: $MAX_PREVIEWS"

# This PR is already counted in open PRs, so we compare with <=
if [ "$OPEN_PRS" -le "$MAX_PREVIEWS" ]; then
  echo "Preview slot available (${OPEN_PRS}/$MAX_PREVIEWS)"
  echo "can_deploy=true" >> $GITHUB_OUTPUT
else
  echo "::warning::Preview limit reached (${OPEN_PRS}/$MAX_PREVIEWS)"
  echo "::warning::This PR will not get a preview environment"
  echo "can_deploy=false" >> $GITHUB_OUTPUT
fi
