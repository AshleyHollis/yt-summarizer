#!/bin/bash
# =============================================================================
# Finalize deployment flags for preview workflow
# =============================================================================
# Used by: .github/workflows/preview.yml (detect-changes job, lines 182-195)
# Purpose: Adjust needs_image_build and needs_deployment flags based on
#          workflow_dispatch inputs
#
# Inputs (via GitHub Actions step context):
#   - needs_image_build: Initial value from detect-pr-code-changes action
#   - needs_deployment: Initial value from detect-pr-code-changes action
#   - github.event_name: 'pull_request' or 'workflow_dispatch'
#   - inputs.run_preview: boolean from workflow_dispatch (if applicable)
#
# Outputs:
#   - needs_image_build: Final value (may be overridden to false)
#   - needs_deployment: Final value (may be overridden to false)
#
# Logic:
#   If workflow_dispatch AND inputs.run_preview != 'true':
#     Set both flags to false (skip preview deployment)
#   Otherwise:
#     Pass through the values from detect-pr-code-changes (respect upstream detection)
#
# Exit: Always succeeds
# =============================================================================

set -e  # Exit on error

needs_image_build="${INITIAL_NEEDS_IMAGE_BUILD}"
needs_deployment="${INITIAL_NEEDS_DEPLOYMENT}"

# workflow_dispatch can explicitly disable preview deployment
if [[ "${EVENT_NAME}" == "workflow_dispatch" ]] && [[ "${RUN_PREVIEW}" != "true" ]]; then
  needs_image_build=false
  needs_deployment=false
fi

# Otherwise, respect the change detection from detect-pr-code-changes
# Don't force both flags to true - let the upstream detection determine them

echo "needs_image_build=$needs_image_build" >> "$GITHUB_OUTPUT"
echo "needs_deployment=$needs_deployment" >> "$GITHUB_OUTPUT"
