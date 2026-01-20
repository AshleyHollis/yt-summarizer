#!/bin/bash
# =============================================================================
# Finalize deployment flags for preview workflow
# =============================================================================
# Used by: .github/workflows/preview.yml (detect-changes job, lines 182-195)
# Purpose: ALWAYS deploy previews (change detection disabled)
#
# Inputs (via GitHub Actions step context):
#   - github.event_name: 'pull_request' or 'workflow_dispatch'
#   - inputs.run_preview: boolean from workflow_dispatch (if applicable)
#
# Outputs:
#   - needs_image_build: Always true (unless workflow_dispatch disables)
#   - needs_deployment: Always true (unless workflow_dispatch disables)
#
# Logic:
#   CHANGE DETECTION DISABLED - Always deploy to avoid skipping issues
#   If workflow_dispatch AND inputs.run_preview != 'true':
#     Set both flags to false (explicit skip)
#   Otherwise:
#     Force both flags to true (always deploy)
#
# Exit: Always succeeds
# =============================================================================

set -e  # Exit on error

# CHANGE DETECTION DISABLED: Always deploy by default
needs_image_build=true
needs_deployment=true

# workflow_dispatch can explicitly disable preview deployment
if [[ "${EVENT_NAME}" == "workflow_dispatch" ]] && [[ "${RUN_PREVIEW}" != "true" ]]; then
  needs_image_build=false
  needs_deployment=false
fi

echo "needs_image_build=$needs_image_build" >> "$GITHUB_OUTPUT"
echo "needs_deployment=$needs_deployment" >> "$GITHUB_OUTPUT"
