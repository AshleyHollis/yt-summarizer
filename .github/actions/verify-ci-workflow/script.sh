#!/bin/bash
# =============================================================================
# Verify CI Workflow Passed
# =============================================================================
# PURPOSE:
#   Verifies that the CI workflow completed successfully
#   Used with workflow_run triggers to prevent deployment on CI failure
#
# INPUTS (via environment variables):
#   WORKFLOW_CONCLUSION    Conclusion of the workflow run (success/failure)
#   WORKFLOW_NAME          Name of the workflow that triggered this run
#
# OUTPUTS:
#   Exit code 0 if passed, 1 if failed
#
# LOGIC:
#   1. Log which workflow triggered this run
#   2. Check if conclusion is "success"
#   3. If not success, error out and prevent deployment
#   4. If success, confirm and proceed
#
# =============================================================================
set -euo pipefail

echo "Triggered by workflow_run for workflow: ${WORKFLOW_NAME}"

if [ "${WORKFLOW_CONCLUSION}" != "success" ]; then
  echo "::error::CI workflow did not pass. Preview deployment blocked."
  exit 1
fi

echo "✅ CI workflow passed successfully"
