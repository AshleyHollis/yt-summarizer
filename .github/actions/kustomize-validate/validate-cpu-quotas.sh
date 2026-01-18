#!/bin/bash

################################################################################
# Action: kustomize-validate / validate-cpu-quotas.sh
#
# Purpose: Validates CPU quotas in the manifest against a maximum threshold.
#          Uses custom validation script to check resource requests/limits.
#
# Inputs (Environment Variables):
#   MANIFEST          - Path to built manifest file
#   MAX_CPU           - Maximum CPU quota in millicores
#   OVERLAY_NAME      - Name of overlay for error messages
#
# Outputs:
#   Reports status via GitHub Actions groups (::group::, ::endgroup::)
#   Reports errors via ::error:: if validation fails
#   No explicit output variables
#   Exits with code 0 on success, 1 on quota violations
#
# Process:
#   1. Calls scripts/ci/validate_kustomize.py with manifest and CPU limit
#   2. Passes overlay name for error context
#   3. Captures and displays validation output
#   4. Reports success or failure
#
# Error Handling:
#   - Fails if validate_kustomize.py returns non-zero
#   - Reports specific quota validation failure
#   - Continues on partial failures if script handles them
#
# Notes:
#   - This step is conditional and only runs if max-cpu input is provided
#   - Uses custom Python validation script
#
################################################################################

set -euo pipefail

MANIFEST="${MANIFEST:?MANIFEST not set}"
MAX_CPU="${MAX_CPU:?MAX_CPU not set}"
OVERLAY_NAME="${OVERLAY_NAME:?OVERLAY_NAME not set}"

echo "::group::Validating CPU quotas (max: ${MAX_CPU}m)"
if ! python3 scripts/ci/validate_kustomize.py \
  --file "$MANIFEST" \
  --max-cpu "$MAX_CPU" \
  --name "$OVERLAY_NAME" 2>&1; then
  echo "::error::CPU quota validation failed for $OVERLAY_NAME"
  echo "::endgroup::"
  exit 1
fi
echo "✅ CPU quotas within limits"
echo "::endgroup::"
