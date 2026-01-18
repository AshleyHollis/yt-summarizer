#!/bin/bash

################################################################################
# Action: kustomize-validate / validate-dry-run.sh
#
# Purpose: Performs Kubernetes server-side dry-run validation of the manifest.
#          Tests whether the manifest would be accepted by the Kubernetes API
#          server without actually applying changes.
#
# Inputs (Environment Variables):
#   MANIFEST          - Path to built manifest file
#   OVERLAY_NAME      - Name of overlay for error messages
#
# Outputs:
#   Reports status via GitHub Actions groups (::group::, ::endgroup::)
#   Reports errors via ::error:: if validation fails
#   No explicit output variables
#   Exits with code 0 on success, 1 on dry-run failure
#
# Process:
#   1. Executes kubectl apply with --server-dry-run=server flag
#   2. Uses server-side validation (requires Kubernetes 1.16+)
#   3. Displays error output and manifest preview on failure
#   4. Reports success or failure
#
# Error Handling:
#   - Fails if kubectl dry-run returns non-zero
#   - Shows first 100 lines of manifest on failure for debugging
#   - Continues if manifest preview fails
#
# Notes:
#   - This step is conditional and only runs if dry-run input is 'true'
#   - Requires active kubectl context/cluster connection
#   - Server-side validation catches schema violations and policy issues
#
################################################################################

set -euo pipefail

MANIFEST="${MANIFEST:?MANIFEST not set}"
OVERLAY_NAME="${OVERLAY_NAME:?OVERLAY_NAME not set}"

echo "::group::Kubernetes server-side dry-run"
if ! kubectl apply --server-dry-run=server -f "$MANIFEST" 2>&1; then
  echo "::error::Server dry-run failed for $OVERLAY_NAME"
  echo "--- Manifest Preview ---"
  head -n 100 "$MANIFEST" || true
  echo "::endgroup::"
  exit 1
fi
echo "✅ Server-side validation passed"
echo "::endgroup::"
