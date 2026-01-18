#!/bin/bash

################################################################################
# Action: kustomize-validate / validate-yaml.sh
#
# Purpose: Validates YAML syntax of the built Kustomize manifest using Python
#          YAML parser. Detects malformed YAML before applying to cluster.
#
# Inputs (Environment Variables):
#   MANIFEST          - Path to built manifest file
#
# Outputs:
#   Reports status via GitHub Actions groups (::group::, ::endgroup::)
#   No explicit output variables
#   Exits with code 0 on success, 1 on syntax errors
#
# Process:
#   1. Calls scripts/ci/parse_yaml.py with manifest path
#   2. Captures and displays parsing output
#   3. Shows first 100 lines of manifest on failure
#   4. Reports success or failure via echo
#
# Error Handling:
#   - Fails if parse_yaml.py returns non-zero
#   - Shows manifest preview on failure for debugging
#   - Continues if manifest file preview fails
#
################################################################################

set -euo pipefail

MANIFEST="${MANIFEST:?MANIFEST not set}"

echo "::group::Validating YAML syntax"
if ! python3 scripts/ci/parse_yaml.py "$MANIFEST" 2>&1; then
  echo "::error::YAML validation failed"
  echo "--- First 100 lines of manifest ---"
  head -n 100 "$MANIFEST" || true
  echo "::endgroup::"
  exit 1
fi
echo "✅ YAML syntax valid"
echo "::endgroup::"
