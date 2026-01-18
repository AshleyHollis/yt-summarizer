#!/bin/bash
# =============================================================================
# Assert Image Tag Artifact
# =============================================================================
# PURPOSE:
#   Verifies that the image-tag artifact was downloaded correctly
#
# INPUTS (via environment variables):
#   ARTIFACT_PATH     Path to the downloaded artifact file
#
# OUTPUTS:
#   Exits with code 0 if artifact exists, 1 otherwise
#
# LOGIC:
#   1. Check if artifact file exists at the specified path
#   2. If missing, emit error and exit 1
#   3. Display the contents of the artifact file for verification
#
# =============================================================================
set -euo pipefail

if [ ! -f "${ARTIFACT_PATH}" ]; then
  echo "::error::${ARTIFACT_PATH} not found in artifact"
  exit 1
fi

echo "Verified image tag artifact:"
cat "${ARTIFACT_PATH}"
