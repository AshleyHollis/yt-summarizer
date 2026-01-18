#!/bin/bash
# =============================================================================
# Validate Preview Overlay Inputs
# =============================================================================
# PURPOSE:
#   Validates that required files and inputs exist before generating overlay
#
# INPUTS (via environment variables):
#   IMAGE_TAG       Docker image tag (must not be empty)
#
# OUTPUTS:
#   Exit code 0     All validations passed
#   Exit code 1     Validation failed
#
# LOGIC:
#   1. Verify IMAGE_TAG environment variable is not empty
#   2. Check that preview overlay file exists at expected path
#   3. Report errors with GitHub Actions annotations
#
# =============================================================================

set -euo pipefail

# Validate IMAGE_TAG is provided
if [ -z "${IMAGE_TAG}" ]; then
  echo "::error::IMAGE_TAG is empty. Aborting to avoid committing empty tags."
  exit 1
fi

# Validate overlay file exists
OVERLAY_FILE="k8s/overlays/preview/kustomization.yaml"
if [ ! -f "${OVERLAY_FILE}" ]; then
  echo "::error::Preview overlay not found at ${OVERLAY_FILE}"
  echo "::error::Ensure k8s/overlays/preview/ exists in your PR branch"
  exit 1
fi

echo "✅ Validation passed: IMAGE_TAG=${IMAGE_TAG}, overlay file exists"
exit 0
