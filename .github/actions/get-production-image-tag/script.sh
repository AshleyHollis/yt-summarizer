#!/bin/bash
# =============================================================================
# Get Production Image Tag
# =============================================================================
# PURPOSE:
#   Extracts the current image tag from the production Kustomize overlay
#
# INPUTS (via environment variables):
#   OVERLAY_PATH        Path to the production overlay kustomization.yaml
#
# OUTPUTS (via $GITHUB_OUTPUT):
#   image_tag           Current production image tag
#
# LOGIC:
#   1. Verify overlay file exists
#   2. Extract newTag value from kustomization.yaml
#   3. If no tag found, error out
#   4. Output the tag via GITHUB_OUTPUT
#
# =============================================================================
set -euo pipefail

if [ ! -f "${OVERLAY_PATH}" ]; then
  echo "::error::Production overlay not found at: ${OVERLAY_PATH}"
  exit 1
fi

IMAGE_TAG=$(grep -oP 'newTag: \K.*' "${OVERLAY_PATH}" | head -1)

if [ -z "${IMAGE_TAG}" ]; then
  echo "::error::Could not find image tag (newTag) in production overlay"
  exit 1
fi

echo "Found production image tag: ${IMAGE_TAG}"
echo "image_tag=${IMAGE_TAG}" >> "$GITHUB_OUTPUT"
