#!/bin/bash
# =============================================================================
# Export Image Tag
# =============================================================================
# PURPOSE:
#   Exports an image tag to GITHUB_OUTPUT for cross-job propagation
#
# INPUTS (via environment variables):
#   IMAGE_TAG       Image tag to export
#
# OUTPUTS (via $GITHUB_OUTPUT):
#   image_tag       Exported image tag
#
# LOGIC:
#   1. Output the provided image tag to GITHUB_OUTPUT
#   2. Log the exported tag for visibility
#
# =============================================================================
set -euo pipefail

echo "image_tag=${IMAGE_TAG}" >> "$GITHUB_OUTPUT"
echo "Exported image tag: ${IMAGE_TAG}"
