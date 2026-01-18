#!/bin/bash
# =============================================================================
# Validate Image Tag Availability
# =============================================================================
# PURPOSE:
#   Validates that an image tag is available from CI for deployment
#
# INPUTS (via environment variables):
#   IMAGE_TAG                   The image tag to validate
#   CONCURRENCY_CHECK_RESULT    Result from concurrency check (can_deploy)
#
# OUTPUTS (via $GITHUB_OUTPUT):
#   can_deploy                  Whether deployment can proceed
#
# LOGIC:
#   1. Check if image tag is empty
#   2. If empty, set can_deploy=false (no images built)
#   3. If not empty, use the concurrency check result
#   4. Display warning if no image tag available
#
# =============================================================================
set -euo pipefail

if [ -z "${IMAGE_TAG}" ]; then
  echo "::error::No image tag available from CI. This may indicate CI " \
    "did not build images for this PR."
  echo "can_deploy=false" >> "$GITHUB_OUTPUT"
else
  echo "✅ Image tag available: ${IMAGE_TAG}"
  echo "can_deploy=${CONCURRENCY_CHECK_RESULT}" >> "$GITHUB_OUTPUT"
fi
