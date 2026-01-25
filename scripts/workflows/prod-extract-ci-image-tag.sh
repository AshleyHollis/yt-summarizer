#!/bin/bash
# =============================================================================
# Extract CI-built image tag for production deployment
# =============================================================================
# Used by: .github/workflows/deploy-prod.yml (get-ci-image-tag job, lines 357-367)
# Purpose: Extract the image tag that CI workflow built for this commit
#
# Inputs:
#   - $COMMIT_SHA: The commit SHA to build tag from (e.g., github.sha)
#
# Outputs:
#   - image_tag: sha-{short_commit_sha} (e.g., sha-abc1234)
#
# Logic:
#   1. Get short SHA (7 characters) of current commit
#   2. Generate deterministic tag: sha-{short_sha}
#   3. CI workflow has already built this image (with same naming)
#
# Note: CI workflow builds images with sha-{commit} tag on every push to main.
#       This job just extracts that tag for use in kustomization.
#
# Exit: Succeeds if tag generation works
# =============================================================================

set -euo pipefail

COMMIT_SHA="${1:-${COMMIT_SHA:-${GITHUB_SHA:-}}}"
if [ -z "$COMMIT_SHA" ]; then
  COMMIT_SHA=$(git rev-parse HEAD)
fi

SHORT_SHA="${COMMIT_SHA:0:7}"
if [ -z "$SHORT_SHA" ]; then
  echo "::error::Unable to determine short commit SHA for image tag"
  exit 1
fi

IMAGE_TAG="sha-${SHORT_SHA}"

echo "image_tag=$IMAGE_TAG" >> "$GITHUB_OUTPUT"
echo "✅ Using CI-built image tag: $IMAGE_TAG"
