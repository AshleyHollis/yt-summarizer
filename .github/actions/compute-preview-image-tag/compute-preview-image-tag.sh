#!/bin/bash
# Purpose: Determines which image tag to use for preview deployment
# Inputs:
#   NEEDS_IMAGE_BUILD: Whether new images need to be built
#   CI_TAG: Image tag from CI workflow (if images were built)
#   PROD_TAG: Current production image tag (fallback)
# Outputs:
#   image_tag: Computed image tag to use for preview deployment
#   source: Source of the image tag (ci or production)
# Logic:
#   1. If needs_image_build=true, use CI_TAG
#   2. If needs_image_build=false, use PROD_TAG
#   3. Error if required tag is empty
#   4. Output selected tag and its source

set -euo pipefail

NEEDS_IMAGE_BUILD="${NEEDS_IMAGE_BUILD:-}"
CI_TAG="${CI_TAG:-}"
PROD_TAG="${PROD_TAG:-}"

echo "=== Image Tag Computation ==="
echo "needs_image_build: $NEEDS_IMAGE_BUILD"
echo "CI image_tag: $CI_TAG"
echo "Production image_tag: $PROD_TAG"
echo ""

# Single Responsibility: Compute the correct image tag based on build requirement
if [ "$NEEDS_IMAGE_BUILD" = "true" ]; then
  # New images from CI are required
  if [ -z "$CI_TAG" ]; then
    echo "::error::needs_image_build=true but CI did not provide an image tag"
    echo "This indicates CI did not complete successfully or did not \
      build images."
    exit 1
  fi
  IMAGE_TAG="$CI_TAG"
  SOURCE="ci"
  echo "✅ Using NEW image tag from CI: $IMAGE_TAG"
else
  # Use existing production images (K8s-only changes or forced deploy)
  if [ -z "$PROD_TAG" ]; then
    echo "::error::needs_image_build=false but could not retrieve production \
      image tag"
    exit 1
  fi
  IMAGE_TAG="$PROD_TAG"
  SOURCE="production"
  echo "✅ Using EXISTING production image tag: $IMAGE_TAG"
fi

echo "image_tag=$IMAGE_TAG" >> $GITHUB_OUTPUT
echo "source=$SOURCE" >> $GITHUB_OUTPUT
