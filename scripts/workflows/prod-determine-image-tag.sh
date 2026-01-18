#!/bin/bash
# =============================================================================
# Determine which image tag to deploy (CI-built vs. existing production)
# =============================================================================
# Used by: .github/workflows/deploy-prod.yml (update-overlay job, lines 491-515)
# Purpose: Select the correct image tag based on what changed
#
# Inputs:
#   - CI_IMAGE_TAG_RESULT: 'success'/'failure' (code changes path)
#   - PROD_IMAGE_TAG_RESULT: 'success'/'failure' (infra-only path)
#   - CI_IMAGE_TAG: The tag from CI (e.g., sha-abc1234)
#   - PROD_IMAGE_TAG: The existing production tag
#
# Outputs:
#   - image_tag: Final tag to deploy
#   - deployment_type: 'ci-build' or 'existing-image'
#
# Logic:
#   Path 1: Code changes detected
#     - CI job succeeded → use CI-built image (sha-{commit})
#   Path 2: K8s/infra only, no code changes
#     - Prod job succeeded → use existing image (current prod tag)
#     - Reuses last deployed image for K8s/config changes
#   Either way, image is validated to exist in ACR before use
#
# Exit: Fails if neither job succeeded
# =============================================================================

set -e  # Exit on error

CI_IMAGE_TAG_RESULT="${1}"
PROD_IMAGE_TAG_RESULT="${2}"
CI_IMAGE_TAG="${3}"
PROD_IMAGE_TAG="${4}"

# Path 1: Code changes (get-ci-image-tag succeeded - uses CI-built images)
if [ "$CI_IMAGE_TAG_RESULT" = "success" ]; then
  IMAGE_TAG="$CI_IMAGE_TAG"
  DEPLOYMENT_TYPE="ci-build"
  echo "📦 Using CI-built image: $IMAGE_TAG"

# Path 2: K8s/infra only (get-last-prod-image succeeded - reuses existing prod image)
elif [ "$PROD_IMAGE_TAG_RESULT" = "success" ]; then
  IMAGE_TAG="$PROD_IMAGE_TAG"
  DEPLOYMENT_TYPE="existing-image"
  echo "📦 Using existing production image: $IMAGE_TAG"
  echo "ℹ️  Deploying K8s/infra changes only (no code changes)"

else
  echo "::error::Neither get-ci-image-tag nor get-last-prod-image succeeded"
  echo "::error::This should not happen - check job dependencies"
  exit 1
fi

echo "image_tag=$IMAGE_TAG" >> "$GITHUB_OUTPUT"
echo "deployment_type=$DEPLOYMENT_TYPE" >> "$GITHUB_OUTPUT"
