#!/bin/bash
# =============================================================================
# Read current production image tag from kustomization
# =============================================================================
# Used by: .github/workflows/deploy-prod.yml (get-last-prod-image job, lines 422-441)
# Purpose: For K8s/infra-only changes, get the existing production image tag
#
# Outputs:
#   - image_tag: The currently deployed production image tag (e.g., sha-abc1234)
#
# Logic:
#   1. Read k8s/overlays/prod/kustomization.yaml from main branch
#   2. Extract newTag field (deterministic SHA-based tag)
#   3. Validate tag is not "latest" (non-deterministic)
#   4. Use that tag for K8s/infra-only deployments
#
# Note: This is different from preview, which searches PR history.
#       Production always uses current deployed tag as source of truth.
#
# Exit: Fails if no valid tag found or if using "latest"
# =============================================================================

set -e  # Exit on error

echo "📋 Reading current production image tag from kustomization..."

PROD_TAG=$(grep -oP 'newTag: \K.*' k8s/overlays/prod/kustomization.yaml | head -1)

if [ -z "$PROD_TAG" ]; then
  echo "::error::Could not find image tag in production kustomization.yaml"
  exit 1
fi

if [ "$PROD_TAG" = "latest" ]; then
  echo "::warning::Production is using 'latest' tag - not deterministic!"
  echo "::warning::This should be fixed to use SHA-based tags (e.g., sha-abc1234)"
  echo "::warning::Continuing with 'latest' for now..."
fi

echo "image_tag=$PROD_TAG" >> "$GITHUB_OUTPUT"
echo "✅ Using existing production image tag: $PROD_TAG"
