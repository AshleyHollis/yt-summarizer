#!/bin/bash
# =============================================================================
# Update Production Kustomization
# =============================================================================
# PURPOSE:
#   Updates production kustomization.yaml with new image tag
#
# INPUTS (via environment variables):
#   IMAGE_TAG                Image tag to use for production deployment
#   KUSTOMIZATION_PATH       Path to kustomization overlay directory
#   TEMPLATE_PATH            Path to kustomization template (relative to repo)
#
# OUTPUTS:
#   Updated kustomization.yaml file in overlay directory
#
# LOGIC:
#   1. Call Python script to update kustomization with image tag
#   2. Display confirmation and show updated file content
#
# =============================================================================
set -euo pipefail

cd "${KUSTOMIZATION_PATH}"

bash ../../../scripts/ci/update_prod_kustomization.sh \
  --image-tag "${IMAGE_TAG}"

echo "✅ Updated production kustomization with tag: ${IMAGE_TAG}"
echo ""
echo "--- kustomization.yaml ---"
cat kustomization.yaml
