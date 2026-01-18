#!/bin/bash
# =============================================================================
# Update Preview Overlay
# =============================================================================
# PURPOSE:
#   Update Kubernetes preview overlay with image tags and preview configuration
#
# INPUTS (via environment variables):
#   PR_NUMBER           Pull request number
#   IMAGE_TAG           Docker image tag to use
#   ACR_SERVER          Azure Container Registry server
#   PREVIEW_HOST        Preview environment hostname
#   TLS_SECRET          TLS secret name
#   PREVIEW_URL         Full preview URL
#   COMMIT_SHA          Current commit SHA
#
# OUTPUTS (via $GITHUB_OUTPUT):
#   preview_url         Preview environment URL
#   preview_host        Preview environment host
#   tls_secret          TLS secret name
#   Updated k8s/overlays/preview/kustomization.yaml file
#
# LOGIC:
#   1. Validate that image tag is not empty
#   2. Check that preview overlay file exists
#   3. Call Python script to generate kustomization with environment variables
#   4. Output URL, host, and secret via GITHUB_OUTPUT
#   5. Display generated overlay for verification
#
# =============================================================================
set -euo pipefail

# Validate inputs
if [ -z "${IMAGE_TAG}" ]; then
  echo "::error::IMAGE_TAG is empty. Aborting to avoid committing empty tags."
  exit 1
fi

OVERLAY_FILE="k8s/overlays/preview/kustomization.yaml"
if [ ! -f "${OVERLAY_FILE}" ]; then
  echo "::error::Preview overlay not found at ${OVERLAY_FILE}"
  echo "::error::Ensure k8s/overlays/preview/ exists in your PR branch"
  exit 1
fi

# Generate preview overlay using Python script
echo "Using IMAGE_TAG=${IMAGE_TAG}"

python scripts/ci/generate_preview_kustomization.py \
  --template scripts/ci/templates/preview-kustomization-template.yaml \
  --output "${OVERLAY_FILE}" \
  --pr-number "${PR_NUMBER}" \
  --image-tag "${IMAGE_TAG}" \
  --acr-server "${ACR_SERVER}" \
  --preview-host "${PREVIEW_HOST}" \
  --tls-secret "${TLS_SECRET}" \
  --commit-sha "${COMMIT_SHA}"

echo "✅ Updated preview overlay at ${OVERLAY_FILE}"

# Output values for downstream jobs
{
  echo "preview_url=${PREVIEW_URL}"
  echo "preview_host=${PREVIEW_HOST}"
  echo "tls_secret=${TLS_SECRET}"
} >> "$GITHUB_OUTPUT"

# Display generated overlay for verification
echo "Generated overlay content:"
cat "${OVERLAY_FILE}"
