#!/bin/bash
# =============================================================================
# Update Preview Overlay
# =============================================================================
# PURPOSE:
#   Update Kubernetes preview overlay with image tags and preview configuration
#   Creates PR-specific overlay directories in preparation for commit to
#   the preview-overlays branch.
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
#   Updated k8s/overlays/preview-pr-{number}/kustomization.yaml file
#
# LOGIC:
#   1. Validate that image tag is not empty
#   2. Create PR-specific overlay directory if it doesn't exist
#   3. Copy base preview overlay as starting point
#   4. Call shell script to generate kustomization with environment variables
#   5. Output URL, host, and secret via GITHUB_OUTPUT
#   6. Display generated overlay for verification
#
# NOTE: This overlay is committed to the 'preview-overlays' branch, NOT the PR branch.
#       This prevents preview commits from invalidating CI status on PR branches.
#
# =============================================================================
set -euo pipefail

# Validate inputs
if [ -z "${IMAGE_TAG}" ]; then
  echo "::error::IMAGE_TAG is empty. Aborting to avoid committing empty tags."
  exit 1
fi

# PR-specific overlay path
OVERLAY_DIR="k8s/overlays/preview-pr-${PR_NUMBER}"
OVERLAY_FILE="${OVERLAY_DIR}/kustomization.yaml"
BASE_OVERLAY_DIR="k8s/overlays/preview"

# Create PR-specific overlay directory if it doesn't exist
if [ ! -d "${OVERLAY_DIR}" ]; then
  echo "📁 Creating PR-specific overlay directory: ${OVERLAY_DIR}"
  mkdir -p "${OVERLAY_DIR}"

  # Copy base preview overlay structure if it exists
  if [ -d "${BASE_OVERLAY_DIR}" ]; then
    echo "📋 Copying base preview overlay structure..."
    cp -r "${BASE_OVERLAY_DIR}"/* "${OVERLAY_DIR}/" 2>/dev/null || true
  fi
fi

# Generate preview overlay using shell script
echo "Using IMAGE_TAG=${IMAGE_TAG}"

bash scripts/ci/generate_preview_kustomization.sh \
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
