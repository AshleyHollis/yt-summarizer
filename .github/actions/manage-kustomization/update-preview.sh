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

# Logging helpers
print_header() {
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "[INFO] 🚀 $1"
  shift
  for line in "$@"; do
    echo "[INFO]    $line"
  done
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
}

print_footer() {
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "[INFO] $1"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

log_info() { echo "[INFO] $1"; }
log_warn() { echo "[WARN] ⚠️  $1"; }
log_error() { echo "[ERROR] ✗ $1"; }
log_success() { echo "[INFO]    ✓ $1"; }
log_step() { echo "[INFO] $1"; }

# Validate inputs
if [ -z "${IMAGE_TAG}" ]; then
  log_error "IMAGE_TAG is empty. Aborting to avoid committing empty tags."
  echo "::error::IMAGE_TAG is empty. Aborting to avoid committing empty tags."
  exit 1
fi

# PR-specific overlay path
OVERLAY_DIR="k8s/overlays/preview-pr-${PR_NUMBER}"
OVERLAY_FILE="${OVERLAY_DIR}/kustomization.yaml"
BASE_OVERLAY_DIR="k8s/overlays/preview"

print_header "Update Preview Overlay" \
  "PR Number: #${PR_NUMBER}" \
  "Image Tag: ${IMAGE_TAG}" \
  "Preview URL: ${PREVIEW_URL}"

# Create PR-specific overlay directory if it doesn't exist
if [ ! -d "${OVERLAY_DIR}" ]; then
  log_step "Creating PR-specific overlay directory..."
  mkdir -p "${OVERLAY_DIR}"

  # Copy base preview overlay structure if it exists
  if [ -d "${BASE_OVERLAY_DIR}" ]; then
    log_step "⏳ Copying base preview overlay structure..."
    cp -r "${BASE_OVERLAY_DIR}"/* "${OVERLAY_DIR}/" 2>/dev/null || true
    log_success "Base overlay copied"
  fi
  log_success "Created ${OVERLAY_DIR}"
else
  log_info "Overlay directory already exists: ${OVERLAY_DIR}"
fi

# Generate preview overlay using shell script
log_step "⏳ Generating preview kustomization..."

bash scripts/ci/generate_preview_kustomization.sh \
  --template scripts/ci/templates/preview-kustomization-template.yaml \
  --output "${OVERLAY_FILE}" \
  --pr-number "${PR_NUMBER}" \
  --image-tag "${IMAGE_TAG}" \
  --acr-server "${ACR_SERVER}" \
  --preview-host "${PREVIEW_HOST}" \
  --tls-secret "${TLS_SECRET}" \
  --commit-sha "${COMMIT_SHA}"

log_success "Generated overlay at ${OVERLAY_FILE}"

# Output values for downstream jobs
{
  echo "preview_url=${PREVIEW_URL}"
  echo "preview_host=${PREVIEW_HOST}"
  echo "tls_secret=${TLS_SECRET}"
} >> "$GITHUB_OUTPUT"

# Display generated overlay for verification
log_step "Generated overlay content:"
cat "${OVERLAY_FILE}"

print_footer "✅ Preview overlay updated successfully!"
