#!/bin/bash
# Verify that one or more Kubernetes deployments are using the expected image tag

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

print_header "Verify K8s Deployments" \
  "Namespace: $NAMESPACE" \
  "Expected Tag: $EXPECTED_TAG" \
  "Registry: $REGISTRY" \
  "Image: $IMAGE_NAME"

# Split deployments into array
IFS=',' read -ra DEPLOYMENT_ARRAY <<< "$DEPLOYMENTS"

# Wait for deployments to be ready if requested
if [ "$WAIT_FOR_READY" = "true" ]; then
  log_step "⏳ Waiting for deployments to be ready..."
  for deployment in "${DEPLOYMENT_ARRAY[@]}"; do
    deployment=$(echo "$deployment" | xargs)  # trim whitespace
    log_info "   ⏳ Waiting for $deployment..."

    if ! kubectl rollout status deployment/"$deployment" -n "$NAMESPACE" --timeout="${TIMEOUT_SECONDS}s"; then
      log_warn "Deployment $deployment is not ready after ${TIMEOUT_SECONDS}s"
      echo "::warning::Deployment $deployment is not ready after ${TIMEOUT_SECONDS}s"
    else
      log_success "$deployment is ready"
    fi
  done
  echo ""
fi

# Verify each deployment
MISMATCH_FOUND=false
VERIFIED_COUNT=0
TOTAL_COUNT=${#DEPLOYMENT_ARRAY[@]}

log_step "Verifying image tags..."
for deployment in "${DEPLOYMENT_ARRAY[@]}"; do
  deployment=$(echo "$deployment" | xargs)  # trim whitespace

  log_info "Checking $deployment..."

  # Get the image from the deployment
  ACTUAL_IMAGE=$(kubectl get deployment "$deployment" -n "$NAMESPACE" \
    -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null || echo "")

  if [ -z "$ACTUAL_IMAGE" ]; then
    log_error "Deployment $deployment not found in namespace $NAMESPACE"
    echo "::error::Deployment $deployment not found in namespace $NAMESPACE"
    MISMATCH_FOUND=true
    continue
  fi

  # Extract tag from image
  ACTUAL_TAG="${ACTUAL_IMAGE##*:}"

  if [ "$ACTUAL_TAG" != "$EXPECTED_TAG" ]; then
    log_error "Tag mismatch for $deployment: expected $EXPECTED_TAG, got $ACTUAL_TAG"
    echo "::error::❌ Image tag mismatch for $deployment: expected $EXPECTED_TAG, got $ACTUAL_TAG"
    MISMATCH_FOUND=true
  else
    log_success "$deployment: $ACTUAL_TAG"
    VERIFIED_COUNT=$((VERIFIED_COUNT + 1))
  fi
done

if [ "$MISMATCH_FOUND" = "true" ] && [ "$FAIL_ON_MISMATCH" = "true" ]; then
  echo "::error::One or more deployments have mismatched image tags"
  print_footer "❌ Verification failed ($VERIFIED_COUNT/$TOTAL_COUNT deployments verified)"
  exit 1
fi

if [ "$MISMATCH_FOUND" = "true" ]; then
  log_warn "Mismatches found but fail-on-mismatch is disabled"
  print_footer "⚠️  Verification completed with warnings ($VERIFIED_COUNT/$TOTAL_COUNT)"
else
  print_footer "✅ All $TOTAL_COUNT deployments verified successfully!"
fi
