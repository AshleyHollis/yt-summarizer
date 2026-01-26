#!/bin/bash
# Verify that one or more Kubernetes deployments are using the expected image tag

set -euo pipefail

echo "🔍 Verifying deployments in namespace: $NAMESPACE"
echo "Expected tag: $EXPECTED_TAG"
echo "Registry: $REGISTRY"
echo "Image: $IMAGE_NAME"
echo ""

# Split deployments into array
IFS=',' read -ra DEPLOYMENT_ARRAY <<< "$DEPLOYMENTS"

# Wait for deployments to be ready if requested
if [ "$WAIT_FOR_READY" = "true" ]; then
  echo "⏳ Waiting for deployments to be ready..."
  for deployment in "${DEPLOYMENT_ARRAY[@]}"; do
    deployment=$(echo "$deployment" | xargs)  # trim whitespace
    echo "  - Waiting for $deployment..."

    if ! kubectl rollout status deployment/"$deployment" -n "$NAMESPACE" --timeout="${TIMEOUT_SECONDS}s"; then
      echo "::warning::Deployment $deployment is not ready after ${TIMEOUT_SECONDS}s"
    fi
  done
  echo ""
fi

# Verify each deployment
MISMATCH_FOUND=false
for deployment in "${DEPLOYMENT_ARRAY[@]}"; do
  deployment=$(echo "$deployment" | xargs)  # trim whitespace

  echo "🔍 Verifying $deployment..."

  # Get the image from the deployment
  ACTUAL_IMAGE=$(kubectl get deployment "$deployment" -n "$NAMESPACE" \
    -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null || echo "")

  if [ -z "$ACTUAL_IMAGE" ]; then
    echo "::error::Deployment $deployment not found in namespace $NAMESPACE"
    MISMATCH_FOUND=true
    continue
  fi

  # Extract tag from image
  ACTUAL_TAG="${ACTUAL_IMAGE##*:}"

  echo "  Actual image: $ACTUAL_IMAGE"
  echo "  Actual tag: $ACTUAL_TAG"

  if [ "$ACTUAL_TAG" != "$EXPECTED_TAG" ]; then
    echo "::error::❌ Image tag mismatch for $deployment: expected $EXPECTED_TAG, got $ACTUAL_TAG"
    MISMATCH_FOUND=true
  else
    echo "  ✅ Tag matches!"
  fi
  echo ""
done

if [ "$MISMATCH_FOUND" = "true" ] && [ "$FAIL_ON_MISMATCH" = "true" ]; then
  echo "::error::One or more deployments have mismatched image tags"
  exit 1
fi

if [ "$MISMATCH_FOUND" = "true" ]; then
  echo "⚠️  Mismatches found but fail-on-mismatch is disabled"
else
  echo "✅ All deployments verified successfully!"
fi
