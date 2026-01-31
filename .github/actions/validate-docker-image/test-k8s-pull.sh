#!/bin/bash

################################################################################
# Action: validate-acr-image / test-k8s-pull.sh
#
# Purpose: Tests whether Kubernetes can successfully pull a Docker image from
#          ACR. This validates not just that the image exists, but that the
#          cluster has proper authentication and network access to ACR.
#
# Inputs (Environment Variables):
#   REGISTRY          - Container registry name (without .azurecr.io suffix)
#   REPOSITORY        - Repository name (e.g., yt-summarizer-api)
#   TAG               - Image tag to test
#
# Outputs:
#   Sets GitHub Actions output: pull_success=true|false
#   Reports status via GitHub Actions commands (::error::, ::group::, ::warning::)
#   Exits with code 0 on success, 1 on failure
#
# Process:
#   1. Creates temporary namespace for isolation
#   2. Launches test pod with the image to pull
#   3. Monitors pod status for up to 60 seconds
#   4. Detects ErrImagePull and ImagePullBackOff states
#   5. On failure, captures pod events and container status for diagnostics
#   6. Cleans up test resources
#   7. Provides actionable guidance for ACR authentication issues
#
# Error Handling:
#   - Issues warnings if namespace creation fails (falls back to default)
#   - Captures detailed pod events on image pull failure
#   - Fails with diagnostic output if pull fails
#   - Handles grep/jq failures gracefully with fallback output
#   - Always cleans up test pods and namespace
#
################################################################################

set -euo pipefail

REGISTRY="${REGISTRY:?REGISTRY not set}"
REPOSITORY="${REPOSITORY:?REPOSITORY not set}"
TAG="${TAG:?TAG not set}"
FULL_IMAGE="${REGISTRY}.azurecr.io/${REPOSITORY}:${TAG}"

echo ""
echo "🧪 Testing Kubernetes image pull capability..."
echo "   This verifies that K8s pods can actually pull the image (not just Azure CLI)"
echo ""

# Use a temporary test namespace to avoid conflicts
TEST_NAMESPACE="acr-pull-test-$(date +%s)"
CLEANUP_NEEDED=false

# Create test namespace
if kubectl create namespace "$TEST_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - &>/dev/null; then
  CLEANUP_NEEDED=true
  echo "  ✓ Created test namespace: $TEST_NAMESPACE"
else
  echo "  ::warning::Could not create test namespace, using default"
  TEST_NAMESPACE="default"
fi

# Try to pull the image using a test pod
echo "  🔄 Attempting image pull with test pod..."

POD_NAME="acr-pull-test-$(date +%s)"
PULL_SUCCESS=false

# Create a simple pod that just tries to pull the image (using kubectl run instead of YAML)
if ! kubectl run ${POD_NAME} \
  --image=${FULL_IMAGE} \
  --restart=Never \
  --namespace="$TEST_NAMESPACE" \
  --command -- sh -c "echo 'Image pulled successfully' && exit 0" 2>&1; then
  echo "  ::error::Failed to create test pod. kubectl run command failed."
  echo "  ::error::This may indicate insufficient permissions or cluster connectivity issues."
  # Cleanup namespace if we created it
  if [ "$CLEANUP_NEEDED" = "true" ]; then
    kubectl delete namespace "$TEST_NAMESPACE" --ignore-not-found=true &>/dev/null || true
  fi
  exit 1
fi

# Wait up to 60 seconds for pod to start or fail
echo "  ⏳ Waiting for pod status (max 60s)..."
for i in {1..60}; do
  POD_STATUS=$(kubectl get pod ${POD_NAME} -n "$TEST_NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")

  if [ "$POD_STATUS" = "Running" ] || [ "$POD_STATUS" = "Succeeded" ]; then
    PULL_SUCCESS=true
    echo "  ✅ Image pull SUCCESSFUL - Pod status: $POD_STATUS"
    break
  elif [ "$POD_STATUS" = "Failed" ] || [ "$POD_STATUS" = "ErrImagePull" ] || [ "$POD_STATUS" = "ImagePullBackOff" ]; then
    echo "  ❌ Image pull FAILED - Pod status: $POD_STATUS"
    break
  fi

  # Check container status for more detail
  CONTAINER_STATE=$(kubectl get pod ${POD_NAME} -n "$TEST_NAMESPACE" -o jsonpath='{.status.containerStatuses[0].state}' 2>/dev/null || echo "")
  if [[ "$CONTAINER_STATE" == *"ErrImagePull"* ]] || [[ "$CONTAINER_STATE" == *"ImagePullBackOff"* ]]; then
    echo "  ❌ Image pull FAILED - Container state: ErrImagePull/ImagePullBackOff"
    break
  fi

  sleep 1
done

# Get detailed pod events if pull failed
if [ "$PULL_SUCCESS" = "false" ]; then
  echo ""
  echo "  ::group::🔍 Pod Events (Pull Failure Diagnostics)"
  kubectl describe pod ${POD_NAME} -n "$TEST_NAMESPACE" 2>/dev/null | grep -A 20 "Events:" || echo "Could not retrieve events"
  echo "  ::endgroup::"
  echo ""

  echo "  ::group::🔍 Container Status Details"
  kubectl get pod ${POD_NAME} -n "$TEST_NAMESPACE" -o jsonpath='{.status.containerStatuses[0]}' 2>/dev/null | jq '.' || echo "Could not retrieve container status"
  echo "  ::endgroup::"
  echo ""

  echo "::error::❌ CRITICAL: Image exists in ACR but Kubernetes CANNOT pull it!"
  echo "::error:: "
  echo "::error::  This indicates an ACR authentication/permissions issue:"
  echo "::error::  1. AKS kubelet identity may not have AcrPull role on the registry"
  echo "::error::  2. ACR network rules may be blocking AKS cluster"
  echo "::error::  3. Image pull secrets may be missing or invalid"
  echo "::error:: "
  echo "::error::  Recommended fixes:"
  echo "::error::  - Verify AKS managed identity has 'AcrPull' role: az role assignment list --scope /subscriptions/.../acr/..."
  echo "::error::  - Check ACR network rules allow AKS subnet"
  echo "::error::  - Prefer granting AKS managed identity the 'AcrPull' role; imagePullSecrets are a fallback and should be used only when necessary and managed securely"
else
  echo "  ✅ VERIFICATION PASSED: Kubernetes can successfully pull this image"
fi

# Cleanup
kubectl delete pod ${POD_NAME} -n "$TEST_NAMESPACE" --ignore-not-found=true &>/dev/null || true
if [ "$CLEANUP_NEEDED" = "true" ]; then
  kubectl delete namespace "$TEST_NAMESPACE" --ignore-not-found=true &>/dev/null || true
fi

# Output result
echo "pull_success=${PULL_SUCCESS}" >> $GITHUB_OUTPUT

# Exit with error if pull test failed
if [ "$PULL_SUCCESS" = "false" ]; then
  exit 1
fi
