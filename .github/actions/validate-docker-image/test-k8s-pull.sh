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

################################################################################
# Header
################################################################################
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║  Kubernetes Image Pull Test                                                  ║"
echo "╠══════════════════════════════════════════════════════════════════════════════╣"
echo "║  Image: ${FULL_IMAGE}"
echo "║  Purpose: Verify K8s cluster can pull from ACR (not just Azure CLI)          ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""

################################################################################
# Setup test namespace
################################################################################
TEST_NAMESPACE="acr-pull-test-$(date +%s)"
CLEANUP_NEEDED=false

echo "[INFO] ⏳ Creating test namespace: $TEST_NAMESPACE"
if kubectl create namespace "$TEST_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f - &>/dev/null; then
  CLEANUP_NEEDED=true
  echo "[INFO] ✓ Test namespace created"
else
  echo "[WARN] ⚠️ Could not create test namespace, using default"
  TEST_NAMESPACE="default"
fi

################################################################################
# Create and monitor test pod
################################################################################
POD_NAME="acr-pull-test-$(date +%s)"
PULL_SUCCESS=false

echo "[INFO] ↻ Creating test pod to pull image..."
if ! kubectl run ${POD_NAME} \
  --image=${FULL_IMAGE} \
  --restart=Never \
  --namespace="$TEST_NAMESPACE" \
  --command -- sh -c "echo 'Image pulled successfully' && exit 0" 2>&1; then
  echo "[ERROR] ✗ Failed to create test pod"
  echo "::error::kubectl run command failed - check permissions or cluster connectivity"
  # Cleanup namespace if we created it
  if [ "$CLEANUP_NEEDED" = "true" ]; then
    kubectl delete namespace "$TEST_NAMESPACE" --ignore-not-found=true &>/dev/null || true
  fi
  exit 1
fi

echo "[INFO] ⏳ Waiting for pod status (max 60s)..."
for i in {1..60}; do
  POD_STATUS=$(kubectl get pod ${POD_NAME} -n "$TEST_NAMESPACE" -o jsonpath='{.status.phase}' 2>/dev/null || echo "Unknown")

  if [ "$POD_STATUS" = "Running" ] || [ "$POD_STATUS" = "Succeeded" ]; then
    PULL_SUCCESS=true
    echo "[INFO] ✓ Image pull successful - Pod status: $POD_STATUS"
    break
  elif [ "$POD_STATUS" = "Failed" ] || [ "$POD_STATUS" = "ErrImagePull" ] || [ "$POD_STATUS" = "ImagePullBackOff" ]; then
    echo "[ERROR] ✗ Image pull failed - Pod status: $POD_STATUS"
    break
  fi

  # Check container status for more detail
  CONTAINER_STATE=$(kubectl get pod ${POD_NAME} -n "$TEST_NAMESPACE" -o jsonpath='{.status.containerStatuses[0].state}' 2>/dev/null || echo "")
  if [[ "$CONTAINER_STATE" == *"ErrImagePull"* ]] || [[ "$CONTAINER_STATE" == *"ImagePullBackOff"* ]]; then
    echo "[ERROR] ✗ Image pull failed - Container state: ErrImagePull/ImagePullBackOff"
    break
  fi

  # Show progress every 10 seconds
  if [ $((i % 10)) -eq 0 ]; then
    echo "[INFO] ⏱️ Still waiting... (${i}s elapsed)"
  fi

  sleep 1
done

################################################################################
# Handle failure diagnostics
################################################################################
if [ "$PULL_SUCCESS" = "false" ]; then
  echo ""
  echo "::group::🔍 Pod Events (Pull Failure Diagnostics)"
  kubectl describe pod ${POD_NAME} -n "$TEST_NAMESPACE" 2>/dev/null | grep -A 20 "Events:" || echo "Could not retrieve events"
  echo "::endgroup::"

  echo "::group::🔍 Container Status Details"
  kubectl get pod ${POD_NAME} -n "$TEST_NAMESPACE" -o jsonpath='{.status.containerStatuses[0]}' 2>/dev/null | jq '.' || echo "Could not retrieve container status"
  echo "::endgroup::"
  echo ""

  echo "[ERROR] ✗ CRITICAL: Image exists in ACR but Kubernetes CANNOT pull it!"
  echo "::error::ACR authentication/permissions issue detected"
  echo ""
  echo "[INFO] Possible causes:"
  echo "       1. AKS kubelet identity may not have AcrPull role on the registry"
  echo "       2. ACR network rules may be blocking AKS cluster"
  echo "       3. Image pull secrets may be missing or invalid"
  echo ""
  echo "[INFO] Recommended fixes:"
  echo "       - Verify AKS managed identity has 'AcrPull' role"
  echo "       - Check ACR network rules allow AKS subnet"
  echo "       - Prefer managed identity over imagePullSecrets"
fi

################################################################################
# Cleanup
################################################################################
echo ""
echo "[INFO] ↻ Cleaning up test resources..."
kubectl delete pod ${POD_NAME} -n "$TEST_NAMESPACE" --ignore-not-found=true &>/dev/null || true
if [ "$CLEANUP_NEEDED" = "true" ]; then
  kubectl delete namespace "$TEST_NAMESPACE" --ignore-not-found=true &>/dev/null || true
fi
echo "[INFO] ✓ Cleanup complete"

################################################################################
# Output result
################################################################################
echo "pull_success=${PULL_SUCCESS}" >> $GITHUB_OUTPUT

echo ""
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
if [ "$PULL_SUCCESS" = "true" ]; then
  echo "║  Result: ✓ SUCCESS - Kubernetes can pull this image                          ║"
  echo "╚══════════════════════════════════════════════════════════════════════════════╝"
else
  echo "║  Result: ✗ FAILED - Kubernetes cannot pull this image                        ║"
  echo "╚══════════════════════════════════════════════════════════════════════════════╝"
  exit 1
fi
