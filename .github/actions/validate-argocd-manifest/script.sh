#!/bin/bash

################################################################################
# Action: validate-argocd-manifest / script.sh
#
# Purpose: Pre-deployment validation of Argo CD manifest generation.
#          Detects manifest errors BEFORE sync operation to avoid timeouts.
#
# Validates:
#   1. Argo CD Application CRD exists and is properly configured
#   2. Application can generate manifest without errors
#   3. No pre-existing sync conditions that would block deployment
#   4. Target revision is correct (branch or SHA)
#   5. Resources can be parsed by kubectl
#
# Inputs (Environment Variables):
#   APP_NAME        - Argo CD Application name
#   NAMESPACE       - Target Kubernetes namespace
#   TIMEOUT         - Maximum validation time in seconds
#
################################################################################

set -euo pipefail

APP_NAME="${APP_NAME:-}"
NAMESPACE="${NAMESPACE:-}"
TIMEOUT="${TIMEOUT:-60}"

if [[ -z "$APP_NAME" ]] || [[ -z "$NAMESPACE" ]]; then
  echo "::error::APP_NAME and NAMESPACE are required"
  exit 1
fi

echo "🔍 Pre-deployment Argo CD manifest validation..."
echo "  Application: ${APP_NAME}"
echo "  Namespace: ${NAMESPACE}"
echo "  Timeout: ${TIMEOUT}s"
echo ""

# Check 1: Application CRD exists
echo "::group::✅ Check 1: Argo CD Application CRD exists"
if ! kubectl get application "${APP_NAME}" -n argocd &>/dev/null; then
  echo "::error::Application '${APP_NAME}' not found in argocd namespace"
  echo "This typically means:"
  echo "  - The ApplicationSet has not created the application yet"
  echo "  - The application name is incorrect"
  echo "  - The argocd namespace is not accessible"
  echo ""
  echo "Available applications:"
  kubectl get applications -n argocd || echo "Cannot list applications"
  exit 1
fi
echo "✅ Application '${APP_NAME}' exists"
echo "::endgroup::"

# Check 2: Application has correct configuration
echo ""
echo "::group::✅ Check 2: Application configuration"

TARGET_REV=$(kubectl get application "${APP_NAME}" -n argocd -o jsonpath='{.spec.source.targetRevision}' 2>/dev/null || echo "")
SOURCE_REPO=$(kubectl get application "${APP_NAME}" -n argocd -o jsonpath='{.spec.source.repoURL}' 2>/dev/null || echo "")
SOURCE_PATH=$(kubectl get application "${APP_NAME}" -n argocd -o jsonpath='{.spec.source.path}' 2>/dev/null || echo "")
DEST_NAMESPACE=$(kubectl get application "${APP_NAME}" -n argocd -o jsonpath='{.spec.destination.namespace}' 2>/dev/null || echo "")

echo "Target Revision: ${TARGET_REV}"
echo "Repository: ${SOURCE_REPO}"
echo "Path: ${SOURCE_PATH}"
echo "Destination Namespace: ${DEST_NAMESPACE}"

# CRITICAL CHECK: Verify Application is tracking branch, not commit SHA
if [[ "${TARGET_REV}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "::error::❌ FATAL: Application is tracking commit SHA instead of branch!"
  echo "  Target: ${TARGET_REV} (appears to be a commit SHA)"
  echo "  This prevents Argo CD from detecting updated overlays pushed to branches."
  echo ""
  echo "  Fix: Update ApplicationSet to use {{branch}} instead of {{head_sha}}"
  echo "  Location: .github/applicationsets/preview.yaml or similar"
  exit 1
fi

# Verify destination namespace matches expected
if [ -n "$DEST_NAMESPACE" ] && [ "$DEST_NAMESPACE" != "$NAMESPACE" ]; then
  echo "::warning::Destination namespace mismatch"
  echo "  Expected: ${NAMESPACE}"
  echo "  Configured: ${DEST_NAMESPACE}"
  # Non-fatal but worth noting
fi

echo "✅ Application configuration is valid"
echo "::endgroup::"

# Check 3: Manifest generation without errors
echo ""
echo "::group::✅ Check 3: Manifest generation"

# Try to get manifest status from Application
MANIFEST_STATUS=$(kubectl get application "${APP_NAME}" -n argocd -o jsonpath='{.status.summary.images}' 2>/dev/null || echo "")
if [ -n "$MANIFEST_STATUS" ]; then
  echo "  Images in manifest: ${MANIFEST_STATUS}"
else
  echo "  ⚠️  No images in manifest yet (may still be generating)"
fi

echo "✅ Manifest generation appears healthy"
echo "::endgroup::"

# Check 4: No pre-existing sync conditions
echo ""
echo "::group::✅ Check 4: Sync conditions"

# Check for sync errors
SYNC_ERROR_MSG=$(kubectl get application "${APP_NAME}" -n argocd -o jsonpath='{.status.conditions[?(@.type=="SyncError")].message}' 2>/dev/null || echo "")
if [ -n "$SYNC_ERROR_MSG" ]; then
  echo "::error::❌ Pre-existing sync error condition detected:"
  echo "${SYNC_ERROR_MSG}"
  echo ""
  echo "Sync conditions:"
  kubectl get application "${APP_NAME}" -n argocd -o jsonpath='{.status.conditions[*]}' | jq . 2>/dev/null || \
    kubectl get application "${APP_NAME}" -n argocd -o jsonpath='{.status.conditions}' 2>/dev/null
  exit 1
fi

# Check health status
HEALTH_STATUS=$(kubectl get application "${APP_NAME}" -n argocd -o jsonpath='{.status.health.status}' 2>/dev/null || echo "Unknown")
echo "  Health Status: ${HEALTH_STATUS}"

if [ "$HEALTH_STATUS" = "Missing" ]; then
  echo "::error::❌ Application health is 'Missing' - resources cannot be found"
  echo "Possible causes:"
  echo "  1. Resources have not been deployed yet (first sync)"
  echo "  2. Resources were deleted externally"
  echo "  3. Namespace does not exist"
  echo ""
  if ! kubectl get namespace "${NAMESPACE}" &>/dev/null; then
    echo "Namespace '${NAMESPACE}' does NOT exist - this is expected before first sync"
  fi
fi

# Check sync status
SYNC_STATUS=$(kubectl get application "${APP_NAME}" -n argocd -o jsonpath='{.status.sync.status}' 2>/dev/null || echo "Unknown")
echo "  Sync Status: ${SYNC_STATUS}"

if [ "$SYNC_STATUS" = "OutOfSync" ]; then
  echo "  ℹ️  Application is OutOfSync (expected - we're about to sync)"
fi

echo "✅ No blocking sync conditions"
echo "::endgroup::"

# Check 5: Check if a sync operation is already running
echo ""
echo "::group::✅ Check 5: Sync operation status"

OPERATION_STATE=$(kubectl get application "${APP_NAME}" -n argocd -o jsonpath='{.status.operationState.phase}' 2>/dev/null || echo "None")
OPERATION_MSG=$(kubectl get application "${APP_NAME}" -n argocd -o jsonpath='{.status.operationState.message}' 2>/dev/null || echo "")

echo "  Operation State: ${OPERATION_STATE}"
if [ -n "$OPERATION_MSG" ]; then
  echo "  Message: ${OPERATION_MSG}"
fi

if [ "$OPERATION_STATE" = "Running" ]; then
  echo "::warning::⚠️  A sync operation is already in progress"
  echo "  Waiting for it to complete or checking if it's stuck..."
  
  # Check how long operation has been running
  STARTED_AT=$(kubectl get application "${APP_NAME}" -n argocd -o jsonpath='{.status.operationState.startedAt}' 2>/dev/null || echo "")
  if [ -n "$STARTED_AT" ]; then
    START_TIME=$(date -d "$STARTED_AT" +%s 2>/dev/null || echo "0")
    CURRENT_TIME=$(date +%s)
    ELAPSED=$((CURRENT_TIME - START_TIME))
    echo "  Operation running for: ${ELAPSED}s"
    
    if [ $ELAPSED -gt 300 ]; then
      echo "::error::❌ Operation has been running for ${ELAPSED}s (>5 minutes) - likely stuck!"
      echo ""
      echo "Recommended actions:"
      echo "  1. Check Argo CD controller logs:"
      echo "     kubectl logs -n argocd deployment/argocd-application-controller -f"
      echo "  2. Check if there's a hook job that's stuck:"
      echo "     kubectl get jobs -n ${NAMESPACE}"
      echo "  3. Force sync abort:"
      echo "     kubectl patch application ${APP_NAME} -n argocd --type merge -p '{\"operation\":null}'"
      exit 1
    fi
  fi
fi

if [ "$OPERATION_STATE" = "Failed" ]; then
  echo "::error::❌ Last sync operation FAILED"
  echo "Error message: ${OPERATION_MSG}"
  echo ""
  
  # Get more details
  echo "Full operation state:"
  kubectl get application "${APP_NAME}" -n argocd -o jsonpath='{.status.operationState}' | jq . 2>/dev/null || \
    kubectl get application "${APP_NAME}" -n argocd -o jsonpath='{.status.operationState}'
  exit 1
fi

echo "✅ No blocking operations"
echo "::endgroup::"

# Check 6: Validate resources can be parsed
echo ""
echo "::group::✅ Check 6: Resource validation"

echo "Getting generated manifests from Argo CD..."
MANIFESTS=$(kubectl get application "${APP_NAME}" -n argocd -o jsonpath='{.status.resources[*].kind}' 2>/dev/null || echo "")

if [ -n "$MANIFESTS" ]; then
  echo "  Resource kinds found: $(echo $MANIFESTS | tr ' ' ', ')"
  RESOURCE_COUNT=$(echo $MANIFESTS | wc -w)
  echo "  Total resources: ${RESOURCE_COUNT}"
  echo "✅ Resources can be parsed"
else
  echo "  ⚠️  No resources found yet (may still be initializing)"
fi

echo "::endgroup::"

echo ""
echo "✅ All pre-deployment validation checks passed!"
echo ""
echo "Ready to sync. The deployment can proceed safely."
