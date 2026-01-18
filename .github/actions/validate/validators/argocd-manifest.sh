#!/usr/bin/env bash
# =============================================================================
# Argo CD Manifest Validator
# =============================================================================
# Pre-deployment validation of Argo CD manifest generation
# Detects manifest errors BEFORE sync operation to avoid timeouts
# Replaces: validate-argocd-manifest action

set -uo pipefail

# Load common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$SCRIPT_DIR/common.sh"

# Configuration
APP_NAME="${ARGOCD_APP_NAME:-}"
ARGOCD_NS="${ARGOCD_NAMESPACE:-argocd}"
TARGET_NS="${TARGET_NAMESPACE:-}"

log_info "Argo CD Manifest Validator"
log_info "Application: $APP_NAME"
log_info "Argo CD Namespace: $ARGOCD_NS"
log_info "Target Namespace: $TARGET_NS"
echo ""

# Validate required inputs
if [[ -z "$APP_NAME" ]]; then
  log_error "ARGOCD_APP_NAME is required"
  log_info "Set the application name to validate"
  exit 1
fi

# Check 1: Application CRD exists
log_info "Check 1: Argo CD Application CRD exists"
if ! kubectl get application "${APP_NAME}" -n "$ARGOCD_NS" &>/dev/null; then
  log_error "Application '${APP_NAME}' not found in $ARGOCD_NS namespace"
  echo ""
  log_info "This typically means:"
  echo "  - The ApplicationSet has not created the application yet"
  echo "  - The application name is incorrect"
  echo "  - The $ARGOCD_NS namespace is not accessible"
  echo ""
  log_info "Available applications:"
  kubectl get applications -n "$ARGOCD_NS" -o custom-columns=NAME:.metadata.name,SYNC:.status.sync.status 2>/dev/null || echo "Cannot list applications"
  exit 1
fi
log_success "Application '${APP_NAME}' exists"
echo ""

# Check 2: Application configuration
log_info "Check 2: Application configuration"

TARGET_REV=$(kubectl get application "${APP_NAME}" -n "$ARGOCD_NS" -o jsonpath='{.spec.source.targetRevision}' 2>/dev/null || echo "")
SOURCE_REPO=$(kubectl get application "${APP_NAME}" -n "$ARGOCD_NS" -o jsonpath='{.spec.source.repoURL}' 2>/dev/null || echo "")
SOURCE_PATH=$(kubectl get application "${APP_NAME}" -n "$ARGOCD_NS" -o jsonpath='{.spec.source.path}' 2>/dev/null || echo "")
DEST_NAMESPACE=$(kubectl get application "${APP_NAME}" -n "$ARGOCD_NS" -o jsonpath='{.spec.destination.namespace}' 2>/dev/null || echo "")

log_verbose "  Target Revision: ${TARGET_REV}"
log_verbose "  Repository: ${SOURCE_REPO}"
log_verbose "  Path: ${SOURCE_PATH}"
log_verbose "  Destination Namespace: ${DEST_NAMESPACE}"

# CRITICAL: Verify Application is tracking branch, not commit SHA
if [[ "${TARGET_REV}" =~ ^[0-9a-f]{40}$ ]]; then
  log_error "Application is tracking commit SHA instead of branch!"
  echo "  Target: ${TARGET_REV} (appears to be a commit SHA)"
  echo "  This prevents Argo CD from detecting updated overlays pushed to branches."
  echo ""
  log_info "Fix: Update ApplicationSet to use {{branch}} instead of {{head_sha}}"
  log_info "Location: k8s/argocd/*.yaml"
  exit 1
fi

# Verify destination namespace matches expected (if provided)
if [[ -n "$TARGET_NS" ]] && [[ "$DEST_NAMESPACE" != "$TARGET_NS" ]]; then
  log_warning "Destination namespace mismatch"
  echo "  Expected: ${TARGET_NS}"
  echo "  Configured: ${DEST_NAMESPACE}"
fi

log_success "Application configuration is valid"
echo ""

# Check 3: No pre-existing sync errors
log_info "Check 3: Sync conditions"

SYNC_ERROR_MSG=$(kubectl get application "${APP_NAME}" -n "$ARGOCD_NS" -o jsonpath='{.status.conditions[?(@.type=="SyncError")].message}' 2>/dev/null || echo "")
if [[ -n "$SYNC_ERROR_MSG" ]]; then
  log_error "Pre-existing sync error condition detected:"
  echo "${SYNC_ERROR_MSG}"
  echo ""
  log_info "Sync conditions:"
  kubectl get application "${APP_NAME}" -n "$ARGOCD_NS" -o jsonpath='{.status.conditions[*]}' 2>/dev/null | jq . 2>/dev/null || \
    kubectl get application "${APP_NAME}" -n "$ARGOCD_NS" -o jsonpath='{.status.conditions}' 2>/dev/null
  exit 1
fi

# Check health and sync status
HEALTH_STATUS=$(kubectl get application "${APP_NAME}" -n "$ARGOCD_NS" -o jsonpath='{.status.health.status}' 2>/dev/null || echo "Unknown")
SYNC_STATUS=$(kubectl get application "${APP_NAME}" -n "$ARGOCD_NS" -o jsonpath='{.status.sync.status}' 2>/dev/null || echo "Unknown")

log_verbose "  Health Status: ${HEALTH_STATUS}"
log_verbose "  Sync Status: ${SYNC_STATUS}"

if [[ "$HEALTH_STATUS" == "Missing" ]] && [[ -n "$TARGET_NS" ]]; then
  # Check if namespace exists
  if ! kubectl get namespace "${TARGET_NS}" &>/dev/null; then
    log_warning "Target namespace '${TARGET_NS}' does not exist yet"
    log_info "This is normal for first-time deployments"
  else
    log_warning "Application health is 'Missing' but namespace exists"
  fi
fi

if [[ "$SYNC_STATUS" == "OutOfSync" ]]; then
  log_verbose "  Application is OutOfSync (expected - about to sync)"
fi

log_success "No blocking sync conditions"
echo ""

# Check 4: Sync operation status
log_info "Check 4: Sync operation status"

OPERATION_STATE=$(kubectl get application "${APP_NAME}" -n "$ARGOCD_NS" -o jsonpath='{.status.operationState.phase}' 2>/dev/null || echo "None")
OPERATION_MSG=$(kubectl get application "${APP_NAME}" -n "$ARGOCD_NS" -o jsonpath='{.status.operationState.message}' 2>/dev/null || echo "")

log_verbose "  Operation State: ${OPERATION_STATE}"
if [[ -n "$OPERATION_MSG" ]]; then
  log_verbose "  Message: ${OPERATION_MSG}"
fi

if [[ "$OPERATION_STATE" == "Running" ]]; then
  log_warning "A sync operation is already in progress"

  # Check how long operation has been running
  STARTED_AT=$(kubectl get application "${APP_NAME}" -n "$ARGOCD_NS" -o jsonpath='{.status.operationState.startedAt}' 2>/dev/null || echo "")
  if [[ -n "$STARTED_AT" ]]; then
    # Try to parse timestamp (may fail on some systems)
    if START_TIME=$(date -d "$STARTED_AT" +%s 2>/dev/null); then
      CURRENT_TIME=$(date +%s)
      ELAPSED=$((CURRENT_TIME - START_TIME))
      log_info "  Operation running for: ${ELAPSED}s"

      if [[ $ELAPSED -gt 300 ]]; then
        log_error "Operation has been running for ${ELAPSED}s (>5 minutes) - likely stuck!"
        echo ""
        log_info "Recommended actions:"
        echo "  1. Check Argo CD controller logs"
        echo "  2. Check for stuck hook jobs: kubectl get jobs -n ${TARGET_NS:-$DEST_NAMESPACE}"
        echo "  3. Force sync abort: kubectl patch application ${APP_NAME} -n $ARGOCD_NS --type merge -p '{\"operation\":null}'"
        exit 1
      fi
    fi
  fi
fi

if [[ "$OPERATION_STATE" == "Failed" ]]; then
  log_error "Last sync operation FAILED"
  echo "Error message: ${OPERATION_MSG}"
  echo ""
  log_info "Full operation state:"
  kubectl get application "${APP_NAME}" -n "$ARGOCD_NS" -o jsonpath='{.status.operationState}' 2>/dev/null | jq . 2>/dev/null || \
    kubectl get application "${APP_NAME}" -n "$ARGOCD_NS" -o jsonpath='{.status.operationState}' 2>/dev/null
  exit 1
fi

log_success "No blocking operations"
echo ""

# Check 5: Resource validation
log_info "Check 5: Resource validation"

MANIFESTS=$(kubectl get application "${APP_NAME}" -n "$ARGOCD_NS" -o jsonpath='{.status.resources[*].kind}' 2>/dev/null || echo "")

if [[ -n "$MANIFESTS" ]]; then
  RESOURCE_COUNT=$(echo "$MANIFESTS" | wc -w)
  log_verbose "  Resource kinds: $(echo "$MANIFESTS" | tr ' ' ', ')"
  log_verbose "  Total resources: ${RESOURCE_COUNT}"
  log_success "Resources can be parsed"
else
  log_warning "No resources found yet (may still be initializing)"
fi

echo ""
log_success "All pre-deployment validation checks passed!"
log_info "Ready to sync - deployment can proceed safely"
exit 0
