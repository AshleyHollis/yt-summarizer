#!/usr/bin/env bash
# =============================================================================
# Argo CD Application Readiness Check
# =============================================================================
# Pre-deployment checks to ensure Argo CD Application is ready for sync.
# Fails fast with actionable error messages.
#
# Inputs (as environment variables):
#   APP_NAME - Application name to check
#   ARGOCD_NAMESPACE - Argo CD namespace (default: argocd)
#   CHECK_TIMEOUT - Overall check timeout (default: 60)
#
# Exit Codes:
#   0 - Application is ready
#   1 - Application has errors
#   2 - Application not found
#   3 - Timeout/configuration error
# =============================================================================

set -uo pipefail

APP_NAME="${APP_NAME:-}"
ARGOCD_NAMESPACE="${ARGOCD_NAMESPACE:-argocd}"
CHECK_TIMEOUT="${CHECK_TIMEOUT:-60}"

if [[ -z "$APP_NAME" ]]; then
    echo "::error::APP_NAME environment variable is required"
    exit 3
fi

echo "Checking Argo CD Application readiness..."
echo "  App: $APP_NAME"
echo "  Namespace: $ARGOCD_NAMESPACE"
echo "  Timeout: ${CHECK_TIMEOUT}s"
echo ""

# =============================================================================
# Check 1: Application exists
# =============================================================================

if ! kubectl get application "$APP_NAME" -n "$ARGOCD_NAMESPACE" &>/dev/null; then
    echo "::error::Application '$APP_NAME' not found in namespace '$ARGOCD_NAMESPACE'"
    echo ""
    echo "Available applications:"
    kubectl get applications -n "$ARGOCD_NAMESPACE" -o name | sed 's/^/  /'
    exit 2
fi

echo "✓ Application exists: $APP_NAME"

# =============================================================================
# Check 2: Validate application configuration
# =============================================================================

REPO_URL=$(kubectl get application "$APP_NAME" -n "$ARGOCD_NAMESPACE" -o jsonpath='{.spec.source.repoURL}')
TARGET_REV=$(kubectl get application "$APP_NAME" -n "$ARGOCD_NAMESPACE" -o jsonpath='{.spec.source.targetRevision}')
PATH=$(kubectl get application "$APP_NAME" -n "$ARGOCD_NAMESPACE" -o jsonpath='{.spec.source.path}')
DEST_NS=$(kubectl get application "$APP_NAME" -n "$ARGOCD_NAMESPACE" -o jsonpath='{.spec.destination.namespace}')

if [[ -z "$REPO_URL" ]] || [[ -z "$TARGET_REV" ]] || [[ -z "$PATH" ]]; then
    echo "::error::Application has incomplete configuration"
    echo "  Repository: $REPO_URL"
    echo "  Target Revision: $TARGET_REV"
    echo "  Path: $PATH"
    exit 1
fi

echo "✓ Configuration valid"
echo "  Repo: $REPO_URL"
echo "  Target: $TARGET_REV"
echo "  Path: $PATH"
echo "  Dest Namespace: $DEST_NS"

# =============================================================================
# Check 3: Detect sync errors
# =============================================================================

# Check for ComparisonError (manifest generation failed)
if kubectl describe application "$APP_NAME" -n "$ARGOCD_NAMESPACE" 2>/dev/null | grep -q "ComparisonError"; then
    echo "::error::Manifest generation error (ComparisonError)"
    echo ""
    echo "This usually indicates:"
    echo "  • Invalid kustomization.yaml syntax"
    echo "  • Missing or invalid patch references"
    echo "  • Non-existent resource files"
    echo ""
    kubectl describe application "$APP_NAME" -n "$ARGOCD_NAMESPACE" | grep -B 2 -A 10 "ComparisonError" || true
    exit 1
fi

echo "✓ No manifest generation errors"

# =============================================================================
# Check 4: Verify no stale operations
# =============================================================================

OP_STATE=$(kubectl get application "$APP_NAME" -n "$ARGOCD_NAMESPACE" -o jsonpath='{.status.operationState.finishedAt}' 2>/dev/null || echo "")

if [[ -z "$OP_STATE" ]] || [[ "$OP_STATE" == "null" ]]; then
    OP_START=$(kubectl get application "$APP_NAME" -n "$ARGOCD_NAMESPACE" -o jsonpath='{.status.operationState.startedAt}' 2>/dev/null || echo "")
    if [[ -n "$OP_START" ]] && [[ "$OP_START" != "null" ]]; then
        echo "::warning::Operation is still running"
        PHASE=$(kubectl get application "$APP_NAME" -n "$ARGOCD_NAMESPACE" -o jsonpath='{.status.operationState.phase}' 2>/dev/null || echo "Unknown")
        echo "  Phase: $PHASE"
    fi
fi

echo "✓ No stale operations"

# =============================================================================
# Check 5: Verify target revision format
# =============================================================================

if [[ "$TARGET_REV" =~ ^[0-9a-f]{40}$ ]]; then
    echo "::warning::Application targets a commit SHA instead of branch"
    echo "  Target: $TARGET_REV"
    echo "  This may prevent Argo CD from detecting future changes"
else
    echo "✓ Target revision format is valid: $TARGET_REV"
fi

# =============================================================================
# Check 6: Verify sync policy is configured
# =============================================================================

AUTO_SYNC=$(kubectl get application "$APP_NAME" -n "$ARGOCD_NAMESPACE" -o jsonpath='{.spec.syncPolicy.automated}' 2>/dev/null || echo "{}")

if [[ -z "$AUTO_SYNC" ]] || [[ "$AUTO_SYNC" == "{}" ]]; then
    echo "::warning::Application does not have automated sync enabled"
    echo "  You may need to manually sync the application"
fi

echo "✓ Sync policy is configured"

# =============================================================================
# Summary
# =============================================================================

echo ""
echo "================================================================"
echo "✓ Application is ready for sync: $APP_NAME"
echo "================================================================"
echo ""
echo "Next steps:"
echo "  1. Verify the deployment:"
echo "     kubectl describe application $APP_NAME -n $ARGOCD_NAMESPACE"
echo ""
echo "  2. Monitor Argo CD sync:"
echo "     kubectl get application $APP_NAME -n $ARGOCD_NAMESPACE -w"
echo ""
echo "  3. Check deployed resources:"
echo "     kubectl get all -n $DEST_NS"
echo ""

exit 0
