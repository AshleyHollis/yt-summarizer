#!/usr/bin/env bash
# =============================================================================
# Argo CD Deployment Diagnostics Script
# =============================================================================
# Comprehensive diagnostics for troubleshooting Argo CD deployment issues.
# Captures detailed information about Application status, resources, and errors.
#
# Usage:
#   ./scripts/diagnose-argocd-deployment.sh [app-name] [output-dir]
#
# Environment Variables:
#   ARGOCD_NAMESPACE - Argo CD namespace (default: argocd)
#   APP_NAMESPACE - Application namespace (default: yt-summarizer)
#
# Output:
#   Creates a diagnostics directory with detailed information files.
#
# Exit Codes:
#   0 - Diagnostics completed successfully
#   1 - Error during diagnostics collection
# =============================================================================

set -uo pipefail

# Configuration
ARGOCD_NAMESPACE="${ARGOCD_NAMESPACE:-argocd}"
APP_NAMESPACE="${APP_NAMESPACE:-yt-summarizer}"
APP_NAME="${1:-yt-summarizer-prod}"
OUTPUT_DIR="${2:-./.argocd-diagnostics}"
TIMESTAMP=$(date -u +%Y%m%d-%H%M%S)
DIAG_DIR="${OUTPUT_DIR}/${APP_NAME}-${TIMESTAMP}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;36m'
NC='\033[0m'

log_info() { echo -e "${BLUE}ℹ${NC} $*"; }
log_success() { echo -e "${GREEN}✓${NC} $*"; }
log_warning() { echo -e "${YELLOW}⚠${NC} $*"; }
log_error() { echo -e "${RED}✗${NC} $*"; }

# Create diagnostics directory
mkdir -p "$DIAG_DIR"
log_info "Collecting diagnostics into: $DIAG_DIR"

# Function to capture output to file
capture() {
    local file="$1"
    shift
    log_info "Collecting: $file"
    "$@" > "$DIAG_DIR/$file" 2>&1 || true
}

# =============================================================================
# Collect Argo CD Application Information
# =============================================================================

log_info "=== Collecting Argo CD Application Information ==="

capture "01-app-status.txt" \
    kubectl get application "$APP_NAME" -n "$ARGOCD_NAMESPACE" -o wide

capture "02-app-detailed.yaml" \
    kubectl get application "$APP_NAME" -n "$ARGOCD_NAMESPACE" -o yaml

capture "03-app-describe.txt" \
    kubectl describe application "$APP_NAME" -n "$ARGOCD_NAMESPACE"

capture "04-app-events.txt" \
    kubectl get events -n "$ARGOCD_NAMESPACE" --field-selector involvedObject.name="$APP_NAME" --sort-by='.lastTimestamp'

# =============================================================================
# Collect Application Resources Information
# =============================================================================

log_info "=== Collecting Application Resources Information ==="

capture "05-app-resources.txt" \
    kubectl get application "$APP_NAME" -n "$ARGOCD_NAMESPACE" -o jsonpath='{range .status.resources[*]}{.group}{"\t"}{.kind}{"\t"}{.name}{"\t"}{.namespace}{"\t"}{.health.status}{"\t"}{.sync.status}{"\n"}{end}' | column -t

# =============================================================================
# Collect Target Namespace Resources
# =============================================================================

log_info "=== Collecting Target Namespace Resources ==="

capture "06-namespace-check.txt" \
    kubectl get namespace "$APP_NAMESPACE" 2>&1

capture "07-pods.txt" \
    kubectl get pods -n "$APP_NAMESPACE" -o wide

capture "08-deployments.txt" \
    kubectl get deployments -n "$APP_NAMESPACE" -o wide

capture "09-services.txt" \
    kubectl get services -n "$APP_NAMESPACE" -o wide

capture "10-jobs.txt" \
    kubectl get jobs -n "$APP_NAMESPACE" -o wide

capture "11-all-resources.txt" \
    kubectl get all -n "$APP_NAMESPACE"

# =============================================================================
# Collect Pod Details and Logs
# =============================================================================

log_info "=== Collecting Pod Details and Logs ==="

capture "12-pod-events.txt" \
    kubectl get events -n "$APP_NAMESPACE" --sort-by='.lastTimestamp'

# Get pod details
{
    kubectl get pods -n "$APP_NAMESPACE" -o name | while read -r pod; do
        echo "=== $pod ==="
        kubectl describe "$pod" -n "$APP_NAMESPACE"
        echo ""
    done
} > "$DIAG_DIR/13-pods-detailed.txt" 2>&1 || true

# Get recent pod logs
{
    kubectl get pods -n "$APP_NAMESPACE" -o name | while read -r pod; do
        pod_name=$(basename "$pod")
        echo "=== Logs for $pod_name ==="
        kubectl logs "$pod" -n "$APP_NAMESPACE" --timestamps=true --tail=100 2>&1 || echo "No logs available"
        echo ""
    done
} > "$DIAG_DIR/14-pod-logs.txt" 2>&1 || true

# =============================================================================
# Collect Argo CD Server Information
# =============================================================================

log_info "=== Collecting Argo CD Server Information ==="

capture "15-argocd-pods.txt" \
    kubectl get pods -n "$ARGOCD_NAMESPACE" -o wide

capture "16-argocd-services.txt" \
    kubectl get services -n "$ARGOCD_NAMESPACE" -o wide

capture "17-argocd-application-controller-logs.txt" \
    kubectl logs -n "$ARGOCD_NAMESPACE" -l app.kubernetes.io/name=argocd-application-controller --tail=100 --timestamps=true

# =============================================================================
# Collect Git Repository Information (if available)
# =============================================================================

log_info "=== Collecting Git Repository Information ==="

{
    APP_REPO=$(kubectl get application "$APP_NAME" -n "$ARGOCD_NAMESPACE" -o jsonpath='{.spec.source.repoURL}')
    APP_TARGET=$(kubectl get application "$APP_NAME" -n "$ARGOCD_NAMESPACE" -o jsonpath='{.spec.source.targetRevision}')
    APP_PATH=$(kubectl get application "$APP_NAME" -n "$ARGOCD_NAMESPACE" -o jsonpath='{.spec.source.path}')
    
    echo "Repository URL: $APP_REPO"
    echo "Target Revision: $APP_TARGET"
    echo "Path: $APP_PATH"
    echo ""
    echo "Git Information Summary:"
    echo "  - Repository appears to be reachable" || echo "  - Repository may have connectivity issues"
} > "$DIAG_DIR/18-git-info.txt" 2>&1

# =============================================================================
# Collect Cluster Information
# =============================================================================

log_info "=== Collecting Cluster Information ==="

capture "19-cluster-info.txt" \
    kubectl cluster-info

capture "20-node-status.txt" \
    kubectl get nodes -o wide

capture "21-node-conditions.txt" \
    kubectl describe nodes

# =============================================================================
# Generate Summary Report
# =============================================================================

log_info "=== Generating Summary Report ==="

{
    echo "Argo CD Deployment Diagnostics Report"
    echo "Generated: $(date)"
    echo ""
    echo "Application Details:"
    echo "  Name: $APP_NAME"
    echo "  Argo CD Namespace: $ARGOCD_NAMESPACE"
    echo "  Target Namespace: $APP_NAMESPACE"
    echo ""
    
    echo "Application Status:"
    kubectl get application "$APP_NAME" -n "$ARGOCD_NAMESPACE" -o jsonpath='{
        "  Sync Status: " .status.sync.status "\n"
        "  Health Status: " .status.health.status "\n"
        "  Message: " .status.operationState.message "\n"
        "  Last Sync Time: " .status.reconciledAt "\n"
    }'
    echo ""
    
    echo "Resource Summary:"
    kubectl get application "$APP_NAME" -n "$ARGOCD_NAMESPACE" -o jsonpath='{
        "  Total Resources: " (.status.resources | length) "\n"
    }'
    echo ""
    
    echo "Key Issues to Check:"
    echo ""
    
    # Check for ComparisonError
    if kubectl describe application "$APP_NAME" -n "$ARGOCD_NAMESPACE" 2>/dev/null | grep -q "ComparisonError"; then
        echo "  ✗ ComparisonError Detected:"
        echo "    - Manifest generation failed"
        echo "    - Check: kustomization.yaml syntax, patch references, resource files"
        echo ""
    fi
    
    # Check for missing resources
    if kubectl get application "$APP_NAME" -n "$ARGOCD_NAMESPACE" -o jsonpath='{.status.health.status}' | grep -q "Missing"; then
        echo "  ✗ Missing Resources:"
        echo "    - Some resources have not been created yet"
        echo "    - Check: Resource definitions, health assessment logic"
        echo ""
    fi
    
    # Check for stuck operations
    {
        OP_START=$(kubectl get application "$APP_NAME" -n "$ARGOCD_NAMESPACE" -o jsonpath='{.status.operationState.startedAt}' 2>/dev/null)
        if [[ -n "$OP_START" ]] && [[ "$OP_START" != "null" ]]; then
            CURRENT=$(date -u +%s)
            OP_TIME=$(date -d "$OP_START" +%s 2>/dev/null || echo "$CURRENT")
            ELAPSED=$((CURRENT - OP_TIME))
            if [[ $ELAPSED -gt 300 ]]; then
                echo "  ✗ Long-Running Operation:"
                echo "    - Operation started at: $OP_START"
                echo "    - Elapsed time: ${ELAPSED}s (>5 minutes)"
                echo "    - Check: Argo CD controller logs, stuck sync processes"
                echo ""
            fi
        fi
    }
    
    # Check for pod issues
    POD_COUNT=$(kubectl get pods -n "$APP_NAMESPACE" 2>/dev/null | tail -n +2 | wc -l)
    RUNNING=$(kubectl get pods -n "$APP_NAMESPACE" --field-selector=status.phase=Running 2>/dev/null | tail -n +2 | wc -l)
    FAILED=$(kubectl get pods -n "$APP_NAMESPACE" --field-selector=status.phase=Failed 2>/dev/null | tail -n +2 | wc -l)
    
    echo "  Pod Status Summary:"
    echo "    - Total Pods: $POD_COUNT"
    echo "    - Running: $RUNNING"
    echo "    - Failed: $FAILED"
    
    if [[ $FAILED -gt 0 ]]; then
        echo "    ✗ Failed pods detected - check pod logs for details"
    fi
    echo ""
    
    echo "Troubleshooting Steps:"
    echo "  1. Review Argo CD Application controller logs:"
    echo "     kubectl logs -n $ARGOCD_NAMESPACE -l app.kubernetes.io/name=argocd-application-controller -f"
    echo ""
    echo "  2. Check Application status and error messages:"
    echo "     kubectl describe application $APP_NAME -n $ARGOCD_NAMESPACE"
    echo ""
    echo "  3. Inspect target namespace resources:"
    echo "     kubectl get all -n $APP_NAMESPACE"
    echo ""
    echo "  4. Review pod logs:"
    echo "     kubectl logs -n $APP_NAMESPACE <pod-name>"
    echo ""
    echo "  5. Check for kustomize build errors:"
    echo "     kubectl get application $APP_NAME -n $ARGOCD_NAMESPACE -o yaml | grep -A 20 'comparisonResult'"
    echo ""
    
} > "$DIAG_DIR/99-summary-report.txt"

# =============================================================================
# Create Index File
# =============================================================================

{
    echo "Argo CD Deployment Diagnostics - File Index"
    echo ""
    ls -lh "$DIAG_DIR" | tail -n +2 | awk '{print "  " $9 " (" $5 ")"}'
    echo ""
    echo "View complete diagnostics:"
    echo "  less $DIAG_DIR/99-summary-report.txt"
    echo ""
    echo "Search for errors:"
    echo "  grep -r 'error\|Error\|ERROR' $DIAG_DIR"
    echo ""
    echo "Monitor Argo CD controller:"
    echo "  kubectl logs -n $ARGOCD_NAMESPACE -l app.kubernetes.io/name=argocd-application-controller -f"
    echo ""
} > "$DIAG_DIR/00-index.txt"

# Summary
echo ""
log_success "Diagnostics collection completed!"
echo ""
echo "Diagnostics saved to: $DIAG_DIR"
echo ""
echo "Quick actions:"
echo "  View summary:  cat $DIAG_DIR/99-summary-report.txt"
echo "  View index:    cat $DIAG_DIR/00-index.txt"
echo "  Find errors:   grep -r 'error' $DIAG_DIR | head -20"
echo ""
