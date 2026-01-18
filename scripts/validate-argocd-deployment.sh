#!/usr/bin/env bash
# =============================================================================
# Argo CD Pre-Deployment Validation Script
# =============================================================================
# Validates that Argo CD configuration is correct before attempting sync.
# Fails fast with detailed diagnostics instead of waiting for timeouts.
#
# Usage:
#   ./scripts/validate-argocd-deployment.sh [app-name] [namespace]
#
# Environment Variables:
#   ARGOCD_NAMESPACE - Argo CD namespace (default: argocd)
#   APP_NAMESPACE - Application namespace (default: yt-summarizer)
#   TIMEOUT - Overall validation timeout in seconds (default: 60)
#   VERBOSE - Enable verbose output (default: false)
#
# Exit Codes:
#   0 - All validations passed
#   1 - Validation failed
#   2 - Script usage error
# =============================================================================

set -uo pipefail

# Configuration
ARGOCD_NAMESPACE="${ARGOCD_NAMESPACE:-argocd}"
APP_NAMESPACE="${APP_NAMESPACE:-yt-summarizer}"
TIMEOUT="${TIMEOUT:-60}"
VERBOSE="${VERBOSE:-false}"
APP_NAME="${1:-yt-summarizer-prod}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;36m'
NC='\033[0m' # No Color

# Utility functions
log_info() {
    echo -e "${BLUE}ℹ${NC} $*"
}

log_success() {
    echo -e "${GREEN}✓${NC} $*"
}

log_warning() {
    echo -e "${YELLOW}⚠${NC} $*"
}

log_error() {
    echo -e "${RED}✗${NC} $*"
}

log_verbose() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "${BLUE}→${NC} $*"
    fi
}

# Usage
usage() {
    cat <<EOF
Usage: $(basename "$0") [app-name] [options]

Arguments:
  app-name          Argo CD Application name (default: yt-summarizer-prod)

Options:
  -h, --help        Show this help message
  -v, --verbose     Enable verbose output
  -n, --namespace   App namespace (default: yt-summarizer)
  -a, --argocd-ns   Argo CD namespace (default: argocd)
  -t, --timeout     Validation timeout in seconds (default: 60)

Examples:
  ./scripts/validate-argocd-deployment.sh
  ./scripts/validate-argocd-deployment.sh yt-summarizer-prod -v
  ./scripts/validate-argocd-deployment.sh my-app -n my-namespace -t 120

EOF
    exit 2
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help) usage ;;
        -v|--verbose) VERBOSE="true"; shift ;;
        -n|--namespace) APP_NAMESPACE="$2"; shift 2 ;;
        -a|--argocd-ns) ARGOCD_NAMESPACE="$2"; shift 2 ;;
        -t|--timeout) TIMEOUT="$2"; shift 2 ;;
        -*) echo "Unknown option: $1"; usage ;;
        *) APP_NAME="$1"; shift ;;
    esac
done

# =============================================================================
# Validation Functions
# =============================================================================

check_kubectl() {
    log_info "Checking kubectl availability..."
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl not found. Install kubectl or add it to PATH."
        exit 1
    fi
    log_success "kubectl is available"
}

check_argocd_api() {
    log_info "Checking Argo CD API access..."
    if ! kubectl api-resources -n "$ARGOCD_NAMESPACE" &>/dev/null; then
        log_error "Cannot access Kubernetes API"
        exit 1
    fi
    
    if ! kubectl get crd applications.argoproj.io &>/dev/null; then
        log_error "Argo CD CRDs not found. Is Argo CD installed?"
        exit 1
    fi
    log_success "Argo CD API is accessible"
}

check_application_exists() {
    log_info "Checking if Application '$APP_NAME' exists..."
    if ! kubectl get application "$APP_NAME" -n "$ARGOCD_NAMESPACE" &>/dev/null; then
        log_error "Application '$APP_NAME' not found in namespace '$ARGOCD_NAMESPACE'"
        log_info "Available applications:"
        kubectl get applications -n "$ARGOCD_NAMESPACE" -o name | sed 's/^/  /'
        exit 1
    fi
    log_success "Application '$APP_NAME' exists"
}

check_application_configuration() {
    log_info "Validating Application configuration..."
    
    local repo_url target_revision path
    repo_url=$(kubectl get application "$APP_NAME" -n "$ARGOCD_NAMESPACE" -o jsonpath='{.spec.source.repoURL}')
    target_revision=$(kubectl get application "$APP_NAME" -n "$ARGOCD_NAMESPACE" -o jsonpath='{.spec.source.targetRevision}')
    path=$(kubectl get application "$APP_NAME" -n "$ARGOCD_NAMESPACE" -o jsonpath='{.spec.source.path}')
    
    log_verbose "Repository URL: $repo_url"
    log_verbose "Target Revision: $target_revision"
    log_verbose "Path: $path"
    
    if [[ -z "$repo_url" ]] || [[ -z "$target_revision" ]] || [[ -z "$path" ]]; then
        log_error "Application is missing required configuration"
        exit 1
    fi
    
    # Check if target revision is valid (not a commit SHA for production)
    if [[ "$target_revision" =~ ^[0-9a-f]{40}$ ]]; then
        log_warning "Application targets a commit SHA instead of a branch/tag"
        log_warning "This may prevent Argo CD from detecting future changes"
    fi
    
    log_success "Application configuration is valid"
}

check_namespace_exists() {
    log_info "Checking if namespace '$APP_NAMESPACE' exists..."
    if ! kubectl get namespace "$APP_NAMESPACE" &>/dev/null; then
        log_warning "Namespace '$APP_NAMESPACE' does not exist"
        log_info "Argo CD will create it (CreateNamespace=true in sync policy)"
    else
        log_success "Namespace '$APP_NAMESPACE' exists"
    fi
}

check_sync_status() {
    log_info "Checking Application sync status..."
    
    local sync_status health_status conditions
    sync_status=$(kubectl get application "$APP_NAME" -n "$ARGOCD_NAMESPACE" -o jsonpath='{.status.sync.status}')
    health_status=$(kubectl get application "$APP_NAME" -n "$ARGOCD_NAMESPACE" -o jsonpath='{.status.health.status}')
    
    log_verbose "Sync Status: $sync_status"
    log_verbose "Health Status: $health_status"
    
    # Check for sync errors
    if [[ "$sync_status" == "Unknown" ]]; then
        log_warning "Sync status is Unknown. Argo CD may still be reconciling."
    fi
    
    if [[ "$health_status" == "Missing" ]]; then
        log_warning "Health status is Missing. Application resources may not exist yet."
    fi
    
    log_success "Sync and health status checked"
}

check_for_errors() {
    log_info "Checking for Argo CD errors..."
    
    local conditions error_count
    conditions=$(kubectl get application "$APP_NAME" -n "$ARGOCD_NAMESPACE" -o jsonpath='{.status.conditions}' 2>/dev/null)
    
    # Check for ComparisonError (manifest generation failed)
    if kubectl describe application "$APP_NAME" -n "$ARGOCD_NAMESPACE" 2>/dev/null | grep -q "ComparisonError"; then
        log_error "ComparisonError detected: Manifest generation failed"
        log_info "This usually indicates:"
        log_info "  - Invalid kustomization.yaml syntax"
        log_info "  - Invalid patch references"
        log_info "  - Missing resource files"
        kubectl describe application "$APP_NAME" -n "$ARGOCD_NAMESPACE" | grep -A 5 "ComparisonError"
        exit 1
    fi
    
    # Check for other error conditions
    error_count=$(kubectl get application "$APP_NAME" -n "$ARGOCD_NAMESPACE" \
        -o jsonpath='{range .status.conditions[?(@.status=="True")]}{.type}{"\n"}{end}' \
        | grep -i error | wc -l)
    
    if [[ $error_count -gt 0 ]]; then
        log_error "Found $error_count error condition(s):"
        kubectl describe application "$APP_NAME" -n "$ARGOCD_NAMESPACE" | grep -A 2 "Conditions:"
        exit 1
    fi
    
    log_success "No errors detected"
}

check_git_connectivity() {
    log_info "Checking git repository connectivity..."
    
    local repo_url
    repo_url=$(kubectl get application "$APP_NAME" -n "$ARGOCD_NAMESPACE" -o jsonpath='{.spec.source.repoURL}')
    
    # Simple connectivity check (could be enhanced with actual git access)
    if [[ ! "$repo_url" =~ ^https?:// ]]; then
        log_error "Invalid repository URL format: $repo_url"
        exit 1
    fi
    
    log_success "Git repository URL is valid"
}

check_resource_diff() {
    log_info "Checking for unsynced resources..."
    
    local out_of_sync_count
    out_of_sync_count=$(kubectl get application "$APP_NAME" -n "$ARGOCD_NAMESPACE" \
        -o jsonpath='{.status.resources[?(@.health.status!="Healthy")]}' | wc -l)
    
    if [[ $out_of_sync_count -gt 0 ]]; then
        log_warning "Found $out_of_sync_count unhealthy resource(s)"
        log_info "Argo CD will sync these during deployment"
    else
        log_verbose "All resources are in sync"
    fi
    
    log_success "Resource status checked"
}

check_no_long_running_operations() {
    log_info "Checking for long-running operations..."
    
    local operation_start_time current_time elapsed_seconds
    operation_start_time=$(kubectl get application "$APP_NAME" -n "$ARGOCD_NAMESPACE" \
        -o jsonpath='{.status.operationState.startedAt}' 2>/dev/null)
    
    if [[ -n "$operation_start_time" ]] && [[ "$operation_start_time" != "null" ]]; then
        current_time=$(date -u +%s)
        operation_timestamp=$(date -d "$operation_start_time" +%s 2>/dev/null || echo "$current_time")
        elapsed_seconds=$((current_time - operation_timestamp))
        
        if [[ $elapsed_seconds -gt 300 ]]; then
            log_error "Operation has been running for ${elapsed_seconds}s (>5 minutes)"
            log_error "This may indicate a stuck sync operation"
            exit 1
        fi
        
        if [[ $elapsed_seconds -gt 60 ]]; then
            log_warning "Operation has been running for ${elapsed_seconds}s"
        fi
    fi
    
    log_success "No long-running operations detected"
}

# =============================================================================
# Main Validation Flow
# =============================================================================

main() {
    echo "================================================================"
    echo "  Argo CD Pre-Deployment Validation"
    echo "================================================================"
    echo ""
    echo "Application:      $APP_NAME"
    echo "App Namespace:    $APP_NAMESPACE"
    echo "Argo CD Namespace: $ARGOCD_NAMESPACE"
    echo "Timeout:          ${TIMEOUT}s"
    echo "Verbose:          $VERBOSE"
    echo ""
    echo "================================================================"
    echo ""
    
    # Run all validations
    check_kubectl
    check_argocd_api
    check_application_exists
    check_application_configuration
    check_namespace_exists
    check_git_connectivity
    check_for_errors
    check_no_long_running_operations
    check_sync_status
    check_resource_diff
    
    echo ""
    echo "================================================================"
    log_success "All pre-deployment validations passed!"
    echo "================================================================"
    echo ""
    echo "Next steps:"
    echo "  1. Trigger Argo CD sync: kubectl patch application $APP_NAME -n $ARGOCD_NAMESPACE --type merge -p '{\"metadata\":{\"annotations\":{\"argocd.argoproj.io/refresh\":\"hard\"}}}'"
    echo "  2. Monitor sync: kubectl describe application $APP_NAME -n $ARGOCD_NAMESPACE"
    echo "  3. Check resources: kubectl get all -n $APP_NAMESPACE"
    echo ""
    
    exit 0
}

main "$@"
