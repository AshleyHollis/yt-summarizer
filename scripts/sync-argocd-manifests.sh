#!/usr/bin/env bash
# =============================================================================
# Argo CD Manifests Synchronization Script
# =============================================================================
# Applies Argo CD manifest files to the cluster.
# Handles bootstrapping and updating of Argo CD applications and configurations.
#
# Usage:
#   ./scripts/sync-argocd-manifests.sh [options]
#
# Options:
#   -h, --help              Show this help message
#   -d, --dry-run          Show what would be applied without applying
#   -v, --verbose          Enable verbose output
#   -n, --namespace        Argo CD namespace (default: argocd)
#   --skip-validation      Skip pre-apply validation
#
# Exit Codes:
#   0 - All manifests applied successfully
#   1 - Application of manifests failed
#   2 - Validation failed
# =============================================================================

set -uo pipefail

# Configuration
ARGOCD_NAMESPACE="argocd"
DRY_RUN=false
VERBOSE=false
SKIP_VALIDATION=false
K8S_ARGOCD_DIR="k8s/argocd"

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

usage() {
    cat <<EOF
Usage: $(basename "$0") [options]

Options:
  -h, --help              Show this help message
  -d, --dry-run          Show what would be applied without applying
  -v, --verbose          Enable verbose output
  -n, --namespace        Argo CD namespace (default: argocd)
  --skip-validation      Skip pre-apply validation
  --infra-only          Apply only infrastructure apps (infra-apps.yaml)
  --apps-only           Apply only main apps (prod-app.yaml, preview-appset.yaml)

Examples:
  ./scripts/sync-argocd-manifests.sh
  ./scripts/sync-argocd-manifests.sh --dry-run
  ./scripts/sync-argocd-manifests.sh --infra-only -v

EOF
    exit 2
}

# Parse arguments
MODE="all"
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help) usage ;;
        -d|--dry-run) DRY_RUN=true; shift ;;
        -v|--verbose) VERBOSE=true; shift ;;
        -n|--namespace) ARGOCD_NAMESPACE="$2"; shift 2 ;;
        --skip-validation) SKIP_VALIDATION=true; shift ;;
        --infra-only) MODE="infra"; shift ;;
        --apps-only) MODE="apps"; shift ;;
        -*) log_error "Unknown option: $1"; usage ;;
        *) log_error "Unexpected argument: $1"; usage ;;
    esac
done

# =============================================================================
# Pre-Apply Validation
# =============================================================================

validate_prerequisites() {
    log_info "=== Validating Prerequisites ==="

    # Check kubectl
    if ! command -v kubectl &> /dev/null; then
        log_error "kubectl not found. Install kubectl or add it to PATH."
        exit 1
    fi
    log_success "kubectl is available"

    # Check Argo CD namespace
    if ! kubectl get namespace "$ARGOCD_NAMESPACE" &>/dev/null; then
        log_error "Argo CD namespace '$ARGOCD_NAMESPACE' does not exist"
        exit 1
    fi
    log_success "Argo CD namespace '$ARGOCD_NAMESPACE' exists"

    # Check Argo CD CRDs
    if ! kubectl get crd applications.argoproj.io &>/dev/null; then
        log_error "Argo CD CRDs not found. Is Argo CD installed?"
        exit 1
    fi
    log_success "Argo CD CRDs are available"

    # Check if k8s/argocd directory exists
    if [[ ! -d "$K8S_ARGOCD_DIR" ]]; then
        log_error "Argo CD manifests directory not found: $K8S_ARGOCD_DIR"
        exit 1
    fi
    log_success "Argo CD manifests directory found"

    echo ""
}

validate_manifests() {
    log_info "=== Validating Manifest Syntax ==="

    local files=()

    if [[ "$MODE" == "infra" ]] || [[ "$MODE" == "all" ]]; then
        files+=("$K8S_ARGOCD_DIR/infra-apps.yaml")
    fi

    if [[ "$MODE" == "apps" ]] || [[ "$MODE" == "all" ]]; then
        files+=("$K8S_ARGOCD_DIR/prod-app.yaml")
        files+=("$K8S_ARGOCD_DIR/preview-appset.yaml")
    fi

    for file in "${files[@]}"; do
        if [[ ! -f "$file" ]]; then
            log_error "Manifest file not found: $file"
            exit 1
        fi

        # Validate YAML syntax
        if ! kubectl apply -f "$file" --dry-run=client &>/dev/null; then
            log_error "Invalid YAML syntax in $file"
            kubectl apply -f "$file" --dry-run=client 2>&1 | tail -5
            exit 1
        fi

        log_success "Valid manifest: $file"
    done

    echo ""
}

# =============================================================================
# Apply Manifests
# =============================================================================

apply_manifests() {
    log_info "=== Applying Argo CD Manifests ==="
    echo ""

    local files=()

    # Determine which files to apply
    if [[ "$MODE" == "infra" ]] || [[ "$MODE" == "all" ]]; then
        log_info "Mode: Infrastructure applications"
        files+=("$K8S_ARGOCD_DIR/infra-apps.yaml")
    fi

    if [[ "$MODE" == "apps" ]] || [[ "$MODE" == "all" ]]; then
        if [[ "$MODE" == "apps" ]]; then
            log_info "Mode: Main applications only"
        fi
        files+=("$K8S_ARGOCD_DIR/prod-app.yaml")
        files+=("$K8S_ARGOCD_DIR/preview-appset.yaml")
    fi

    echo ""

    # Apply each manifest
    for file in "${files[@]}"; do
        log_info "Processing: $file"

        if [[ "$DRY_RUN" == "true" ]]; then
            log_warning "DRY-RUN: Would apply the following changes:"
            kubectl apply -f "$file" --dry-run=client -o diff 2>&1 | head -50
            if [[ "$VERBOSE" == "true" ]]; then
                kubectl apply -f "$file" --dry-run=client -o diff 2>&1 | tail -n +51
            fi
        else
            # Apply the manifest
            if kubectl apply -f "$file" 2>&1 | tee /tmp/apply-output.txt; then
                # Show what was applied
                grep -E "^(application|applicationset)" /tmp/apply-output.txt | while read -r line; do
                    status=$(echo "$line" | awk '{print $NF}')
                    resource=$(echo "$line" | awk '{print $1}')
                    name=$(echo "$line" | awk '{print $2}' | sed 's/\.argoproj\.io.*//')

                    case "$status" in
                        "created")
                            log_success "$resource created: $name"
                            ;;
                        "configured")
                            log_success "$resource updated: $name"
                            ;;
                        "unchanged")
                            log_info "$resource unchanged: $name"
                            ;;
                        *)
                            log_info "$line"
                            ;;
                    esac
                done
            else
                log_error "Failed to apply manifest: $file"
                exit 1
            fi
        fi

        echo ""
    done

    if [[ "$DRY_RUN" == "true" ]]; then
        log_warning "DRY-RUN mode: No changes were applied"
    fi
}

# =============================================================================
# Post-Apply Validation
# =============================================================================

verify_applications() {
    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "Skipping verification (dry-run mode)"
        return 0
    fi

    log_info "=== Verifying Applied Applications ==="

    sleep 2

    local apps=()

    if [[ "$MODE" == "infra" ]] || [[ "$MODE" == "all" ]]; then
        apps+=("eso-secretstore")
        apps+=("eso-cluster-secretstore")
        apps+=("external-secrets")
        apps+=("cert-manager")
    fi

    if [[ "$MODE" == "apps" ]] || [[ "$MODE" == "all" ]]; then
        apps+=("yt-summarizer-prod")
        apps+=("yt-summarizer-previews")
    fi

    echo ""

    for app in "${apps[@]}"; do
        if kubectl get application "$app" -n "$ARGOCD_NAMESPACE" &>/dev/null; then
            local sync_status health_status
            sync_status=$(kubectl get application "$app" -n "$ARGOCD_NAMESPACE" -o jsonpath='{.status.sync.status}' 2>/dev/null || echo "Unknown")
            health_status=$(kubectl get application "$app" -n "$ARGOCD_NAMESPACE" -o jsonpath='{.status.health.status}' 2>/dev/null || echo "Unknown")

            log_success "Application '$app' exists"
            echo "  Sync Status:   $sync_status"
            echo "  Health Status: $health_status"
        else
            log_warning "Application '$app' not found (may still be creating)"
        fi
    done

    echo ""
    log_info "Application verification complete"
}

# =============================================================================
# Main
# =============================================================================

main() {
    echo "================================================================"
    echo "  Argo CD Manifests Synchronization"
    echo "================================================================"
    echo ""
    echo "Configuration:"
    echo "  Argo CD Namespace: $ARGOCD_NAMESPACE"
    echo "  Manifests Dir:     $K8S_ARGOCD_DIR"
    echo "  Mode:              $MODE"
    echo "  Dry-Run:           $DRY_RUN"
    echo "  Verbose:           $VERBOSE"
    echo ""
    echo "================================================================"
    echo ""

    # Run validations
    if [[ "$SKIP_VALIDATION" != "true" ]]; then
        validate_prerequisites
        validate_manifests
    else
        log_warning "Validation skipped"
        echo ""
    fi

    # Apply manifests
    apply_manifests

    # Verify
    verify_applications

    echo "================================================================"
    log_success "Argo CD manifest synchronization completed!"
    echo "================================================================"
    echo ""
    echo "Next steps:"
    echo "  1. Monitor application sync:"
    echo "     kubectl get applications -n $ARGOCD_NAMESPACE -w"
    echo ""
    echo "  2. Check application details:"
    echo "     kubectl describe application <app-name> -n $ARGOCD_NAMESPACE"
    echo ""
    echo "  3. View Argo CD UI:"
    echo "     kubectl port-forward svc/argocd-server -n $ARGOCD_NAMESPACE 8080:443"
    echo "     https://localhost:8080"
    echo ""
}

main "$@"
