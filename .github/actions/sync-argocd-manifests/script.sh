#!/usr/bin/env bash
# =============================================================================
# GitHub Action Wrapper for Argo CD Manifest Synchronization
# =============================================================================
# This script wraps scripts/sync-argocd-manifests.sh for use in GitHub Actions.
#
# Environment Variables:
#   MODE             - Sync mode: all, infra, apps
#   DRY_RUN          - Perform dry-run: true, false
#   NAMESPACE        - Argo CD namespace
#   VERBOSE          - Enable verbose output: true, false
#   SKIP_VALIDATION  - Skip validation: true, false
# =============================================================================

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

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"

# Build arguments for sync script
ARGS=()

# Mode
case "${MODE:-all}" in
    infra)
        ARGS+=(--infra-only)
        ;;
    apps)
        ARGS+=(--apps-only)
        ;;
    all)
        # Default mode, no flag needed
        ;;
    *)
        log_error "Invalid mode: ${MODE}. Must be 'all', 'infra', or 'apps'"
        echo "::error::Invalid mode: ${MODE}. Must be 'all', 'infra', or 'apps'"
        exit 1
        ;;
esac

# Namespace
if [[ -n "${NAMESPACE:-}" ]] && [[ "${NAMESPACE}" != "argocd" ]]; then
    ARGS+=(--namespace "$NAMESPACE")
fi

# Dry-run
if [[ "${DRY_RUN:-false}" == "true" ]]; then
    ARGS+=(--dry-run)
fi

# Verbose
if [[ "${VERBOSE:-false}" == "true" ]]; then
    ARGS+=(--verbose)
fi

# Skip validation
if [[ "${SKIP_VALIDATION:-false}" == "true" ]]; then
    ARGS+=(--skip-validation)
fi

# Run the sync script
print_header "Sync Argo CD Manifests" \
  "Mode: ${MODE:-all}" \
  "Namespace: ${NAMESPACE:-argocd}" \
  "Dry-run: ${DRY_RUN:-false}" \
  "Verbose: ${VERBOSE:-false}"

log_step "⏳ Running sync script..."

if "$REPO_ROOT/scripts/sync-argocd-manifests.sh" "${ARGS[@]}"; then
    log_success "Sync completed"
    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        echo "applied=false" >> "$GITHUB_OUTPUT"
        print_footer "✅ Dry-run completed successfully (no changes applied)"
    else
        echo "applied=true" >> "$GITHUB_OUTPUT"
        print_footer "✅ Argo CD manifests synced successfully!"
    fi
    exit 0
else
    log_error "Failed to sync Argo CD manifests"
    echo "::error::Failed to sync Argo CD manifests"
    print_footer "❌ Sync failed"
    exit 1
fi
