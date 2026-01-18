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
echo "::group::Sync Argo CD Manifests"
echo "Mode: ${MODE:-all}"
echo "Dry-run: ${DRY_RUN:-false}"
echo "Namespace: ${NAMESPACE:-argocd}"
echo "Verbose: ${VERBOSE:-false}"
echo ""

if "$REPO_ROOT/scripts/sync-argocd-manifests.sh" "${ARGS[@]}"; then
    if [[ "${DRY_RUN:-false}" == "true" ]]; then
        echo "applied=false" >> "$GITHUB_OUTPUT"
    else
        echo "applied=true" >> "$GITHUB_OUTPUT"
    fi
    echo "::endgroup::"
    exit 0
else
    echo "::endgroup::"
    echo "::error::Failed to sync Argo CD manifests"
    exit 1
fi
