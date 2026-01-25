#!/usr/bin/env bash
# =============================================================================
# K8s Placeholder Validator
# =============================================================================
# Validates that K8s preview patch files use placeholders instead of hardcoded values
# This prevents deployment issues where patches reference wrong PR numbers or URLs

set -uo pipefail

# Source common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$SCRIPT_DIR/common.sh"

# Configuration - support comma-separated list of directories
K8S_PREVIEW_PATCH_DIR="${K8S_PREVIEW_PATCH_DIR:-k8s/overlays/preview/patches,k8s/overlays/prod/patches}"

# Validation header
log_info "K8s Placeholder Validator"
echo ""

# Parse directories
IFS=',' read -ra PATCH_DIRS <<< "$K8S_PREVIEW_PATCH_DIR"

# Validate directories exist
for dir in "${PATCH_DIRS[@]}"; do
  [[ -z "$dir" ]] && continue
  if [[ ! -d "$dir" ]]; then
    log_error "Patch directory not found: $dir"
    exit 1
  fi
  log_info "Will check: $dir"
done
echo ""

ERRORS=0

# Patterns to detect (hardcoded values that should use placeholders)
declare -A PATTERNS=(
    ["api-pr-[0-9]+"]="Should use __PREVIEW_HOST__ instead of hardcoded 'api-pr-XXX'"
    ["pr-[0-9]+\.yt-summarizer"]="Should use __PREVIEW_HOST__ instead of hardcoded PR URL"
    ["red-grass-[0-9a-f]+-[0-9]+\.eastasia"]="Should use __SWA_URL__ instead of hardcoded SWA URL"
    ["azurestaticapps\.net"]="Should use __SWA_URL__ placeholder for Azure Static Web Apps URLs"
)

# Check each patch file in all directories
for patch_dir in "${PATCH_DIRS[@]}"; do
    [[ -z "$patch_dir" ]] && continue

    log_info "Checking directory: $patch_dir"

    found_files=false
    for patch_file in "$patch_dir"/*.yaml; do
        # Skip if no files found (glob doesn't match)
        [[ -e "$patch_file" ]] || continue

        found_files=true
        filename=$(basename "$patch_file")
        log_verbose "Checking: $filename"

        # Check for each pattern
        for pattern in "${!PATTERNS[@]}"; do
            message="${PATTERNS[$pattern]}"

            if grep -qE "$pattern" "$patch_file"; then
                log_error "Found hardcoded value matching pattern: $pattern"
                echo "     $message"
                echo "     File: $patch_file"
                echo ""

                # Show the matching lines with context
                echo "     Matching lines:"
                grep -nE "$pattern" "$patch_file" | sed 's/^/       /'
                echo ""

                ERRORS=$((ERRORS + 1))
            fi
        done
    done

    if [[ "$found_files" == "false" ]]; then
        log_warning "No .yaml files found in $patch_dir"
    fi
    echo ""
done

echo ""
echo "=========================================="

if [[ $ERRORS -eq 0 ]]; then
    log_success "All patch files use proper placeholders"
    echo ""
    echo "Valid placeholders:"
    echo "  - __PR_NUMBER__    : PR number (e.g., 109)"
    echo "  - __PREVIEW_HOST__ : Preview hostname (e.g., api-pr-109.yt-summarizer.apps.ashleyhollis.com)"
    echo "  - __TLS_SECRET__   : TLS secret name"
    echo "  - __SWA_URL__      : Static Web App URL"
    exit 0
else
    log_error "Found $ERRORS hardcoded value(s) in patch files"
    echo ""
    echo "These values should use placeholders that get substituted during deployment."
    echo "See scripts/ci/generate_preview_kustomization.py for placeholder substitution logic."
    echo ""
    echo "Valid placeholders:"
    echo "  - __PR_NUMBER__    : PR number (e.g., 109)"
    echo "  - __PREVIEW_HOST__ : Preview hostname (e.g., api-pr-109.yt-summarizer.apps.ashleyhollis.com)"
    echo "  - __TLS_SECRET__   : TLS secret name"
    echo "  - __SWA_URL__      : Static Web App URL"
    exit 1
fi
