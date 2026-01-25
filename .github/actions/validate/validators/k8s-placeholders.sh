#!/usr/bin/env bash
# =============================================================================
# K8s Placeholder Validator
# =============================================================================
# Validates that K8s patch files don't contain hardcoded environment-specific values
# Note: Preview uses inline patches (no patch files), prod uses file-based patches
# This validator only checks prod patches for hardcoded values

set -uo pipefail

# Source common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$SCRIPT_DIR/common.sh"

# Configuration - only check prod patches (preview uses inline patches)
K8S_PREVIEW_PATCH_DIR="${K8S_PREVIEW_PATCH_DIR:-k8s/overlays/prod/patches}"

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

# Patterns to detect (hardcoded environment-specific values)
# These patterns check for values that should be environment-agnostic
declare -A PATTERNS=(
    ["api-pr-[0-9]+"]="Found PR-specific hostname (should be environment-agnostic)"
    ["pr-[0-9]+\.yt-summarizer"]="Found PR-specific URL (should be environment-agnostic)"
    ["red-grass-[0-9a-f]+-[0-9]+\.eastasia"]="Found hardcoded SWA URL (should be environment-agnostic)"
    ["preview-pr-[0-9]+"]="Found PR-specific namespace (should be environment-agnostic)"
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
    log_success "All patch files are environment-agnostic"
    echo ""
    echo "Note: Preview environment uses inline patches in kustomization template."
    echo "      Production patches should not contain environment-specific values."
    exit 0
else
    log_error "Found $ERRORS hardcoded environment-specific value(s) in patch files"
    echo ""
    echo "Patch files should be environment-agnostic and not contain:"
    echo "  - PR numbers or PR-specific URLs"
    echo "  - Hardcoded SWA URLs"
    echo "  - Preview-specific namespaces"
    echo ""
    echo "For preview environments, use inline patches with placeholders in the template."
    echo "See scripts/ci/templates/preview-kustomization-template.yaml"
    exit 1
fi
