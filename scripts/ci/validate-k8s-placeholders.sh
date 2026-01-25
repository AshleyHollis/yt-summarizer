#!/bin/bash
# Validate that K8s preview patch files use placeholders instead of hardcoded values
# This prevents deployment issues where patches reference wrong PR numbers or URLs

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PATCH_DIR="$REPO_ROOT/k8s/overlays/preview/patches"

echo "🔍 Validating K8s preview patch files for hardcoded values..."
echo "Patch directory: $PATCH_DIR"
echo ""

ERRORS=0

# Patterns to detect (hardcoded values that should use placeholders)
declare -A PATTERNS=(
    ["api-pr-[0-9]+"]="Should use __PREVIEW_HOST__ instead of hardcoded 'api-pr-XXX'"
    ["pr-[0-9]+\.yt-summarizer"]="Should use __PREVIEW_HOST__ instead of hardcoded PR URL"
    ["red-grass-[0-9a-f]+-[0-9]+\.eastasia"]="Should use __SWA_URL__ instead of hardcoded SWA URL"
    ["azurestaticapps\.net"]="Should use __SWA_URL__ placeholder for Azure Static Web Apps URLs"
)

# Check each patch file
for patch_file in "$PATCH_DIR"/*.yaml; do
    filename=$(basename "$patch_file")
    echo "Checking: $filename"

    # Check for each pattern
    for pattern in "${!PATTERNS[@]}"; do
        message="${PATTERNS[$pattern]}"

        if grep -qE "$pattern" "$patch_file"; then
            echo "  ❌ ERROR: Found hardcoded value matching pattern: $pattern"
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

echo ""
echo "=========================================="

if [ $ERRORS -eq 0 ]; then
    echo "✅ SUCCESS: All preview patch files use proper placeholders"
    echo ""
    echo "Valid placeholders:"
    echo "  - __PR_NUMBER__    : PR number (e.g., 109)"
    echo "  - __PREVIEW_HOST__ : Preview hostname (e.g., api-pr-109.yt-summarizer.apps.ashleyhollis.com)"
    echo "  - __TLS_SECRET__   : TLS secret name"
    echo "  - __SWA_URL__      : Static Web App URL"
    exit 0
else
    echo "❌ FAILURE: Found $ERRORS hardcoded value(s) in preview patch files"
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
