#!/usr/bin/env bash
# =============================================================================
# SWA Config Validator
# =============================================================================
# Validates Static Web Apps configuration consistency
# Checks: output_location, token names, build scripts, and lockfile presence

set -uo pipefail

# Source common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$SCRIPT_DIR/common.sh"

# Configuration
SWA_WORKFLOW_FILES="${SWA_WORKFLOW_FILES:-.github/workflows/deploy-prod.yml,.github/workflows/swa-baseline-deploy.yml}"
SWA_APP_DIR="${SWA_APP_DIR:-apps/web}"

# Validation header
log_info "SWA Config Validator"
echo ""

# Check prerequisites
require_command "jq" "apt-get install jq or brew install jq"

ERRORS=0

# Parse workflow files
IFS=',' read -ra WORKFLOW_FILES <<< "$SWA_WORKFLOW_FILES"

# 1. Validate output_location in workflow files
log_info "Checking output_location in SWA workflows..."
for workflow_file in "${WORKFLOW_FILES[@]}"; do
    [[ -z "$workflow_file" ]] && continue

    if [[ ! -f "$workflow_file" ]]; then
        log_error "Workflow file not found: $workflow_file"
        ERRORS=$((ERRORS + 1))
        continue
    fi

    log_verbose "Checking: $workflow_file"

    # Look for output_location lines and check they're empty strings or .next/standalone
    # Valid values: "" (static) or ".next/standalone" (hybrid SSR)
    if grep -q "output_location:" "$workflow_file"; then
        # Extract output_location values
        while IFS= read -r line; do
            # Check if the value is an empty string
            if echo "$line" | grep -qE 'output_location:\s*["\x27]{2}\s*$'; then
                # Empty string - correct (static site mode)
                continue
            elif echo "$line" | grep -qE 'output_location:\s*["\x27]\.next/standalone["\x27]'; then
                # .next/standalone - correct (hybrid SSR mode)
                continue
            elif echo "$line" | grep -qE 'output_location:\s*["\x27][^\x27"]+["\x27]'; then
                # Non-empty, non-standalone string - error
                value=$(echo "$line" | sed -E 's/.*output_location:\s*(["\x27][^\x27"]*["\x27]).*/\1/')
                log_error "Invalid output_location in $workflow_file. Expected empty string or \".next/standalone\", found: $value"
                ERRORS=$((ERRORS + 1))
            fi
        done < <(grep "output_location:" "$workflow_file")
    else
        log_error "No output_location entries found in $workflow_file"
        ERRORS=$((ERRORS + 1))
    fi
done

# 2. Validate SWA token name in SWA workflow files
log_info "Checking SWA token configuration..."
token_found=false

for workflow_file in "${WORKFLOW_FILES[@]}"; do
    [[ -z "$workflow_file" ]] && continue
    [[ ! -f "$workflow_file" ]] && continue

    log_verbose "Checking SWA token in: $workflow_file"

    # Pattern 1: azure_static_web_apps_api_token: ${{ secrets.XXX }}
    if grep -qE '^\s*azure_static_web_apps_api_token:\s*\$\{\{\s*secrets\.' "$workflow_file"; then
        token_name=$(grep -E '^\s*azure_static_web_apps_api_token:' "$workflow_file" | sed -E 's/.*secrets\.([A-Z_]+).*/\1/' | head -1)
        if [[ "$token_name" != "SWA_DEPLOYMENT_TOKEN" ]]; then
            log_error "Invalid SWA token in $workflow_file. Expected SWA_DEPLOYMENT_TOKEN, found: $token_name"
            ERRORS=$((ERRORS + 1))
        else
            token_found=true
        fi
    fi

    # Pattern 2: swa-token: ${{ secrets.XXX }}
    if grep -qE '^\s*swa-token:\s*\$\{\{\s*secrets\.' "$workflow_file"; then
        token_name=$(grep -E '^\s*swa-token:' "$workflow_file" | sed -E 's/.*secrets\.([A-Z_]+).*/\1/' | head -1)
        if [[ "$token_name" != "SWA_DEPLOYMENT_TOKEN" ]]; then
            log_error "Invalid SWA token in $workflow_file. Expected SWA_DEPLOYMENT_TOKEN, found: $token_name"
            ERRORS=$((ERRORS + 1))
        else
            token_found=true
        fi
    fi
done

if [[ "$token_found" == "false" ]]; then
    log_error "Missing SWA deployment token configuration in any of: ${WORKFLOW_FILES[*]}"
    ERRORS=$((ERRORS + 1))
fi

# 3. Validate package.json build script
log_info "Checking package.json build script..."
package_json="$SWA_APP_DIR/package.json"

if [[ ! -f "$package_json" ]]; then
    log_error "package.json not found: $package_json"
    ERRORS=$((ERRORS + 1))
else
    build_script=$(jq -r '.scripts.build // empty' "$package_json")

    if [[ -z "$build_script" ]]; then
        log_error "Missing build script in $package_json"
        ERRORS=$((ERRORS + 1))
    elif [[ ! "$build_script" =~ ^next\ build\ --webpack ]] && [[ ! "$build_script" =~ ^node\ scripts/swa-build\.js ]]; then
        log_error "Invalid build script in $package_json. Expected 'next build --webpack' or 'node scripts/swa-build.js', found: $build_script"
        ERRORS=$((ERRORS + 1))
    fi
fi

# 4. Check for root lockfiles (should not exist)
log_info "Checking for root lockfiles..."
if [[ -f "package.json" ]]; then
    log_error "Root package.json detected. Remove root lockfiles to avoid Next.js output tracing issues in SWA."
    ERRORS=$((ERRORS + 1))
fi

if [[ -f "package-lock.json" ]]; then
    log_error "Root package-lock.json detected. Remove root lockfiles to avoid Next.js output tracing issues in SWA."
    ERRORS=$((ERRORS + 1))
fi

# Summary
echo ""
echo "=========================================="

if [[ $ERRORS -eq 0 ]]; then
    log_success "All SWA configuration checks passed"
    echo ""
    echo "Validated:"
    echo "  - output_location: \"\" or \".next/standalone\""
    echo "  - SWA token: SWA_DEPLOYMENT_TOKEN"
    echo "  - Build script: next build --webpack OR node scripts/swa-build.js"
    echo "  - No root lockfiles"
    exit 0
else
    log_error "Found $ERRORS SWA configuration error(s)"
    echo ""
    echo "SWA Configuration Requirements:"
    echo "  - output_location must be \"\" or \".next/standalone\" in workflow files"
    echo "  - SWA token must be SWA_DEPLOYMENT_TOKEN"
    echo "  - build script must be 'next build --webpack' or 'node scripts/swa-build.js'"
    echo "  - No package.json/package-lock.json at repo root"
    exit 1
fi
