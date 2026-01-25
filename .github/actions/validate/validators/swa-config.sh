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

    # Look for output_location lines and check they're empty strings
    # Match patterns like: output_location: "" or output_location: ''
    if grep -q "output_location:" "$workflow_file"; then
        # Extract output_location values
        while IFS= read -r line; do
            # Check if the value is an empty string
            if echo "$line" | grep -qE 'output_location:\s*["\x27]{2}\s*$'; then
                # Empty string - correct
                continue
            elif echo "$line" | grep -qE 'output_location:\s*["\x27][^\x27"]+["\x27]'; then
                # Non-empty string - error
                value=$(echo "$line" | sed -E 's/.*output_location:\s*(["\x27][^\x27"]*["\x27]).*/\1/')
                log_error "Invalid output_location in $workflow_file. Expected empty string, found: $value"
                ERRORS=$((ERRORS + 1))
            fi
        done < <(grep "output_location:" "$workflow_file")
    else
        log_error "No output_location entries found in $workflow_file"
        ERRORS=$((ERRORS + 1))
    fi
done

# 2. Validate SWA token name in deploy-prod.yml
log_info "Checking SWA token configuration..."
deploy_workflow=".github/workflows/deploy-prod.yml"

if [[ ! -f "$deploy_workflow" ]]; then
    log_error "Deploy workflow not found: $deploy_workflow"
    ERRORS=$((ERRORS + 1))
else
    # Check for azure_static_web_apps_api_token and swa-token patterns
    token_found=false

    # Pattern 1: azure_static_web_apps_api_token: ${{ secrets.XXX }}
    if grep -qE '^\s*azure_static_web_apps_api_token:\s*\$\{\{\s*secrets\.' "$deploy_workflow"; then
        token_name=$(grep -E '^\s*azure_static_web_apps_api_token:' "$deploy_workflow" | sed -E 's/.*secrets\.([A-Z_]+).*/\1/' | head -1)
        if [[ "$token_name" != "SWA_DEPLOYMENT_TOKEN" ]]; then
            log_error "Invalid SWA token in $deploy_workflow. Expected SWA_DEPLOYMENT_TOKEN, found: $token_name"
            ERRORS=$((ERRORS + 1))
        else
            token_found=true
        fi
    fi

    # Pattern 2: swa-token: ${{ secrets.XXX }}
    if grep -qE '^\s*swa-token:\s*\$\{\{\s*secrets\.' "$deploy_workflow"; then
        token_name=$(grep -E '^\s*swa-token:' "$deploy_workflow" | sed -E 's/.*secrets\.([A-Z_]+).*/\1/' | head -1)
        if [[ "$token_name" != "SWA_DEPLOYMENT_TOKEN" ]]; then
            log_error "Invalid SWA token in $deploy_workflow. Expected SWA_DEPLOYMENT_TOKEN, found: $token_name"
            ERRORS=$((ERRORS + 1))
        else
            token_found=true
        fi
    fi

    if [[ "$token_found" == "false" ]]; then
        log_error "Missing SWA deployment token configuration in $deploy_workflow"
        ERRORS=$((ERRORS + 1))
    fi
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
    elif [[ ! "$build_script" =~ ^next\ build\ --webpack ]]; then
        log_error "Invalid build script in $package_json. Expected to start with 'next build --webpack', found: $build_script"
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
    echo "  - output_location: \"\" (empty string)"
    echo "  - SWA token: SWA_DEPLOYMENT_TOKEN"
    echo "  - Build script: next build --webpack"
    echo "  - No root lockfiles"
    exit 0
else
    log_error "Found $ERRORS SWA configuration error(s)"
    echo ""
    echo "SWA Configuration Requirements:"
    echo "  - output_location must be empty string (\"\") in workflow files"
    echo "  - SWA token must be SWA_DEPLOYMENT_TOKEN"
    echo "  - Build script must start with 'next build --webpack'"
    echo "  - No package.json/package-lock.json at repo root"
    exit 1
fi
