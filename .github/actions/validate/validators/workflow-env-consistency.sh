#!/usr/bin/env bash
# =============================================================================
# Workflow Environment Variable Consistency Validator
# =============================================================================
# Ensures that common environment variables in preview.yml and deploy-prod.yml
# have the same values to prevent drift.
#
# This validator checks that shared configuration values (ACR names, image names,
# tool versions, timeouts, etc.) are identical across both workflows.
#
# Integrated with .github/actions/validate
# =============================================================================

set -uo pipefail

# Find repository root
REPO_ROOT="${GITHUB_WORKSPACE:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"

PREVIEW_WORKFLOW="$REPO_ROOT/.github/workflows/preview.yml"
DEPLOY_PROD_WORKFLOW="$REPO_ROOT/.github/workflows/deploy-prod.yml"

# Configuration
VERBOSE="${VERBOSE:-false}"

# Color codes for output
BLUE='\033[0;34m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${BLUE}ℹ️  Workflow Environment Variable Consistency Validator${NC}"
echo -e "${BLUE}ℹ️  Checking preview.yml and deploy-prod.yml${NC}"
echo ""

# Shared environment variables that MUST match across workflows
# Format: "ENV_VAR_NAME" (will check that the value is identical)
SHARED_ENV_VARS=(
    "ACR_NAME"
    "ACR_LOGIN_SERVER"
    "APP_NAME"
    "API_IMAGE_NAME"
    "WORKERS_IMAGE_NAME"
    "NAMESPACE_ARGOCD"
    "WORKER_DEPLOYMENTS"
    "HEALTH_CHECK_PATH"
    "HEALTH_CHECK_MAX_ATTEMPTS"
    "HEALTH_CHECK_INTERVAL"
    "HEALTH_CHECK_TIMEOUT"
    "ARGOCD_OPERATION_TIMEOUT_THRESHOLD"
    "ARGOCD_MANIFESTS_PATH"
    "TERRAFORM_WORKING_DIR"
    "TERRAFORM_VERSION"
    "KUSTOMIZE_VERSION"
    "NODE_VERSION"
)

errors=0

for var in "${SHARED_ENV_VARS[@]}"; do
    # Extract env var value from preview.yml (look in env: section)
    preview_value=$(grep -A 100 "^env:" "$PREVIEW_WORKFLOW" | grep "^  $var:" | head -1 | sed "s/^  $var: //")
    
    # Extract env var value from deploy-prod.yml (look in env: section)
    prod_value=$(grep -A 100 "^env:" "$DEPLOY_PROD_WORKFLOW" | grep "^  $var:" | head -1 | sed "s/^  $var: //")
    
    if [[ -z "$preview_value" ]] && [[ -z "$prod_value" ]]; then
        if [[ "$VERBOSE" == "true" ]]; then
            echo -e "${YELLOW}⚠️  $var not found in either workflow${NC}"
        fi
        continue
    fi
    
    if [[ -z "$preview_value" ]]; then
        echo -e "${RED}❌ $var missing from preview.yml${NC}"
        ((errors++))
        continue
    fi

    if [[ -z "$prod_value" ]]; then
        echo -e "${RED}❌ $var missing from deploy-prod.yml${NC}"
        ((errors++))
        continue
    fi
    
    if [[ "$preview_value" != "$prod_value" ]]; then
        echo -e "${RED}❌ MISMATCH: $var${NC}"
        echo -e "    preview.yml:     ${YELLOW}$preview_value${NC}"
        echo -e "    deploy-prod.yml: ${YELLOW}$prod_value${NC}"
        ((errors++))
    else
        if [[ "$VERBOSE" == "true" ]]; then
            echo -e "${GREEN}  ✓ $var${NC}"
        fi
    fi
done

echo ""

if [[ $errors -eq 0 ]]; then
    echo -e "${GREEN}✅ All ${#SHARED_ENV_VARS[@]} environment variables are consistent${NC}"
    exit 0
else
    echo -e "${RED}❌ Found $errors inconsistency/inconsistencies${NC}"
    echo ""
    echo "Fix: Update env vars in preview.yml or deploy-prod.yml to match"
    exit 1
fi
