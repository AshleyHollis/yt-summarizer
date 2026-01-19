#!/usr/bin/env bash
# =============================================================================
# Validate Workflow Environment Variable Consistency
# =============================================================================
# Ensures that common environment variables in preview.yml and deploy-prod.yml
# have the same values to prevent drift.
#
# This script validates that shared configuration values (ACR names, image names,
# tool versions, timeouts, etc.) are identical across both workflows.
#
# Usage:
#   ./scripts/ci/validate-workflow-env-consistency.sh
#
# Exit codes:
#   0 - All env vars are consistent
#   1 - Inconsistencies found
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

PREVIEW_WORKFLOW="$REPO_ROOT/.github/workflows/preview.yml"
DEPLOY_PROD_WORKFLOW="$REPO_ROOT/.github/workflows/deploy-prod.yml"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

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

echo "=================================================="
echo "Workflow Environment Variable Consistency Check"
echo "=================================================="
echo ""

for var in "${SHARED_ENV_VARS[@]}"; do
    # Extract env var value from preview.yml (look in env: section)
    preview_value=$(grep -A 100 "^env:" "$PREVIEW_WORKFLOW" | grep "^  $var:" | head -1 | sed "s/^  $var: //")
    
    # Extract env var value from deploy-prod.yml (look in env: section)
    prod_value=$(grep -A 100 "^env:" "$DEPLOY_PROD_WORKFLOW" | grep "^  $var:" | head -1 | sed "s/^  $var: //")
    
    if [[ -z "$preview_value" ]] && [[ -z "$prod_value" ]]; then
        echo -e "${YELLOW}⚠️  WARNING${NC}: $var not found in either workflow"
        continue
    fi
    
    if [[ -z "$preview_value" ]]; then
        echo -e "${RED}❌ ERROR${NC}: $var missing from preview.yml"
        ((errors++))
        continue
    fi
    
    if [[ -z "$prod_value" ]]; then
        echo -e "${RED}❌ ERROR${NC}: $var missing from deploy-prod.yml"
        ((errors++))
        continue
    fi
    
    if [[ "$preview_value" != "$prod_value" ]]; then
        echo -e "${RED}❌ MISMATCH${NC}: $var"
        echo "    preview.yml:     $preview_value"
        echo "    deploy-prod.yml: $prod_value"
        ((errors++))
    else
        echo -e "${GREEN}✓${NC} $var: $preview_value"
    fi
done

echo ""
echo "=================================================="

if [[ $errors -eq 0 ]]; then
    echo -e "${GREEN}✅ All environment variables are consistent!${NC}"
    exit 0
else
    echo -e "${RED}❌ Found $errors inconsistenc(y/ies)${NC}"
    echo ""
    echo "To fix: Update the env vars in either preview.yml or deploy-prod.yml"
    echo "to ensure they have matching values for shared configuration."
    exit 1
fi
