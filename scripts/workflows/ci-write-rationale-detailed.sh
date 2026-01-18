#!/bin/bash

# =============================================================================
# Write CI Execution Rationale to GitHub Step Summary
# =============================================================================
#
# PURPOSE:
#   Generates a detailed markdown summary of the CI pipeline execution,
#   documenting why each job ran or was skipped.
#
# INPUTS (via environment variables from workflow context):
#   IS_MAIN_BRANCH - true if running on main branch
#   CHANGED_AREAS - Space-separated list of changed code areas
#   LINT_PYTHON_RESULT - Result of lint-python job
#   LINT_FRONTEND_RESULT - Result of lint-frontend job
#   SCAN_PYTHON_SECURITY_RESULT - Result of scan-python-security job
#   SCAN_JAVASCRIPT_SECURITY_RESULT - Result of scan-javascript-security job
#   TEST_SHARED_RESULT - Result of test-shared job
#   TEST_API_RESULT - Result of test-api job
#   TEST_WORKERS_RESULT - Result of test-workers job
#   TEST_FRONTEND_RESULT - Result of test-frontend job
#   BUILD_IMAGES_RESULT - Result of build-images job
#   BUILD_IMAGES_VALIDATE_RESULT - Result of build-images-validate job
#   VALIDATE_TERRAFORM_RESULT - Result of validate-terraform job
#   KUBERNETES_VALIDATE_RESULT - Result of kubernetes-validate job
#   SECRET_SCANNING_RESULT - Result of secret-scanning job
#   VALIDATE_WORKFLOWS_RESULT - Result of validate-workflows job
#   ACR_CONFIGURED - true if ACR_NAME is configured
#
# OUTPUTS:
#   Appends to $GITHUB_STEP_SUMMARY for GitHub workflow display
#
# LOGIC:
#   1. Determine execution mode (main branch vs PR)
#   2. Format all job results with their reasons
#   3. Create markdown summary table with all metrics
#   4. Append to GitHub Step Summary
#
# =============================================================================

set -euo pipefail

# Determine mode
if [[ "${IS_MAIN_BRANCH}" == "true" ]]; then
  MODE="main branch (full validation)"
else
  MODE="PR (change-based)"
fi

# Determine linting reasons
LINT_PYTHON_REASON="N/A"
if [[ "${IS_MAIN_BRANCH}" == "true" ]]; then
  LINT_PYTHON_REASON="main branch"
elif [[ "${CHANGED_AREAS}" == *"services/api"* ]] || \
     [[ "${CHANGED_AREAS}" == *"services/workers"* ]] || \
     [[ "${CHANGED_AREAS}" == *"services/shared"* ]]; then
  LINT_PYTHON_REASON="python changes"
else
  LINT_PYTHON_REASON="no python changes"
fi

LINT_FRONTEND_REASON="N/A"
if [[ "${IS_MAIN_BRANCH}" == "true" ]]; then
  LINT_FRONTEND_REASON="main branch"
elif [[ "${CHANGED_AREAS}" == *"apps/web"* ]]; then
  LINT_FRONTEND_REASON="frontend changes"
else
  LINT_FRONTEND_REASON="no frontend changes"
fi

VALIDATE_WORKFLOWS_REASON="N/A"
if [[ "${IS_MAIN_BRANCH}" == "true" ]]; then
  VALIDATE_WORKFLOWS_REASON="main branch"
elif [[ "${CHANGED_AREAS}" == *"ci"* ]]; then
  VALIDATE_WORKFLOWS_REASON="ci/workflow changes"
else
  VALIDATE_WORKFLOWS_REASON="no ci changes"
fi

# Determine if ACR is configured
ACR_INFO="not configured"
if [[ "${ACR_CONFIGURED}" == "true" ]]; then
  ACR_INFO="configured"
fi

# Build the summary
{
  echo "## CI Execution Rationale"
  echo ""
  echo "**Mode:** $MODE"
  echo "**Changed areas:** $CHANGED_AREAS"
  echo ""
  echo "### Job Execution Details"
  echo ""
  echo "| Job | Result | Reason |"
  echo "|-----|--------|--------|"
  echo "| Lint Python | $LINT_PYTHON_RESULT | $LINT_PYTHON_REASON |"
  echo "| Lint Frontend | $LINT_FRONTEND_RESULT | $LINT_FRONTEND_REASON |"
  echo "| Security Scans (Python/JS) | $SCAN_PYTHON_SECURITY_RESULT/$SCAN_JAVASCRIPT_SECURITY_RESULT | Standard scan |"
  echo "| Tests (shared/api/workers/frontend) | $TEST_SHARED_RESULT/$TEST_API_RESULT/$TEST_WORKERS_RESULT/$TEST_FRONTEND_RESULT | Standard tests |"
  echo "| Build Images | $BUILD_IMAGES_RESULT | ACR: $ACR_INFO |"
  echo "| Build Images (validate) | $BUILD_IMAGES_VALIDATE_RESULT | Validation |"
  echo "| Terraform Validate | $VALIDATE_TERRAFORM_RESULT | Standard validation |"
  echo "| K8s Validate | $KUBERNETES_VALIDATE_RESULT | Standard validation |"
  echo "| Secret Scanning | $SECRET_SCANNING_RESULT | Standard scan |"
  echo "| Workflow Validation | $VALIDATE_WORKFLOWS_RESULT | $VALIDATE_WORKFLOWS_REASON |"
} >> "$GITHUB_STEP_SUMMARY"

echo "✅ CI execution rationale written to step summary"
