#!/bin/bash
# =============================================================================
# Write CI execution rationale to workflow summary
# =============================================================================
# Used by: .github/workflows/ci.yml (ci-status job, lines 851-868)
# Purpose: Document why each job ran or skipped for debugging/auditing
#
# Inputs (via environment variables from GitHub Actions):
#   - IS_MAIN_BRANCH: 'true'/'false'
#   - CHANGED_AREAS: space-separated areas that changed
#   - ACR_NAME: Azure Container Registry name
#   - All job results (lint-python, test-api, etc.)
#
# Outputs:
#   - Appends markdown formatted rationale to $GITHUB_STEP_SUMMARY
#
# The rationale explains:
#   1. Execution mode (main branch vs PR)
#   2. Which areas changed
#   3. Why each job ran or skipped
#   4. Build mode (ACR configured vs validation-only)
#
# Exit: Always succeeds (markdown output is purely informational)
# =============================================================================

set -e  # Exit on error

# Format and append rationale to workflow summary
{
  echo "## CI Execution Rationale"
  echo ""
  echo "- Mode: $([[ "$IS_MAIN_BRANCH" == "true" ]] && echo "main branch (full validation)" || echo "PR (change-based)")"
  echo "- Changed areas: $CHANGED_AREAS"
  echo "- Lint Python: $LINT_PYTHON_RESULT (reason: $([[ "$IS_MAIN_BRANCH" == "true" ]] && echo "main branch" || (echo "$CHANGED_AREAS" | grep -qE "(services/api|services/workers|services/shared)" && echo "python changes" || echo "no python changes")))"
  echo "- Lint Frontend: $LINT_FRONTEND_RESULT (reason: $([[ "$IS_MAIN_BRANCH" == "true" ]] && echo "main branch" || (echo "$CHANGED_AREAS" | grep -q "apps/web" && echo "frontend changes" || echo "no frontend changes")))"
  echo "- Security Scans (Python/JS): $SCAN_PYTHON_SECURITY_RESULT/$SCAN_JAVASCRIPT_SECURITY_RESULT"
  echo "- Tests (shared/api/workers/frontend): $TEST_SHARED_RESULT/$TEST_API_RESULT/$TEST_WORKERS_RESULT/$TEST_FRONTEND_RESULT"
  echo "- Build Images: $BUILD_IMAGES_RESULT (ACR: $([[ -n "$ACR_NAME" ]] && echo "configured" || echo "not configured"))"
  echo "- Build Images (validate): $BUILD_IMAGES_VALIDATE_RESULT"
  echo "- Terraform Validate: $VALIDATE_TERRAFORM_RESULT"
  echo "- K8s Validate: $KUBERNETES_VALIDATE_RESULT"
  echo "- Secret Scanning: $SECRET_SCANNING_RESULT"
  echo "- Workflow Validation: $VALIDATE_WORKFLOWS_RESULT (reason: $([[ "$IS_MAIN_BRANCH" == "true" ]] && echo "main branch" || (echo "$CHANGED_AREAS" | grep -q "ci" && echo "ci/workflow changes" || echo "no ci changes")))"
} >> "$GITHUB_STEP_SUMMARY"
