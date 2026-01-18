#!/bin/bash
# =============================================================================
# Write production deployment execution rationale to workflow summary
# =============================================================================
# Used by: .github/workflows/deploy-prod.yml (summary job, lines 623-636)
# Purpose: Document why production deployment succeeded, failed, or was skipped
#
# Inputs (via environment variables from GitHub Actions):
#   - CHANGED_AREAS: space-separated areas that changed
#   - All job results (wait-for-ci, terraform-plan, update-overlay, etc.)
#   - IMAGE_TAG: The image tag that was deployed
#
# Outputs:
#   - Appends markdown formatted rationale to $GITHUB_STEP_SUMMARY
#
# Documents:
#   1. Which areas changed
#   2. CI wait result
#   3. Terraform plan/apply results and whether changes exist
#   4. Image tag selected (CI-built vs. existing)
#   5. Overlay update status
#   6. Frontend and health check results
#
# Exit: Always succeeds (markdown output is purely informational)
# =============================================================================

set -e  # Exit on error

CHANGED_AREAS="${1}"
WAIT_FOR_CI_RESULT="${2}"
TERRAFORM_PLAN_RESULT="${3}"
TERRAFORM_APPLY_RESULT="${4}"
HAS_TERRAFORM_CHANGES="${5}"
CI_IMAGE_TAG="${6}"
PROD_IMAGE_TAG="${7}"
UPDATE_OVERLAY_RESULT="${8}"
DEPLOY_FRONTEND_RESULT="${9}"
HEALTH_CHECK_RESULT="${10}"

# Format and append rationale to workflow summary
{
  echo "## Prod Deployment Rationale"
  echo ""
  echo "- Changed areas: $CHANGED_AREAS"
  echo "- Wait for CI: $WAIT_FOR_CI_RESULT"
  echo "- Terraform plan: $TERRAFORM_PLAN_RESULT (changes: $([ "$HAS_TERRAFORM_CHANGES" = "true" ] && echo "yes" || echo "no"))"
  echo "- Terraform apply: $TERRAFORM_APPLY_RESULT (reason: $([ "$TERRAFORM_PLAN_RESULT" = "success" ] && [ "$HAS_TERRAFORM_CHANGES" = "true" ] && echo "plan has changes" || echo "no changes"))"
  echo "- Backend deploy tag: $([ -n "$CI_IMAGE_TAG" ] && echo "$CI_IMAGE_TAG" || echo "$PROD_IMAGE_TAG") ($([ -n "$CI_IMAGE_TAG" ] && echo "CI-built" || echo "existing"))"
  echo "- Overlay update: $UPDATE_OVERLAY_RESULT"
  echo "- Frontend deploy: $DEPLOY_FRONTEND_RESULT"
  echo "- Health check: $HEALTH_CHECK_RESULT"
} >> "$GITHUB_STEP_SUMMARY"
