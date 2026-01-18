#!/bin/bash
# =============================================================================
# Write preview deployment execution rationale to workflow summary
# =============================================================================
# Used by: .github/workflows/preview.yml (preview-status-check job, lines 1042-1057)
# Purpose: Document why preview deployment succeeded, failed, or was skipped
#
# Inputs (via environment variables from GitHub Actions):
#   - NEEDS_DEPLOYMENT: 'true'/'false'
#   - NEEDS_IMAGE_BUILD: 'true'/'false'
#   - INFRA_CHANGED: 'true'/'false'
#   - All job results (terraform, wait-for-ci, verify-deployment, etc.)
#
# Outputs:
#   - Appends markdown formatted rationale to $GITHUB_STEP_SUMMARY
#
# Documents:
#   1. Whether preview deployment was needed
#   2. Image build requirement (code changes vs k8s-only)
#   3. Terraform plan/apply results
#   4. Deployment verification status
#   5. E2E test results
#   6. Overall outcome
#
# Exit: Always succeeds (markdown output is purely informational)
# =============================================================================

set -e  # Exit on error

# Format and append rationale to workflow summary
{
  echo "## Preview Execution Rationale"
  echo ""
  echo "- Needs deployment: $NEEDS_DEPLOYMENT"
  echo "- Needs image build: $NEEDS_IMAGE_BUILD"
  echo "- Infra changed: $INFRA_CHANGED"
  echo "- Terraform plan: $TERRAFORM_RESULT (changes: $([ "$TERRAFORM_HAS_CHANGES" = "true" ] && echo "yes" || echo "no"), reason: $([ "$EVENT_NAME" = "workflow_dispatch" ] && [ "$RUN_TERRAFORM" = "true" ] && echo "manual request" || ([ "$INFRA_CHANGED" = "true" ] && echo "infra changes" || echo "not requested")))"
  echo "- Wait for CI: $WAIT_FOR_CI_RESULT (reason: $([ "$NEEDS_DEPLOYMENT" = "true" ] && echo "deployment needed" || echo "no deployment"))"
  echo "- Concurrency gate: $CONCURRENCY_RESULT"
  echo "- Overlay update: $OVERLAY_RESULT"
  echo "- Backend verify: $VERIFY_DEPLOYMENT_RESULT"
  echo "- Frontend deploy: $DEPLOY_FRONTEND_RESULT"
  echo "- E2E tests: $E2E_TESTS_RESULT"
} >> "$GITHUB_STEP_SUMMARY"
