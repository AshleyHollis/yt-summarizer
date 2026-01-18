#!/bin/bash

################################################################################
# Action: check-preview-status / script.sh
#
# Purpose: Validates preview pipeline results and creates status summary.
#          Checks all deployment jobs and reports final status to GitHub.
#
# Inputs (Environment Variables):
#   NEEDS_IMAGE_BUILD          - Whether PR needs image build (true/false)
#   NEEDS_DEPLOYMENT           - Whether PR needs deployment (true/false)
#   UPDATE_OVERLAY_RESULT      - Result of update-overlay job
#   VERIFY_DEPLOYMENT_RESULT   - Result of verify-deployment job
#   DEPLOY_FRONTEND_RESULT     - Result of deploy-frontend-preview job
#   E2E_TESTS_RESULT           - Result of e2e-tests job
#   API_URL_CONFIGURED         - Whether API URL is configured
#   WAIT_FOR_CI_RESULT         - Result of wait-for-ci job
#
# Outputs:
#   Exit code 0 - Preview pipeline succeeded
#   Exit code 1 - Preview pipeline failed
#
# Logic Flow:
#   1. If no deployment needed (docs-only PR), mark as success and exit
#   2. Check all critical jobs (wait-for-ci, update-overlay, etc.)
#   3. Determine E2E test status (skipped/passed/failed)
#   4. Build status table for GitHub summary
#   5. Report errors if any critical jobs failed
#   6. Exit with appropriate code
#
################################################################################

set -euo pipefail

# Track if any critical jobs failed
HAS_FAILURES=false

# If no deployment needed, mark as success (docs-only PR)
if [ "$NEEDS_DEPLOYMENT" != "true" ]; then
  echo "## Preview Pipeline Status" >> $GITHUB_STEP_SUMMARY
  echo "" >> $GITHUB_STEP_SUMMARY
  echo "📝 No deployment needed - docs-only PR" >> \
    $GITHUB_STEP_SUMMARY
  echo "| Job | Status |" >> $GITHUB_STEP_SUMMARY
  echo "|-----|--------|" >> $GITHUB_STEP_SUMMARY
  echo "| Detect Changes | ✅ No deployment needed |" >> \
    $GITHUB_STEP_SUMMARY
  echo "" >> $GITHUB_STEP_SUMMARY
  echo "✅ Preview pipeline completed successfully!" >> \
    $GITHUB_STEP_SUMMARY
  exit 0
fi

echo "## Preview Pipeline Status" >> $GITHUB_STEP_SUMMARY
echo "" >> $GITHUB_STEP_SUMMARY

# Check Wait for CI status (critical if images need to be built)
if [ "$NEEDS_IMAGE_BUILD" = "true" ]; then
  if [ "$WAIT_FOR_CI_RESULT" != "success" ]; then
    echo "::error::CI workflow failed - cannot proceed with deployment"
    HAS_FAILURES=true
  fi
fi

# Check required deployment jobs
if [ "$UPDATE_OVERLAY_RESULT" != "success" ] && \
   [ "$UPDATE_OVERLAY_RESULT" != "skipped" ]; then
  echo "::error::Update overlay failed"
  HAS_FAILURES=true
fi

if [ "$VERIFY_DEPLOYMENT_RESULT" != "success" ] && \
   [ "$VERIFY_DEPLOYMENT_RESULT" != "skipped" ]; then
  echo "::error::Deployment verification failed"
  HAS_FAILURES=true
fi

if [ "$DEPLOY_FRONTEND_RESULT" != "success" ] && \
   [ "$DEPLOY_FRONTEND_RESULT" != "skipped" ]; then
  echo "::error::Frontend deployment failed"
  HAS_FAILURES=true
fi

# Determine E2E test status display
if [ -z "$API_URL_CONFIGURED" ]; then
  E2E_STATUS="⏭️ Skipped (no API URL)"
elif [ "$E2E_TESTS_RESULT" = "success" ]; then
  E2E_STATUS="✅ Passed"
elif [ "$E2E_TESTS_RESULT" = "skipped" ]; then
  E2E_STATUS="⏭️ Skipped"
elif [ "$E2E_TESTS_RESULT" = "failure" ]; then
  E2E_STATUS="❌ Failed"
  echo "::error::E2E tests failed"
  HAS_FAILURES=true
else
  E2E_STATUS="⏭️ Skipped"
fi

# Display status table
echo "| Job | Status |" >> $GITHUB_STEP_SUMMARY
echo "|-----|--------|" >> $GITHUB_STEP_SUMMARY

if [ "$NEEDS_IMAGE_BUILD" = "true" ]; then
  if [ "$WAIT_FOR_CI_RESULT" = "success" ]; then
    echo "| Wait for CI | ✅ Success |" >> $GITHUB_STEP_SUMMARY
  elif [ "$WAIT_FOR_CI_RESULT" = "failure" ]; then
    echo "| Wait for CI | ❌ Failed |" >> $GITHUB_STEP_SUMMARY
  else
    echo "| Wait for CI | ⏭️ Skipped |" >> $GITHUB_STEP_SUMMARY
  fi
fi

if [ "$UPDATE_OVERLAY_RESULT" = "success" ]; then
  echo "| Update Overlay | ✅ Success |" >> $GITHUB_STEP_SUMMARY
elif [ "$UPDATE_OVERLAY_RESULT" = "failure" ]; then
  echo "| Update Overlay | ❌ Failed |" >> $GITHUB_STEP_SUMMARY
else
  echo "| Update Overlay | ⏭️ Skipped |" >> $GITHUB_STEP_SUMMARY
fi

if [ "$VERIFY_DEPLOYMENT_RESULT" = "success" ]; then
  echo "| Verify Deployment | ✅ Success |" >> $GITHUB_STEP_SUMMARY
elif [ "$VERIFY_DEPLOYMENT_RESULT" = "failure" ]; then
  echo "| Verify Deployment | ❌ Failed |" >> $GITHUB_STEP_SUMMARY
else
  echo "| Verify Deployment | ⏭️ Skipped |" >> $GITHUB_STEP_SUMMARY
fi

if [ "$DEPLOY_FRONTEND_RESULT" = "success" ]; then
  echo "| Deploy Frontend | ✅ Success |" >> $GITHUB_STEP_SUMMARY
elif [ "$DEPLOY_FRONTEND_RESULT" = "failure" ]; then
  echo "| Deploy Frontend | ❌ Failed |" >> $GITHUB_STEP_SUMMARY
else
  echo "| Deploy Frontend | ⏭️ Skipped |" >> $GITHUB_STEP_SUMMARY
fi

echo "| E2E Tests | ${E2E_STATUS} |" >> $GITHUB_STEP_SUMMARY
echo "" >> $GITHUB_STEP_SUMMARY

# Fail the check if any critical jobs failed
if [ "$HAS_FAILURES" = "true" ]; then
  echo "❌ Preview pipeline failed!" >> $GITHUB_STEP_SUMMARY
  echo "" >> $GITHUB_STEP_SUMMARY
  echo "Please check the errors above and fix the issues before deploying." >> \
    $GITHUB_STEP_SUMMARY
  exit 1
fi

# Warning if no API URL configured
if [ -z "$API_URL_CONFIGURED" ]; then
  echo "⚠️ Preview deployed without backend API" >> $GITHUB_STEP_SUMMARY
  echo "" >> $GITHUB_STEP_SUMMARY
  echo "To enable full preview functionality:" >> $GITHUB_STEP_SUMMARY
  echo "1. Set \`PREVIEW_API_URL\` in repository variables" >> \
    $GITHUB_STEP_SUMMARY
  echo "2. Re-run this workflow" >> $GITHUB_STEP_SUMMARY
  echo "" >> $GITHUB_STEP_SUMMARY
fi

echo "✅ Preview pipeline completed successfully!" >> $GITHUB_STEP_SUMMARY
