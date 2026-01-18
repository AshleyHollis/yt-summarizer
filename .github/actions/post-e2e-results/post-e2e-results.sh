#!/bin/bash
# Purpose: Creates GitHub Actions step summary for E2E test results
# Inputs:
#   TEST_OUTCOME: Test outcome (success/failure)
#   PREVIEW_URL: Preview environment URL where tests ran
#   COMMIT_SHA: Commit SHA tested
# Outputs: None (writes to $GITHUB_STEP_SUMMARY)
# Logic:
#   1. Determine success/failure based on TEST_OUTCOME
#   2. Write header with appropriate emoji
#   3. Add test environment and artifact information
#   4. Provide troubleshooting tips if tests failed

set -euo pipefail

TEST_OUTCOME="${TEST_OUTCOME:-}"
PREVIEW_URL="${PREVIEW_URL:-}"
COMMIT_SHA="${COMMIT_SHA:-}"

if [ "$TEST_OUTCOME" = "success" ]; then
  echo "## ✅ E2E Tests Passed" >> $GITHUB_STEP_SUMMARY
  echo "" >> $GITHUB_STEP_SUMMARY
  echo "All end-to-end tests completed successfully!" >> $GITHUB_STEP_SUMMARY
else
  echo "## ❌ E2E Tests Failed" >> $GITHUB_STEP_SUMMARY
  echo "" >> $GITHUB_STEP_SUMMARY
  echo "Some tests failed. Check the Playwright report artifact for details." \
    >> $GITHUB_STEP_SUMMARY
fi
echo "" >> $GITHUB_STEP_SUMMARY
echo "### Test Environment" >> $GITHUB_STEP_SUMMARY
echo "" >> $GITHUB_STEP_SUMMARY
echo "| Property | Value |" >> $GITHUB_STEP_SUMMARY
echo "|----------|-------|" >> $GITHUB_STEP_SUMMARY
echo "| **Preview URL** | $PREVIEW_URL |" >> $GITHUB_STEP_SUMMARY
echo "| **Commit** | \`$COMMIT_SHA\` |" >> $GITHUB_STEP_SUMMARY
echo "" >> $GITHUB_STEP_SUMMARY
echo "### Artifacts" >> $GITHUB_STEP_SUMMARY
echo "" >> $GITHUB_STEP_SUMMARY
echo "- 📦 **Playwright Report**: Available in workflow artifacts" >> \
  $GITHUB_STEP_SUMMARY
echo "" >> $GITHUB_STEP_SUMMARY
