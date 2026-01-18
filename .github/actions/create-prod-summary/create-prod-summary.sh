#!/bin/bash
# Purpose: Creates a GitHub Actions step summary for production deployments
# Inputs:
#   IMAGE_TAG: Docker image tag deployed
#   COMMIT_SHA: Git commit SHA
#   UPDATE_OVERLAY_RESULT: Result of update-overlay job
#   DEPLOY_FRONTEND_RESULT: Result of deploy-frontend job
#   HEALTH_CHECK_RESULT: Result of health-check job
# Outputs: None (writes to $GITHUB_STEP_SUMMARY)
# Logic:
#   1. Write header and deployment details table
#   2. Extract job results and show status
#   3. Determine overall success by checking all job results
#   4. Write success/failure summary message

set -euo pipefail

IMAGE_TAG="${IMAGE_TAG:-}"
COMMIT_SHA="${COMMIT_SHA:-}"
UPDATE_OVERLAY_RESULT="${UPDATE_OVERLAY_RESULT:-}"
DEPLOY_FRONTEND_RESULT="${DEPLOY_FRONTEND_RESULT:-}"
HEALTH_CHECK_RESULT="${HEALTH_CHECK_RESULT:-}"

echo "# 🚀 Production Deployment Summary" >> $GITHUB_STEP_SUMMARY
echo "" >> $GITHUB_STEP_SUMMARY
echo "## Deployment Details" >> $GITHUB_STEP_SUMMARY
echo "| Property | Value |" >> $GITHUB_STEP_SUMMARY
echo "|----------|-------|" >> $GITHUB_STEP_SUMMARY
echo "| **Image Tag** | \`${IMAGE_TAG}\` |" >> $GITHUB_STEP_SUMMARY
echo "| **Commit** | \`${COMMIT_SHA}\` |" >> $GITHUB_STEP_SUMMARY
echo "| **Timestamp** | $(date -u +"%Y-%m-%d %H:%M:%S UTC") |" >> \
  $GITHUB_STEP_SUMMARY
echo "" >> $GITHUB_STEP_SUMMARY

echo "## Job Status" >> $GITHUB_STEP_SUMMARY
echo "| Job | Status |" >> $GITHUB_STEP_SUMMARY
echo "|-----|--------|" >> $GITHUB_STEP_SUMMARY
if [ "$UPDATE_OVERLAY_RESULT" = "success" ]; then
  echo "| Update Overlay | ✅ Success |" >> $GITHUB_STEP_SUMMARY
else
  echo "| Update Overlay | ❌ Failed |" >> $GITHUB_STEP_SUMMARY
fi
if [ "$DEPLOY_FRONTEND_RESULT" = "success" ]; then
  echo "| Deploy Frontend | ✅ Success |" >> $GITHUB_STEP_SUMMARY
else
  echo "| Deploy Frontend | ❌ Failed |" >> $GITHUB_STEP_SUMMARY
fi
if [ "$HEALTH_CHECK_RESULT" = "success" ]; then
  echo "| Health Check | ✅ Success |" >> $GITHUB_STEP_SUMMARY
else
  echo "| Health Check | ❌ Failed |" >> $GITHUB_STEP_SUMMARY
fi
echo "" >> $GITHUB_STEP_SUMMARY

if [ "$UPDATE_OVERLAY_RESULT" = "success" ] && \
   [ "$DEPLOY_FRONTEND_RESULT" = "success" ] && \
   [ "$HEALTH_CHECK_RESULT" = "success" ]; then
  echo "## ✅ Deployment Successful" >> $GITHUB_STEP_SUMMARY
  echo "" >> $GITHUB_STEP_SUMMARY
  echo "Production environment updated successfully." >> $GITHUB_STEP_SUMMARY
else
  echo "## ❌ Deployment Failed" >> $GITHUB_STEP_SUMMARY
  echo "" >> $GITHUB_STEP_SUMMARY
  echo "One or more deployment steps failed. Check job logs for details." >> \
    $GITHUB_STEP_SUMMARY
fi
