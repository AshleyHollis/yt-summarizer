#!/bin/bash
################################################################################
# Action: post-preview-comment / post-preview-comment.sh
#
# Purpose: Creates GitHub Actions step summary for preview deployment
#
# Inputs (Environment Variables):
#   PR_NUMBER    - Pull request number
#   PREVIEW_URL  - Preview environment URL
#   FRONTEND_URL - Frontend preview URL (optional)
#   IMAGE_TAG    - Docker image tag deployed
#   COMMIT_SHA   - Commit SHA deployed
#
# Outputs: None (writes to $GITHUB_STEP_SUMMARY)
#
# Logic:
#   1. Write header with deployment title
#   2. Add environment URLs table
#   3. Add deployment details (PR, image tag, commit)
#   4. Include deployment timestamp
################################################################################

set -euo pipefail

PR_NUMBER="${PR_NUMBER:-}"
PREVIEW_URL="${PREVIEW_URL:-}"
FRONTEND_URL="${FRONTEND_URL:-}"
IMAGE_TAG="${IMAGE_TAG:-}"
COMMIT_SHA="${COMMIT_SHA:-}"

################################################################################
# Header
################################################################################
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║  Post Preview Comment                                                        ║"
echo "╠══════════════════════════════════════════════════════════════════════════════╣"
echo "║  PR Number:   #${PR_NUMBER}"
echo "║  Preview URL: ${PREVIEW_URL}"
echo "║  Image Tag:   ${IMAGE_TAG}"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""

################################################################################
# Generate step summary
################################################################################
echo "[INFO] ⏳ Generating GitHub step summary..."

echo "## 🚀 Preview Deployment Summary" >> $GITHUB_STEP_SUMMARY
echo "" >> $GITHUB_STEP_SUMMARY
echo "### 🌐 Environment URLs" >> $GITHUB_STEP_SUMMARY
echo "" >> $GITHUB_STEP_SUMMARY
echo "| Environment | URL |" >> $GITHUB_STEP_SUMMARY
echo "|-------------|-----|" >> $GITHUB_STEP_SUMMARY
echo "| **Backend API** | [$PREVIEW_URL]($PREVIEW_URL) |" >> $GITHUB_STEP_SUMMARY

if [ -n "$FRONTEND_URL" ]; then
  echo "| **Frontend** | [$FRONTEND_URL]($FRONTEND_URL) |" >> $GITHUB_STEP_SUMMARY
  echo "[INFO] ✓ Frontend URL included"
fi

echo "| **Health Check** | [$PREVIEW_URL/health/live]($PREVIEW_URL/health/live) |" >> $GITHUB_STEP_SUMMARY
echo "| **API Docs** | [$PREVIEW_URL/docs]($PREVIEW_URL/docs) |" >> $GITHUB_STEP_SUMMARY
echo "" >> $GITHUB_STEP_SUMMARY
echo "### 📦 Deployment Details" >> $GITHUB_STEP_SUMMARY
echo "" >> $GITHUB_STEP_SUMMARY
echo "| Property | Value |" >> $GITHUB_STEP_SUMMARY
echo "|----------|-------|" >> $GITHUB_STEP_SUMMARY
echo "| **PR** | #${PR_NUMBER} |" >> $GITHUB_STEP_SUMMARY
echo "| **Image Tag** | \`${IMAGE_TAG}\` |" >> $GITHUB_STEP_SUMMARY
echo "| **Commit** | \`${COMMIT_SHA}\` |" >> $GITHUB_STEP_SUMMARY
echo "" >> $GITHUB_STEP_SUMMARY

echo "[INFO] ✓ Step summary generated"

################################################################################
# Summary
################################################################################
echo ""
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║  Result: ✓ SUCCESS - Preview comment posted                                  ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
