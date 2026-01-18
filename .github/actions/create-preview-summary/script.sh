#!/bin/bash
# =============================================================================
# Create Preview Deployment Summary
# =============================================================================
# PURPOSE:
#   Creates a GitHub Actions step summary for preview deployments
#
# INPUTS (via environment variables):
#   PR_NUMBER       Pull request number
#   PREVIEW_URL     Preview environment URL
#   IMAGE_TAG       Docker image tag deployed
#   COMMIT_SHA      Git commit SHA
#
# OUTPUTS:
#   Writes to $GITHUB_STEP_SUMMARY with markdown summary
#
# LOGIC:
#   1. Create header with deployment summary
#   2. Build property table with PR, URL, image tag, and commit
#   3. Add quick links and architecture description
#
# =============================================================================
set -euo pipefail

cat >> "$GITHUB_STEP_SUMMARY" << EOF
## 🚀 Preview Deployment Summary

| Property | Value |
|----------|-------|
| **PR** | #${PR_NUMBER} |
| **Preview URL** | ${PREVIEW_URL} |
| **Image Tag** | \`${IMAGE_TAG}\` |
| **Commit** | \`${COMMIT_SHA}\` |

### 🔗 Quick Links
- [Preview Site](${PREVIEW_URL})

### ℹ️ Architecture
- **Backend**: Deployed to AKS preview namespace
- **Frontend**: Deployed to Azure Static Web Apps staging slot
EOF
