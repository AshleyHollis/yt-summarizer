#!/bin/bash
# =============================================================================
# Create Cleanup Summary
# =============================================================================
# PURPOSE:
#   Creates a GitHub Actions step summary for preview cleanup
#
# INPUTS (via environment variables):
#   PR_NUMBER        Pull request number
#   PR_MERGED        Whether the PR was merged (true/false)
#
# OUTPUTS:
#   Writes to $GITHUB_STEP_SUMMARY with markdown summary
#
# LOGIC:
#   1. Create a markdown table with PR information
#   2. Display automatic cleanup explanation for Argo CD ApplicationSet
#
# =============================================================================
set -euo pipefail

cat >> "$GITHUB_STEP_SUMMARY" << 'EOF'
## 🗑️ Preview Cleanup Summary

| Property | Value |
|----------|-------|
EOF

echo "| **PR** | #${PR_NUMBER} |" >> "$GITHUB_STEP_SUMMARY"
echo "| **Merged** | ${PR_MERGED} |" >> "$GITHUB_STEP_SUMMARY"

cat >> "$GITHUB_STEP_SUMMARY" << 'EOF'

### ℹ️ Automatic Cleanup

With Argo CD ApplicationSet using Pull Request Generator:
- ✅ Application deleted automatically when PR closes
- ✅ Namespace pruned automatically
- ✅ No overlay files to delete (they lived in PR branch)
EOF
