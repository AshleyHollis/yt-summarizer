#!/bin/bash
# =============================================================================
# CI: Check if Main Branch
# =============================================================================
# Determines if the current event is from the main branch
#
# INPUT ENVIRONMENT VARIABLES (from GitHub Actions):
#   - GITHUB_REF: Full reference name (e.g., refs/heads/main)
#   - GITHUB_REF_NAME: Short reference name (e.g., main)
#   - GITHUB_EVENT_NAME: Event type (push, pull_request, etc)
#
# OUTPUT: Sets GITHUB_OUTPUT with:
#   - is_main_branch: true if main branch, false otherwise
#
# USAGE:
#   GITHUB_REF="refs/heads/main" GITHUB_REF_NAME="main" GITHUB_EVENT_NAME="push" scripts/workflows/ci-check-branch.sh
# =============================================================================

set -e

# Check if this is a push to main branch or PR targeting main
if [[ "${GITHUB_REF}" == "refs/heads/main" ]] || [[ "${GITHUB_EVENT_NAME}" == "push" && "${GITHUB_REF_NAME}" == "main" ]]; then
    echo "is_main_branch=true" >> $GITHUB_OUTPUT
    echo "✓ Main branch detected - FULL validation mode"
else
    echo "is_main_branch=false" >> $GITHUB_OUTPUT
    echo "✓ PR/branch detected - Smart change detection mode"
fi
