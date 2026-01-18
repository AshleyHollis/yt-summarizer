#!/bin/bash
# =============================================================================
# CI: Check if Main Branch
# =============================================================================
# Determines if the current event is from the main branch
#
# OUTPUT: Sets GITHUB_OUTPUT with:
#   - is_main_branch: true if main branch, false otherwise
#
# USAGE:
#   scripts/workflows/ci-check-branch.sh
# =============================================================================

set -e

# Check if this is a push to main branch or PR targeting main
if [[ "${{ github.ref }}" == "refs/heads/main" ]] || [[ "${{ github.event_name }}" == "push" && "${{ github.ref_name }}" == "main" ]]; then
    echo "is_main_branch=true" >> $GITHUB_OUTPUT
    echo "✓ Main branch detected - FULL validation mode"
else
    echo "is_main_branch=false" >> $GITHUB_OUTPUT
    echo "✓ PR/branch detected - Smart change detection mode"
fi
