#!/bin/bash
# =============================================================================
# Preview Cleanup: Report SWA Cleanup Status
# =============================================================================
# Reports the status of SWA cleanup operation
# Handles both success and warning cases appropriately
#
# INPUTS (via environment):
#   - SWA_CLEANUP_OUTCOME: outcome from previous step (success/failure/etc)
#
# BEHAVIOR:
#   - Prints success message if cleanup succeeded
#   - Prints warning message if cleanup had issues
#   - Writes summary to GITHUB_STEP_SUMMARY
#
# USAGE:
#   SWA_CLEANUP_OUTCOME=success scripts/workflows/preview-cleanup-swa-status.sh
# =============================================================================

set -e

if [[ "${SWA_CLEANUP_OUTCOME}" == "success" ]]; then
    echo "✅ SWA staging environment successfully deleted"
else
    echo "⚠️  SWA cleanup completed with warnings (environment may not have existed)"
fi

cat >> $GITHUB_STEP_SUMMARY << 'EOF'
## 🗑️ Azure Static Web Apps Cleanup

**Status:** ${{ steps.swa-cleanup.outcome == 'success' && '✅ Success' || '⚠️  Completed with warnings' }}
**PR Number:** #${{ github.event.pull_request.number }}

The staging environment for this PR has been processed for deletion.
EOF

echo "✓ Cleanup status reported to step summary"
