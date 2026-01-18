#!/bin/bash
# =============================================================================
# SWA Cleanup Scheduled: Report Cleanup Results
# =============================================================================
# Reports the results of scheduled SWA cleanup operation
# Handles both success (items deleted) and no-cleanup (all current) cases
#
# INPUTS (via environment):
#   - DELETED_COUNT: number of stale environments deleted
#   - STALE_PRS: comma-separated list of PR numbers that were cleaned
#
# BEHAVIOR:
#   - Reports count of deleted environments
#   - Lists PR numbers that were cleaned
#   - Shows message if no cleanup was needed
#
# USAGE:
#   DELETED_COUNT=3 STALE_PRS="42,43,44" scripts/workflows/cleanup-swa-report-results.sh
# =============================================================================

set -e

if [[ "${DELETED_COUNT:-0}" != "0" ]]; then
    echo "✅ Cleaned up ${DELETED_COUNT} stale environment(s)"
    echo "💡 Deleted environments for PRs: ${STALE_PRS}"
else
    echo "✅ No stale environments found or all cleanup completed"
fi

echo "✓ Cleanup results reported"
