#!/bin/bash
# =============================================================================
# Record Test Duration
# =============================================================================
# PURPOSE:
#   Records test execution start and finish times for reporting
#
# INPUTS (via environment variables):
#   START_TIME          Test start time (epoch seconds), empty if recording start
#   TEST_NAME           Name of the test suite for logging
#
# OUTPUTS (via $GITHUB_OUTPUT):
#   started_at          Test start time (epoch seconds)
#   test_duration       Test duration in seconds (only set when finishing)
#
# LOGIC:
#   1. If START_TIME is empty, record current time as start
#   2. If START_TIME provided, calculate duration and output it
#
# =============================================================================
set -euo pipefail

if [ -z "${START_TIME}" ]; then
  # Record start time
  echo "started_at=$(date +%s)" >> "$GITHUB_OUTPUT"
  echo "📊 Starting ${TEST_NAME}..."
else
  # Record finish time and calculate duration
  END=$(date +%s)
  START="${START_TIME}"
  DURATION=$((END - START))
  echo "test_duration=${DURATION}" >> "$GITHUB_OUTPUT"
  echo "✅ ${TEST_NAME} completed in ${DURATION}s"
fi
