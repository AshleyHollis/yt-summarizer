#!/bin/bash
# =============================================================================
# Docker Build and Push - Record Build Timing
# =============================================================================
# PURPOSE:
#   Records Docker build duration for reporting and optimization tracking
#
# INPUTS (via environment variables):
#   BUILD_START_TIME        Start time epoch timestamp
#
# OUTPUTS (via $GITHUB_OUTPUT):
#   build_duration          Build duration in seconds
#
# LOGIC:
#   1. Get current time
#   2. Calculate duration from start time
#   3. Output duration and display in logs
#   Note: This script is called AFTER docker/build-push-action completes
#
# =============================================================================
set -euo pipefail

END=$(date +%s)
START="${BUILD_START_TIME}"
DURATION=$((END - START))

echo "build_duration=${DURATION}" >> "$GITHUB_OUTPUT"
echo "Build duration: ${DURATION}s"
