#!/bin/bash
# =============================================================================
# Run pytest
# =============================================================================
# PURPOSE:
#   Executes pytest with standardized configuration
#
# INPUTS (via environment variables):
#   PARALLEL            Run tests in parallel with pytest-xdist (true/false)
#   PYTEST_ARGS         Additional pytest arguments
#   MARKERS             Marker expression for -m option (e.g., "not integration and not live")
#
# OUTPUTS:
#   Test results and coverage reports
#
# LOGIC:
#   1. Build pytest command progressively
#   2. If PARALLEL is true, add -n auto for pytest-xdist
#   3. Add any additional pytest arguments
#   4. Add marker expression with proper quoting if provided
#   5. Execute with eval to ensure proper quote handling
#   (Note: GitHub Actions sets working-directory via action.yml)
#
# =============================================================================
set -euo pipefail

# Build pytest command
CMD="python -m pytest"
if [ "${PARALLEL}" = "true" ]; then
  CMD="$CMD -n auto"
fi
CMD="$CMD tests/"
if [ -n "${PYTEST_ARGS}" ]; then
  CMD="$CMD ${PYTEST_ARGS}"
fi
if [ -n "${MARKERS}" ]; then
  CMD="$CMD -m \"${MARKERS}\""
fi

echo "Running: $CMD"
eval "$CMD"
