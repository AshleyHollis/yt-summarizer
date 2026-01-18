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
#   WORKING_DIRECTORY   Directory containing tests to run
#
# OUTPUTS:
#   Test results and coverage reports
#
# LOGIC:
#   1. Change to working directory
#   2. If PARALLEL is true, run with pytest-xdist (auto workers)
#   3. Otherwise run serially
#   4. Include any additional pytest arguments
#
# =============================================================================
set -euo pipefail

cd "${WORKING_DIRECTORY}"

if [ "${PARALLEL}" = "true" ]; then
  python -m pytest -n auto tests/ ${PYTEST_ARGS}
else
  python -m pytest tests/ ${PYTEST_ARGS}
fi
