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
#
# OUTPUTS:
#   Test results and coverage reports
#
# LOGIC:
#   1. If PARALLEL is true, run with pytest-xdist (auto workers)
#   2. Otherwise run serially
#   3. Include any additional pytest arguments
#   (Note: GitHub Actions sets working-directory via action.yml)
#
# =============================================================================
set -euo pipefail

if [ "${PARALLEL}" = "true" ]; then
  python -m pytest -n auto tests/ ${PYTEST_ARGS}
else
  python -m pytest tests/ ${PYTEST_ARGS}
fi
