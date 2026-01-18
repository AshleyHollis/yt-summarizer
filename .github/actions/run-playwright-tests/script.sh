#!/bin/bash
# =============================================================================
# Run Playwright Tests
# =============================================================================
# PURPOSE:
#   Installs Playwright browsers and runs E2E tests
#
# INPUTS (via environment variables):
#   INSTALL_DEPS            Install system dependencies with browsers (true/false)
#   PLAYWRIGHT_ARGS         Additional Playwright test arguments
#
# OUTPUTS:
#   HTML report in working directory
#
# LOGIC:
#   1. Install Playwright browsers (with or without deps)
#   2. Run Playwright test suite with provided arguments
#   (Note: GitHub Actions sets working-directory via action.yml)
#
# =============================================================================
set -euo pipefail

# Install Playwright browsers
if [ "${INSTALL_DEPS}" = "true" ]; then
  npx playwright install --with-deps chromium
else
  npx playwright install chromium
fi

# Run tests
npx playwright test ${PLAYWRIGHT_ARGS}
