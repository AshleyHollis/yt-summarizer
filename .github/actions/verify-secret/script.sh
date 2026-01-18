#!/bin/bash
# =============================================================================
# Verify Secret Configured
# =============================================================================
# PURPOSE:
#   Verifies that a required secret is configured before proceeding
#
# INPUTS (via environment variables):
#   SECRET_VALUE         Value of the secret to check
#   SECRET_NAME          Display name of the secret being verified
#   ERROR_MESSAGE        Custom error message (optional)
#
# OUTPUTS:
#   Exit code 0 if secret present, 1 if missing
#
# LOGIC:
#   1. Check if secret value is empty
#   2. If empty, display custom error message or generic message
#   3. If present, confirm with success message
#
# =============================================================================
set -euo pipefail

if [ -z "${SECRET_VALUE}" ]; then
  if [ -n "${ERROR_MESSAGE}" ]; then
    echo "::error::${ERROR_MESSAGE}"
  else
    echo "::error::${SECRET_NAME} is not configured. Please add it to " \
      "repository secrets."
  fi
  exit 1
fi

echo "✅ ${SECRET_NAME} is configured"
