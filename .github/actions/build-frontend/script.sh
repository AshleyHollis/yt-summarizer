#!/bin/bash
# =============================================================================
# Build Frontend with API URL
# =============================================================================
# PURPOSE:
#   Builds the Next.js frontend with configured API URL
#
# INPUTS (via environment variables):
#   NEXT_PUBLIC_API_URL       Backend API URL
#   NEXT_PUBLIC_ENVIRONMENT   Environment name (preview/production)
#   WORKING_DIRECTORY         Working directory for the frontend
#
# OUTPUTS:
#   Built frontend artifacts in dist/ directory
#
# LOGIC:
#   1. Check if API URL is provided
#   2. Log warning if API URL is missing
#   3. Run npm build with environment variables
#
# =============================================================================
set -euo pipefail

cd "${WORKING_DIRECTORY}"

if [ -z "${NEXT_PUBLIC_API_URL}" ]; then
  echo "::warning::Building frontend without backend API URL"
else
  echo "Building frontend with API URL: ${NEXT_PUBLIC_API_URL}"
fi

npm run build
