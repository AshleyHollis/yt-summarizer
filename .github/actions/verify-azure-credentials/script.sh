#!/bin/bash
# =============================================================================
# Verify Azure OIDC Credentials
# =============================================================================
# PURPOSE:
#   Verifies that required Azure OIDC credentials are configured
#
# INPUTS (via environment variables):
#   CLIENT_ID            Azure client ID to verify
#   TENANT_ID            Azure tenant ID to verify
#   SUBSCRIPTION_ID      Azure subscription ID to verify
#
# OUTPUTS:
#   Exit code 0 if all credentials present, 1 if any missing
#
# LOGIC:
#   1. Check if all three Azure credential values are non-empty
#   2. If any are missing, display error with setup instructions
#   3. If all present, confirm with success message
#
# =============================================================================
set -euo pipefail

if [ -z "${CLIENT_ID}" ] || \
   [ -z "${TENANT_ID}" ] || \
   [ -z "${SUBSCRIPTION_ID}" ]; then
  echo "::error::Azure OIDC credentials not configured."
  echo ""
  echo "Required secrets:"
  echo "  - AZURE_CLIENT_ID: App registration client ID"
  echo "  - AZURE_TENANT_ID: Azure AD tenant ID"
  echo "  - AZURE_SUBSCRIPTION_ID: Target subscription ID"
  echo ""
  echo "See docs/runbooks/ci-cd-troubleshooting.md for setup instructions."
  exit 1
fi

echo "✅ Azure OIDC credentials verified"
