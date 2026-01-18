#!/bin/bash

################################################################################
# Action: health-check-preview / check-external-diagnostics.sh
#
# Purpose: Performs diagnostic checks when external health check fails.
#          Helps identify the root cause of connectivity issues.
#
# Inputs (Environment Variables):
#   EXTERNAL_URL      - External URL to check (e.g., https://api.preview-pr-4.example.com)
#   NAMESPACE         - Kubernetes namespace (for additional diagnostics)
#
# Outputs:
#   Reports diagnostic information via GitHub Actions commands (::warning::, ::notice::)
#
# Process:
#   1. Attempts insecure (bypass SSL) connection to distinguish cert vs connectivity issues
#   2. Retrieves certificate status for reference
#   3. Provides detailed diagnostic information and possible causes
#
# Error Handling:
#   - Never exits with error code (diagnostic only)
#   - Always provides suggestions for troubleshooting
#
################################################################################

set -euo pipefail

EXTERNAL_URL="${EXTERNAL_URL:?EXTERNAL_URL not set}"
NAMESPACE="${NAMESPACE:-unknown}"

echo "::group::🔍 External Health Check Diagnostics"

# Check if it's a cert issue (diagnostic only)
echo "Running insecure connection test (bypasses SSL verification)..."
INSECURE_CODE=$(curl -k -s -o /dev/null -w "%{http_code}" --max-time 5 "${EXTERNAL_URL}/health/live" 2>/dev/null || echo "000")
if [ "$INSECURE_CODE" = "200" ]; then
  echo "::warning::API responds successfully when bypassing SSL verification (-k flag)"
  echo "::notice::This indicates a TLS certificate configuration issue"
fi

# Get certificate status for reference
WILDCARD_CERT="yt-summarizer-wildcard"
CERT_NAMESPACE="gateway-system"
CERT_READY=$(kubectl get certificate ${WILDCARD_CERT} -n ${CERT_NAMESPACE} -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "Unknown")

# Provide diagnostic information
echo ""
echo "::notice::Diagnostic Summary:"
echo "::notice::- Insecure check result: HTTP $INSECURE_CODE"
echo "::notice::- Certificate ready status: $CERT_READY"
echo "::notice::- Preview namespace: $NAMESPACE"
echo "::notice::"
echo "::notice::Possible causes of external health check failure:"
echo "::notice::- DNS propagation delay (wait a few minutes and retry)"
echo "::notice::- Gateway API HTTPRoute misconfiguration"
echo "::notice::- Gateway not routing traffic correctly"
echo "::notice::- Service/pod not ready or unhealthy"
echo "::notice::- Backend service port mismatch"
echo "::notice::- TLS certificate issue (even if status shows Ready)"

echo "::endgroup::"
