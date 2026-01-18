#!/bin/bash

################################################################################
# Action: health-check-preview / check-httproute-config.sh
#
# Purpose: Validates Gateway API HTTPRoute configuration for the preview
#          environment, ensuring routes are properly configured and bound to
#          the gateway.
#
# Inputs (Environment Variables):
#   NAMESPACE         - Kubernetes namespace for the preview environment
#
# Outputs:
#   Reports findings via GitHub Actions commands (::warning::, ::notice::)
#   No explicit output variables; purely informational/diagnostic
#
# Process:
#   1. Lists HTTPRoute resources in the namespace
#   2. Retrieves HTTPRoute status and binding information
#   3. Extracts configured hostname from HTTPRoute spec
#   4. Reports failures gracefully if HTTPRoute not found
#
# Error Handling:
#   - Issues warnings if HTTPRoute not found or status unavailable
#   - Continues on jq JSON parsing failures
#   - Does not fail the overall health check
#
################################################################################

set -euo pipefail

NAMESPACE="${NAMESPACE:?NAMESPACE not set}"

echo "::group::🔧 HTTPRoute Configuration"

# Get HTTPRoute details
kubectl get httproute -n ${NAMESPACE} -o wide || echo "::warning::Failed to get HTTPRoute"

# Check HTTPRoute status
echo "--- HTTPRoute Status ---"
HTTPROUTE_NAME=$(kubectl get httproute -n ${NAMESPACE} -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "")
if [ -n "$HTTPROUTE_NAME" ]; then
  echo "HTTPRoute: $HTTPROUTE_NAME"
  kubectl get httproute $HTTPROUTE_NAME -n ${NAMESPACE} -o jsonpath='{.status}' | jq '.' 2>/dev/null || echo "No status available"

  # Get hostname
  HOSTNAME=$(kubectl get httproute $HTTPROUTE_NAME -n ${NAMESPACE} -o jsonpath='{.spec.hostnames[0]}' 2>/dev/null || echo "")
  echo "✅ HTTPRoute configured for: ${HOSTNAME}"
else
  echo "::warning::No HTTPRoute found"
fi
echo "::endgroup::"
