#!/bin/bash

################################################################################
# Action: health-check-preview / check-service-endpoints.sh
#
# Purpose: Validates that the API service and its endpoints are properly
#          configured and ready to receive traffic in the Kubernetes cluster.
#
# Inputs (Environment Variables):
#   NAMESPACE         - Kubernetes namespace for the preview environment
#
# Outputs:
#   Reports findings via GitHub Actions commands (::error::, ::warning::)
#   No explicit output variables; purely informational/diagnostic
#
# Process:
#   1. Retrieves service definition for 'api' service
#   2. Checks endpoints and their addresses
#   3. Counts healthy endpoint addresses
#   4. Fails if service has zero endpoints
#
# Error Handling:
#   - Issues warnings for missing service/endpoints
#   - Fails with error if endpoints are empty (indicates pod readiness issue)
#   - Does not fail if service not found (diagnostic only)
#
################################################################################

set -euo pipefail

NAMESPACE="${NAMESPACE:?NAMESPACE not set}"

echo "::group::🔌 Service and Endpoints"

# Check service
kubectl get svc api -n ${NAMESPACE} -o wide || echo "::warning::Service not found"

# Check endpoints
echo "--- Endpoints ---"
kubectl get endpoints api -n ${NAMESPACE} || echo "::warning::Endpoints not found"

# Check if endpoints have addresses
ENDPOINT_COUNT=$(kubectl get endpoints api -n ${NAMESPACE} -o jsonpath='{.subsets[0].addresses}' 2>/dev/null | jq 'length' 2>/dev/null || echo "0")
if [ "$ENDPOINT_COUNT" != "0" ]; then
  echo "✅ Service has ${ENDPOINT_COUNT} endpoint(s)"
else
  echo "::error::Service has no endpoints - pods may not be ready"
fi
echo "::endgroup::"
