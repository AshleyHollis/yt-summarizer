#!/bin/bash

################################################################################
# Action: health-check-preview / check-internal-health.sh
#
# Purpose: Performs health checks on preview environment API running within the
#          internal Kubernetes cluster, verifying both internal service
#          connectivity and overall cluster readiness.
#
# Inputs (Environment Variables):
#   NAMESPACE         - Kubernetes namespace for the preview environment
#   MAX_ATTEMPTS      - Maximum number of health check attempts
#   INTERVAL          - Seconds to wait between attempts
#
# Outputs:
#   Sets GitHub Actions output: healthy=true|false
#   Reports success/failure via GitHub Actions commands (::error::, ::notice::)
#
# Process:
#   1. Uses kubectl to run curl test pod inside the cluster
#   2. Tests internal http://api/health/live endpoint
#   3. Retries with configured interval between attempts
#   4. Sets output and exits with appropriate code
#
# Error Handling:
#   - Fails fast if all attempts exhausted
#   - Provides diagnostic output on failure
#   - Uses strict error handling (set -euo pipefail)
#
################################################################################

set -euo pipefail

NAMESPACE="${NAMESPACE:?NAMESPACE not set}"
MAX_ATTEMPTS="${MAX_ATTEMPTS:?MAX_ATTEMPTS not set}"
INTERVAL="${INTERVAL:?INTERVAL not set}"

echo "::group::🔍 Internal Cluster Health Check"
echo "Namespace: ${NAMESPACE}"

INTERNAL_HEALTHY=false
for i in $(seq 1 $MAX_ATTEMPTS); do
  echo "Attempt $i/$MAX_ATTEMPTS..."

  # Run curl from within the cluster to check internal service
  if kubectl run curl-test-internal-${i} \
    --image=curlimages/curl:latest \
    --rm -i --restart=Never \
    --namespace=${NAMESPACE} \
    --timeout=15s \
    -- curl -s --max-time 5 http://api/health/live 2>/dev/null | grep -q "ok"; then
    echo "✅ Internal API health check passed"
    INTERNAL_HEALTHY=true
    break
  fi

  if [ $i -lt $MAX_ATTEMPTS ]; then
    echo "  ⏳ Waiting ${INTERVAL}s before retry..."
    sleep $INTERVAL
  else
    echo "::endgroup::"
    echo "::error::Internal API health check failed after $MAX_ATTEMPTS attempts"
    echo "healthy=false" >> $GITHUB_OUTPUT
    exit 1
  fi
done

echo "::endgroup::"
echo "healthy=${INTERNAL_HEALTHY}" >> $GITHUB_OUTPUT
