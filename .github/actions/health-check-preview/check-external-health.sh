#!/bin/bash

################################################################################
# Action: health-check-preview / check-external-health.sh
#
# Purpose: Performs comprehensive external health checks on the preview
#          environment API through the public ingress. Validates TLS certificate
#          readiness before attempting external connectivity tests.
#
# Inputs (Environment Variables):
#   EXTERNAL_URL      - External URL to check (e.g., https://api.preview-pr-4.example.com)
#   MAX_ATTEMPTS      - Maximum number of health check attempts
#   INTERVAL          - Seconds to wait between attempts
#   NAMESPACE         - Kubernetes namespace (for additional diagnostics)
#
# Outputs:
#   Sets GitHub Actions output: healthy=true|false|false-cert-not-ready
#   Reports status via GitHub Actions commands (::error::, ::warning::, ::notice::)
#
# Process:
#   1. Checks Gateway API wildcard TLS certificate readiness (FAIL FAST)
#   2. If cert not ready, reports detailed error and exits
#   3. Waits 30 seconds for DNS propagation
#   4. Retries external HTTP health check with configured attempts
#   5. On failure, performs diagnostic SSL checks and reports possible causes
#   6. Always exits with error code on failure
#
# Error Handling:
#   - Fails immediately if TLS certificate not ready (no point retrying)
#   - Provides specific guidance for Let's Encrypt rate limiting
#   - Performs SSL verification bypass test to distinguish cert vs connectivity issues
#   - Uses strict error handling (set -euo pipefail)
#
################################################################################

set -euo pipefail

EXTERNAL_URL="${EXTERNAL_URL:?EXTERNAL_URL not set}"
MAX_ATTEMPTS="${MAX_ATTEMPTS:?MAX_ATTEMPTS not set}"
INTERVAL="${INTERVAL:?INTERVAL not set}"
NAMESPACE="${NAMESPACE:?NAMESPACE not set}"

echo "::group::🌐 External Ingress Health Check"
echo "URL: ${EXTERNAL_URL}/health/live"

# Check certificate status first - FAIL FAST if not ready
WILDCARD_CERT="yt-summarizer-wildcard"
CERT_NAMESPACE="gateway-system"
CERT_READY=$(kubectl get certificate ${WILDCARD_CERT} -n ${CERT_NAMESPACE} -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "Unknown")
CERT_MESSAGE=$(kubectl get certificate ${WILDCARD_CERT} -n ${CERT_NAMESPACE} -o jsonpath='{.status.conditions[?(@.type=="Ready")].message}' 2>/dev/null || echo "")

# If certificate is NOT ready, fail immediately without doing external checks
if [ "$CERT_READY" != "True" ]; then
  echo "::error::Gateway API wildcard TLS certificate is NOT ready"
  echo "::error::Certificate: ${WILDCARD_CERT} (namespace: ${CERT_NAMESPACE})"
  echo "::error::Status: ${CERT_READY}"
  echo "::error::Message: ${CERT_MESSAGE}"

  # Provide specific guidance based on cert status
  if echo "$CERT_MESSAGE" | grep -qi "rateLimited"; then
    echo "::error::Let's Encrypt rate limit detected!"
    echo "::notice::Rate limit: 5 certificates per exact domain set per 168 hours"
    echo "::notice::Wait for rate limit to expire or use staging certificates for testing"
  fi

  echo "::notice::External access requires a valid TLS certificate"
  echo "::notice::Fix the certificate issue before the preview environment will be accessible"
  echo "healthy=false-cert-not-ready" >> $GITHUB_OUTPUT
  exit 1
fi

echo "✅ TLS certificate is ready - proceeding with external health checks"

# DNS propagation can take a few minutes - give it some time
echo "::notice::Waiting 30 seconds for DNS propagation..."
sleep 30

EXTERNAL_HEALTHY=false
for i in $(seq 1 $MAX_ATTEMPTS); do
  echo "Attempt $i/$MAX_ATTEMPTS (external)..."

  HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "${EXTERNAL_URL}/health/live" 2>&1 || echo "000")

  if [ "$HTTP_CODE" = "200" ]; then
    echo "✅ External API health check passed (HTTP $HTTP_CODE)"
    EXTERNAL_HEALTHY=true
    break
  else
    echo "  ❌ Status: $HTTP_CODE (expected: 200)"
  fi

  if [ $i -lt $MAX_ATTEMPTS ]; then
    echo "  ⏳ Waiting ${INTERVAL}s before retry..."
    sleep $INTERVAL
  fi
done

# If external check passed, we're done
if [ "$EXTERNAL_HEALTHY" = "true" ]; then
  echo "::endgroup::"
  echo "healthy=true" >> $GITHUB_OUTPUT
  exit 0
fi

# External check failed - perform diagnostics and fail
echo ""
echo "::error::External API health check failed after $MAX_ATTEMPTS attempts"

# Check if it's a cert issue (diagnostic only)
INSECURE_CODE=$(curl -k -s -o /dev/null -w "%{http_code}" --max-time 5 "${EXTERNAL_URL}/health/live" 2>/dev/null || echo "000")
if [ "$INSECURE_CODE" = "200" ]; then
  echo "::warning::API responds successfully when bypassing SSL verification (-k flag)"
  echo "::notice::This indicates a TLS certificate configuration issue"
fi

# Provide diagnostic information
echo "::notice::Diagnostic information:"
echo "::notice::- External check: $MAX_ATTEMPTS attempts failed (HTTP $HTTP_CODE)"
echo "::notice::- Insecure check: HTTP $INSECURE_CODE"
echo "::notice::- Certificate ready: $CERT_READY"
echo "::notice::"
echo "::notice::Possible causes:"
echo "::notice::- DNS propagation delay (wait a few minutes and retry)"
echo "::notice::- Gateway API HTTPRoute misconfiguration"
echo "::notice::- Gateway not routing traffic correctly"
echo "::notice::- Service/pod not ready or unhealthy"
echo "::notice::- Backend service port mismatch"

# ALWAYS fail if external check fails
echo "::endgroup::"
echo "healthy=false" >> $GITHUB_OUTPUT
exit 1
