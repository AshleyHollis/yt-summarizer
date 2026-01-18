#!/bin/bash

################################################################################
# Action: health-check-preview / check-gateway-cert.sh
#
# Purpose: Validates Gateway API wildcard TLS certificate readiness before
#          attempting external connectivity tests. Fails fast if cert not ready.
#
# Inputs (Environment Variables):
#   None (uses hardcoded certificate name and namespace)
#
# Outputs:
#   Reports status via GitHub Actions commands (::error::, ::warning::, ::notice::)
#
# Process:
#   1. Checks Gateway API wildcard TLS certificate readiness
#   2. If cert not ready, reports detailed error and exits
#   3. Provides specific guidance for Let's Encrypt rate limiting
#
# Error Handling:
#   - Fails immediately if TLS certificate not ready (no point retrying)
#   - Provides specific guidance for Let's Encrypt rate limiting
#   - Uses strict error handling (set -euo pipefail)
#
################################################################################

set -euo pipefail

echo "🔒 Checking Gateway API wildcard TLS certificate..."

WILDCARD_CERT="yt-summarizer-wildcard"
CERT_NAMESPACE="gateway-system"
CERT_READY=$(kubectl get certificate ${WILDCARD_CERT} -n ${CERT_NAMESPACE} -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "Unknown")
CERT_MESSAGE=$(kubectl get certificate ${WILDCARD_CERT} -n ${CERT_NAMESPACE} -o jsonpath='{.status.conditions[?(@.type=="Ready")].message}' 2>/dev/null || echo "")

# If certificate is NOT ready, fail immediately
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
  exit 1
fi

echo "✅ TLS certificate is ready"
