#!/bin/bash

################################################################################
# Action: health-check-preview / check-dns-and-tls.sh
#
# Purpose: Performs DNS resolution and TLS certificate status checks for the
#          preview environment external URL. Diagnostic helper for external
#          connectivity issues.
#
# Inputs (Environment Variables):
#   EXTERNAL_URL      - External URL to check (e.g., https://api.preview-pr-4.example.com)
#   NAMESPACE         - Kubernetes namespace (for TLS cert checks)
#
# Outputs:
#   Reports findings via GitHub Actions commands (::warning::, ::notice::)
#   No explicit output variables; purely informational/diagnostic
#
# Process:
#   1. Extracts hostname from URL using sed regex
#   2. Attempts DNS resolution using nslookup and dig commands
#   3. Checks getent for hostname resolution
#   4. Validates Gateway API wildcard TLS certificate status
#   5. Detects Let's Encrypt rate limiting if certificate is not ready
#
# Error Handling:
#   - Continues on DNS command failures (they may not be available)
#   - Issues warnings for resolution failures but doesn't fail
#   - Provides actionable guidance for rate limiting detection
#
################################################################################

set -euo pipefail

EXTERNAL_URL="${EXTERNAL_URL:?EXTERNAL_URL not set}"
NAMESPACE="${NAMESPACE:?NAMESPACE not set}"

# Extract hostname from URL
HOSTNAME=$(echo "$EXTERNAL_URL" | sed -E 's|https?://([^/]+).*|\1|')

echo "::group::🌐 DNS Resolution Check"
echo "Hostname: ${HOSTNAME}"

# Try to resolve the hostname
if command -v nslookup >/dev/null 2>&1; then
  echo "--- nslookup output ---"
  nslookup ${HOSTNAME} || echo "::warning::DNS resolution failed"
fi

if command -v dig >/dev/null 2>&1; then
  echo "--- dig output ---"
  dig +short ${HOSTNAME} || echo "::warning::dig failed"
fi

# Check if hostname resolves to expected IP
RESOLVED_IP=$(getent hosts ${HOSTNAME} | awk '{ print $1 }' || echo "")
if [ -n "$RESOLVED_IP" ]; then
  echo "✅ Hostname resolves to: ${RESOLVED_IP}"
else
  echo "::warning::Failed to resolve hostname"
fi
echo "::endgroup::"

# Check for Gateway API wildcard certificate in gateway-system namespace
echo "::group::🔐 TLS Certificate Status"

WILDCARD_CERT="yt-summarizer-wildcard"
CERT_NAMESPACE="gateway-system"
CERT_READY=$(kubectl get certificate ${WILDCARD_CERT} -n ${CERT_NAMESPACE} -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || echo "Unknown")

if [ "$CERT_READY" = "True" ]; then
  echo "✅ Gateway API wildcard certificate is ready"
  CERT_NOT_AFTER=$(kubectl get certificate ${WILDCARD_CERT} -n ${CERT_NAMESPACE} -o jsonpath='{.status.notAfter}' 2>/dev/null || echo "")
  echo "  Certificate: ${WILDCARD_CERT} (namespace: ${CERT_NAMESPACE})"
  echo "  Expires: ${CERT_NOT_AFTER}"
else
  echo "::warning::Wildcard TLS certificate not ready in ${CERT_NAMESPACE} namespace"
  CERT_MESSAGE=$(kubectl get certificate ${WILDCARD_CERT} -n ${CERT_NAMESPACE} -o jsonpath='{.status.conditions[?(@.type=="Ready")].message}' 2>/dev/null || echo "Unknown")
  echo "  Message: ${CERT_MESSAGE}"

  # Check for rate limiting
  if echo "$CERT_MESSAGE" | grep -q "rateLimited"; then
    echo "::error::Let's Encrypt rate limit detected!"
    echo "::notice::Rate limit: 5 certificates per exact domain set per 168 hours"
  fi
fi
echo "::endgroup::"
