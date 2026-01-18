#!/bin/bash

################################################################################
# Action: health-check-preview / check-dns-and-tls.sh
#
# Purpose: Performs DNS resolution checks for the preview environment external
#          URL. Diagnostic helper for external connectivity issues.
#
# Inputs (Environment Variables):
#   EXTERNAL_URL      - External URL to check (e.g., https://api.preview-pr-4.example.com)
#   NAMESPACE         - Kubernetes namespace (for reference only)
#
# Outputs:
#   Reports findings via GitHub Actions commands (::warning::, ::notice::)
#   No explicit output variables; purely informational/diagnostic
#
# Process:
#   1. Extracts hostname from URL using sed regex
#   2. Attempts DNS resolution using nslookup and dig commands
#   3. Checks getent for hostname resolution
#
# Note:
#   TLS certificate validation is handled separately by check-gateway-cert.sh,
#   which provides fail-fast validation with Let's Encrypt rate limit detection.
#
# Error Handling:
#   - Continues on DNS command failures (they may not be available)
#   - Issues warnings for resolution failures but doesn't fail
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

# Note: Gateway API wildcard TLS certificate status is now checked separately
# by check-gateway-cert.sh, which provides fail-fast validation with detailed
# error messages including Let's Encrypt rate limit detection.
