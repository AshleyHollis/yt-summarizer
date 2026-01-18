#!/bin/bash
# Purpose: Computes preview environment URLs based on PR number
# Inputs:
#   PR_NUMBER: Pull request number
#   APP_NAME: Application name (default: yt-summarizer)
#   BASE_DOMAIN: Base domain for previews
# Outputs:
#   preview_url: Full preview URL (https://api-pr-{number}.{base-domain})
#   preview_host: Preview hostname (api-pr-{number}.{base-domain})
#   tls_secret: TLS secret name for preview (shared wildcard certificate)
#   namespace: Preview namespace (preview-pr-{number})
# Logic:
#   1. Construct preview hostname from PR number and base domain
#   2. Prepend https:// to hostname for full URL
#   3. Use shared wildcard TLS secret from gateway-system namespace
#   4. Create namespace name with PR-specific suffix

set -euo pipefail

PR_NUMBER="${PR_NUMBER:-}"
APP_NAME="${APP_NAME:-yt-summarizer}"
BASE_DOMAIN="${BASE_DOMAIN:-}"

# New URL scheme uses Gateway API with wildcard DNS
# Format: api-pr-{number}.{base-domain}
# Example: api-pr-123.yt-summarizer.apps.ashleyhollis.com

# Compute preview hostname
PREVIEW_HOST="api-pr-${PR_NUMBER}.${BASE_DOMAIN}"

# Preview URL (always HTTPS with wildcard certificate)
PREVIEW_URL="https://${PREVIEW_HOST}"

# TLS secret name (shared wildcard certificate from gateway-system namespace)
# Note: Gateway terminates TLS, no per-preview secret needed
TLS_SECRET="yt-summarizer-wildcard-tls"

# Namespace
NAMESPACE="preview-pr-${PR_NUMBER}"

echo "preview_url=${PREVIEW_URL}" >> $GITHUB_OUTPUT
echo "preview_host=${PREVIEW_HOST}" >> $GITHUB_OUTPUT
echo "tls_secret=${TLS_SECRET}" >> $GITHUB_OUTPUT
echo "namespace=${NAMESPACE}" >> $GITHUB_OUTPUT

echo "✅ Preview URLs computed:"
echo "   URL: ${PREVIEW_URL}"
echo "   Host: ${PREVIEW_HOST}"
echo "   TLS Secret: ${TLS_SECRET} (shared wildcard)"
echo "   Namespace: ${NAMESPACE}"
