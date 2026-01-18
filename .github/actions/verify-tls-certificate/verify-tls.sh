#!/bin/bash
# Purpose: Verify TLS certificate is valid and not expired
# Inputs:
#   API_HOST: Hostname to verify (passed as parameter)
# Outputs: None (exits with status code 0 or 1)
# Logic:
#   1. Skip if no API_HOST provided
#   2. Retrieve certificate chain from host using openssl s_client
#   3. Extract certificate dates and check validity
#   4. Verify certificate is not currently expired (checkend 0)
#   5. Warn if certificate expires within 7 days
#   6. Display issuer information

API_HOST="${1:-}"

if [ -z "$API_HOST" ]; then
  echo "::warning::No API host provided - skipping certificate verification"
  exit 0
fi

echo "Verifying certificate for ${API_HOST}"

# Use openssl to get certificate and check validity using built-in commands
# Get certificate chain
CERT_CHAIN=$(echo | openssl s_client -connect ${API_HOST}:443 \
  -servername ${API_HOST} 2>&1)

if ! echo "$CERT_CHAIN" | grep -q "BEGIN CERTIFICATE"; then
  echo "::error::Failed to retrieve certificate from ${API_HOST}"
  echo "::error::Connection output: $(echo "$CERT_CHAIN" | head -20)"
  exit 1
fi

# Extract and verify the certificate dates using openssl's built-in date checking
CERT_DATES=$(echo | openssl s_client -connect ${API_HOST}:443 \
  -servername ${API_HOST} 2>/dev/null | openssl x509 -noout -dates)

if [ -z "$CERT_DATES" ]; then
  echo "::error::Failed to extract certificate dates"
  exit 1
fi

echo "✅ Certificate dates retrieved"
echo "$CERT_DATES"

# Check if certificate is currently valid using openssl's checkend
if echo | openssl s_client -connect ${API_HOST}:443 \
  -servername ${API_HOST} 2>/dev/null | \
  openssl x509 -noout -checkend 0 > /dev/null; then
  echo "✅ Certificate is currently valid (not expired)"
else
  echo "::error::Certificate is expired or invalid"
  exit 1
fi

# Check certificate will be valid for at least 7 days
SEVEN_DAYS_SECONDS=$((7 * 24 * 60 * 60))
if echo | openssl s_client -connect ${API_HOST}:443 \
  -servername ${API_HOST} 2>/dev/null | \
  openssl x509 -noout -checkend $SEVEN_DAYS_SECONDS > /dev/null; then
  echo "✅ Certificate valid for at least 7 more days"
else
  echo "::warning::Certificate will expire in less than 7 days"
fi

# Get issuer information
ISSUER=$(echo | openssl s_client -connect ${API_HOST}:443 \
  -servername ${API_HOST} 2>/dev/null | openssl x509 -noout -issuer)
echo "Certificate issuer: ${ISSUER}"

echo "✅ Certificate verification passed"
