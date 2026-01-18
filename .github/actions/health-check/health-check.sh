#!/bin/bash
# Purpose: Wait for service to become healthy by polling endpoint
# Inputs:
#   URL: Health check URL (e.g., https://api.example.com/health/live)
#   MAX_ATTEMPTS: Maximum number of attempts (default: 30)
#   INTERVAL: Seconds between attempts (default: 10)
#   TIMEOUT: Timeout for each request in seconds (default: 5)
#   EXPECTED_STATUS: Expected HTTP status code (default: 200)
#   SERVICE_NAME: Service name for logging (default: Service)
# Outputs:
#   healthy: Whether service became healthy
#   attempts: Number of attempts made
# Logic:
#   1. Loop up to MAX_ATTEMPTS times
#   2. For each attempt, curl the health URL with timeout
#   3. Check if HTTP status matches EXPECTED_STATUS
#   4. If match, set healthy=true and exit
#   5. Otherwise, sleep INTERVAL seconds and retry
#   6. Output healthy=true/false and attempt count

set -euo pipefail

URL="${URL:-}"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-30}"
INTERVAL="${INTERVAL:-10}"
TIMEOUT="${TIMEOUT:-5}"
EXPECTED_STATUS="${EXPECTED_STATUS:-200}"
SERVICE_NAME="${SERVICE_NAME:-Service}"

echo "Waiting for $SERVICE_NAME to become healthy..."
echo "URL: $URL"
echo "Max attempts: $MAX_ATTEMPTS (interval: ${INTERVAL}s)"

ATTEMPT=1
HEALTHY=false

while [ $ATTEMPT -le $MAX_ATTEMPTS ]; do
  echo "Attempt $ATTEMPT/$MAX_ATTEMPTS..."

  HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    --max-time $TIMEOUT \
    --connect-timeout $TIMEOUT \
    "$URL" 2>/dev/null || echo "000")

  if [ "$HTTP_STATUS" = "$EXPECTED_STATUS" ]; then
    echo "✅ $SERVICE_NAME is healthy (HTTP $HTTP_STATUS)"
    HEALTHY=true
    break
  else
    echo "  Status: $HTTP_STATUS (expected: $EXPECTED_STATUS)"

    if [ $ATTEMPT -lt $MAX_ATTEMPTS ]; then
      echo "  Waiting ${INTERVAL}s before next attempt..."
      sleep $INTERVAL
    fi
  fi

  ATTEMPT=$((ATTEMPT + 1))
done

if [ "$HEALTHY" = "false" ]; then
  echo "::error::$SERVICE_NAME did not become healthy after \
    $MAX_ATTEMPTS attempts"
  exit 1
fi

echo "healthy=true" >> $GITHUB_OUTPUT
echo "attempts=$ATTEMPT" >> $GITHUB_OUTPUT
