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

# Logging helpers
print_header() {
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "[INFO] 🚀 $1"
  shift
  for line in "$@"; do
    echo "[INFO]    $line"
  done
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
}

print_footer() {
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "[INFO] $1"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

log_info() { echo "[INFO] $1"; }
log_warn() { echo "[WARN] ⚠️  $1"; }
log_error() { echo "[ERROR] ✗ $1"; }
log_success() { echo "[INFO]    ✓ $1"; }
log_step() { echo "[INFO] $1"; }

URL="${URL:-}"
MAX_ATTEMPTS="${MAX_ATTEMPTS:-30}"
INTERVAL="${INTERVAL:-10}"
TIMEOUT="${TIMEOUT:-5}"
EXPECTED_STATUS="${EXPECTED_STATUS:-200}"
SERVICE_NAME="${SERVICE_NAME:-Service}"

print_header "Health Check: $SERVICE_NAME" \
  "URL: $URL" \
  "Max Attempts: $MAX_ATTEMPTS" \
  "Interval: ${INTERVAL}s" \
  "Expected Status: $EXPECTED_STATUS"

ATTEMPT=1
HEALTHY=false

while [ $ATTEMPT -le $MAX_ATTEMPTS ]; do
  log_info "⏳ Attempt $ATTEMPT/$MAX_ATTEMPTS..."

  HTTP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
    --max-time $TIMEOUT \
    --connect-timeout $TIMEOUT \
    "$URL" 2>/dev/null || echo "000")

  if [ "$HTTP_STATUS" = "$EXPECTED_STATUS" ]; then
    log_success "$SERVICE_NAME is healthy (HTTP $HTTP_STATUS)"
    HEALTHY=true
    break
  else
    if [ "$HTTP_STATUS" = "000" ]; then
      log_info "   ⏱️ Connection timeout or error"
    else
      log_info "   ↻ HTTP $HTTP_STATUS (expected: $EXPECTED_STATUS)"
    fi

    if [ $ATTEMPT -lt $MAX_ATTEMPTS ]; then
      log_info "   Waiting ${INTERVAL}s before retry..."
      sleep $INTERVAL
    fi
  fi

  ATTEMPT=$((ATTEMPT + 1))
done

if [ "$HEALTHY" = "false" ]; then
  log_error "$SERVICE_NAME did not become healthy after $MAX_ATTEMPTS attempts"
  echo "::error::$SERVICE_NAME did not become healthy after $MAX_ATTEMPTS attempts"
  print_footer "❌ Health check failed after $((ATTEMPT - 1)) attempts"
  exit 1
fi

echo "healthy=true" >> $GITHUB_OUTPUT
echo "attempts=$ATTEMPT" >> $GITHUB_OUTPUT

print_footer "✅ $SERVICE_NAME is healthy! (took $ATTEMPT attempt(s))"
