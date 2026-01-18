#!/bin/bash
# =============================================================================
# Health Check and Readiness Probe Utilities
# =============================================================================
# Purpose:
#   Provides reusable functions for health checks and readiness verification
#   in CI/CD workflows, including HTTP health checks, DNS resolution, and
#   TLS certificate validation.
#
# Functions:
#   - http_health_check(url, timeout)
#                                    Single HTTP health check
#   - wait_for_health(url, timeout, max_attempts)
#                                    Poll until endpoint healthy
#   - check_dns_resolution(hostname)
#                                    Verify DNS resolution works
#   - check_tls_certificate(hostname, port)
#                                    Verify TLS cert validity
#   - check_service_ready(service_url)
#                                    Comprehensive readiness check
#
# Usage:
#   source ./lib/health-utils.sh
#   http_health_check "https://api.example.com/health" 5
#   wait_for_health "https://api.example.com/health" 30 10
#   check_dns_resolution "api.example.com"
#   check_tls_certificate "api.example.com" 443
#
# Dependencies:
#   - curl: For HTTP health checks
#   - dig or nslookup: For DNS checks
#   - openssl: For TLS certificate checks
#
# Exit codes:
#   Functions return 0 for success, 1 for failure
#
# =============================================================================

# Perform single HTTP health check
# Args:
#   $1: URL to check (required, should include protocol)
#   $2: Timeout in seconds (optional, defaults to 10)
#   $3: Expected HTTP status code (optional, defaults to 200)
# Returns: 0 if healthy, 1 if not
# Example: http_health_check "https://api.example.com/health" 5 200
http_health_check() {
  local url="${1:-}"
  local timeout="${2:-10}"
  local expected_status="${3:-200}"

  if [ -z "$url" ]; then
    echo "::error::http_health_check requires URL argument"
    return 1
  fi

  # Perform the check with timeout
  local http_code
  http_code=$(curl -s -w "%{http_code}" \
    --connect-timeout "$timeout" \
    --max-time "$timeout" \
    -o /dev/null \
    "$url" 2>/dev/null) || {
    echo "::warning::HTTP check failed (connection error): $url"
    return 1
  }

  if [ "$http_code" = "$expected_status" ]; then
    echo "✅ Health check passed: $url (HTTP $http_code)"
    return 0
  else
    echo "::warning::Unexpected status code: $http_code (expected $expected_status)"
    return 1
  fi
}

# Poll endpoint until healthy with retries
# Args:
#   $1: URL to check (required)
#   $2: Total timeout in seconds (optional, defaults to 60)
#   $3: Max number of attempts (optional, defaults to 10)
#   $4: Delay between attempts in seconds (optional, defaults to 5)
# Returns: 0 if healthy, 1 if timeout
# Example: wait_for_health "https://api.example.com/health" 60 10 5
wait_for_health() {
  local url="${1:-}"
  local timeout="${2:-60}"
  local max_attempts="${3:-10}"
  local delay="${4:-5}"

  if [ -z "$url" ]; then
    echo "::error::wait_for_health requires URL argument"
    return 1
  fi

  local attempt=0
  local start_time
  start_time=$(date +%s)

  echo "⏳ Waiting for service to be healthy: $url"

  while [ $attempt -lt "$max_attempts" ]; do
    attempt=$((attempt + 1))

    if http_health_check "$url" 5 200; then
      echo "✅ Service is healthy (after $attempt attempt(s))"
      return 0
    fi

    # Check if we've exceeded timeout
    local current_time
    current_time=$(date +%s)
    local elapsed=$((current_time - start_time))

    if [ $elapsed -ge "$timeout" ]; then
      echo "::error::Timeout waiting for service health (${elapsed}s exceeded ${timeout}s)"
      return 1
    fi

    echo "⏳ Attempt $attempt/$max_attempts failed, retrying in ${delay}s..."
    sleep "$delay"
  done

  echo "::error::Max attempts ($max_attempts) exceeded"
  return 1
}

# Check DNS resolution for hostname
# Args:
#   $1: Hostname to resolve (required)
#   $2: Timeout in seconds (optional, defaults to 5)
# Returns: 0 if resolves, 1 if not
# Example: check_dns_resolution "api.example.com"
check_dns_resolution() {
  local hostname="${1:-}"
  local timeout="${2:-5}"

  if [ -z "$hostname" ]; then
    echo "::error::check_dns_resolution requires hostname argument"
    return 1
  fi

  echo "🔍 Checking DNS resolution for: $hostname"

  # Try dig first, fall back to nslookup
  if command -v dig &>/dev/null; then
    if dig +short +timeout=1 "$hostname" @8.8.8.8 >/dev/null 2>&1; then
      echo "✅ DNS resolves: $hostname"
      return 0
    fi
  elif command -v nslookup &>/dev/null; then
    if nslookup "$hostname" 8.8.8.8 >/dev/null 2>&1; then
      echo "✅ DNS resolves: $hostname"
      return 0
    fi
  else
    echo "::warning::dig/nslookup not available, skipping DNS check"
    return 0
  fi

  echo "::warning::DNS resolution failed for: $hostname"
  return 1
}

# Check TLS certificate validity
# Args:
#   $1: Hostname (required)
#   $2: Port (optional, defaults to 443)
#   $3: Minimum validity days (optional, defaults to 1)
# Returns: 0 if valid, 1 if invalid/expired
# Example: check_tls_certificate "api.example.com" 443 30
check_tls_certificate() {
  local hostname="${1:-}"
  local port="${2:-443}"
  local min_days="${3:-1}"

  if [ -z "$hostname" ]; then
    echo "::error::check_tls_certificate requires hostname argument"
    return 1
  fi

  if ! command -v openssl &>/dev/null; then
    echo "::warning::openssl not available, skipping certificate check"
    return 0
  fi

  echo "🔐 Checking TLS certificate for: $hostname:$port"

  # Get certificate expiration date
  local expiry_date
  expiry_date=$(echo | openssl s_client \
    -connect "$hostname:$port" \
    -servername "$hostname" 2>/dev/null \
    | openssl x509 -noout -enddate 2>/dev/null \
    | cut -d= -f2) || {
    echo "::warning::Could not retrieve certificate from $hostname:$port"
    return 1
  }

  if [ -z "$expiry_date" ]; then
    echo "::warning::Could not parse certificate expiry date"
    return 1
  fi

  # Calculate days until expiration
  local expiry_epoch
  local current_epoch
  local days_left

  expiry_epoch=$(date -d "$expiry_date" +%s 2>/dev/null) || {
    echo "::warning::Could not parse date: $expiry_date"
    return 1
  }

  current_epoch=$(date +%s)
  days_left=$(((expiry_epoch - current_epoch) / 86400))

  if [ "$days_left" -lt 0 ]; then
    echo "::error::Certificate has expired (${days_left} days ago)"
    return 1
  elif [ "$days_left" -lt "$min_days" ]; then
    echo "::warning::Certificate expires in $days_left days (less than minimum $min_days)"
    return 1
  else
    echo "✅ Certificate valid for $days_left more days"
    echo "   Expires: $expiry_date"
    return 0
  fi
}

# Comprehensive service readiness check
# Args:
#   $1: Service URL (required, include protocol)
#   $2: Timeout in seconds (optional, defaults to 30)
# Returns: 0 if all checks pass, 1 if any fail
# Example: check_service_ready "https://api.example.com"
check_service_ready() {
  local service_url="${1:-}"
  local timeout="${2:-30}"

  if [ -z "$service_url" ]; then
    echo "::error::check_service_ready requires service URL"
    return 1
  fi

  echo "🚀 Performing comprehensive service readiness check..."

  # Extract hostname and port from URL
  local hostname
  local port
  hostname=$(echo "$service_url" | sed -E 's|.*://([^:/]+).*|\1|')
  port=$(echo "$service_url" | sed -E 's|.*:([0-9]+).*|\1|')
  [ -z "$port" ] && port=443

  # Check 1: DNS resolution
  if ! check_dns_resolution "$hostname"; then
    echo "::error::Service readiness check failed: DNS resolution"
    return 1
  fi

  # Check 2: TLS certificate (if HTTPS)
  if [[ "$service_url" == https://* ]]; then
    if ! check_tls_certificate "$hostname" "$port" 1; then
      echo "::warning::Certificate check failed, continuing..."
    fi
  fi

  # Check 3: HTTP health
  if ! wait_for_health "$service_url/health" "$timeout" 6 5; then
    echo "::error::Service readiness check failed: health endpoint"
    return 1
  fi

  echo "✅ Service is ready!"
  return 0
}
