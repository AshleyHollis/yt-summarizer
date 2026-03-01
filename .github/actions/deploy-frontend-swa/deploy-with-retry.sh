#!/bin/bash
# Deploy to Azure Static Web Apps with retry and timeout logic
# This script wraps the SWA CLI with per-attempt timeout and retry logic

set -euo pipefail

# Configuration from environment variables
: "${AZURE_STATIC_WEB_APPS_API_TOKEN:?Required}"
: "${APP_LOCATION:?Required}"
: "${OUTPUT_LOCATION:-}"
: "${VERBOSE:=false}"
: "${MAX_ATTEMPTS:=3}"
: "${TIMEOUT_SECONDS:=1200}" # 20 minutes per attempt (SWA binary has 15min internal timeout)

# Normalize deployment environment:
# - empty or "default" -> "production" for SWA CLI (production environment)
# - "pr-{N}" -> keep as-is (preview environment)
if [[ -z "${DEPLOYMENT_ENVIRONMENT:-}" || "${DEPLOYMENT_ENVIRONMENT}" == "default" ]]; then
  DEPLOYMENT_ENVIRONMENT="production"
fi

# Export GitHub context for SWA CLI (fixes "Could not get repository branch/url" warnings)
export GITHUB_REPOSITORY="${GITHUB_REPOSITORY:-}"
export GITHUB_REF="${GITHUB_REF:-}"
export GITHUB_SHA="${GITHUB_SHA:-}"
export GITHUB_HEAD_REF="${GITHUB_HEAD_REF:-}"
export GITHUB_BASE_REF="${GITHUB_BASE_REF:-}"
export GITHUB_EVENT_NAME="${GITHUB_EVENT_NAME:-}"
export GITHUB_ACTOR="${GITHUB_ACTOR:-}"

# Set REPOSITORY_BASE for SWA CLI to detect branch (fixes "Could not get repository branch" warning)
if [ -n "${GITHUB_REPOSITORY}" ] && [ -n "${GITHUB_HEAD_REF}" ]; then
  export REPOSITORY_BASE="${GITHUB_REPOSITORY}#${GITHUB_HEAD_REF}"
elif [ -n "${GITHUB_REPOSITORY}" ] && [ -n "${GITHUB_REF##*/}" ]; then
  export REPOSITORY_BASE="${GITHUB_REPOSITORY}#${GITHUB_REF##*/}"
fi

# Determine SWA CLI verbosity flags
VERBOSE_FLAGS=""
if [[ "${VERBOSE}" == "true" ]]; then
  VERBOSE_FLAGS="--verbose=silly"
fi

# Logging helpers
log_info() { echo "[INFO] $*"; }
log_warn() { echo "[WARN] $*"; }
log_error() { echo "[ERROR] $*"; }

# Print deployment header
print_header() {
  echo ""
  echo "============================================================"
  log_info "🚀 Azure Static Web Apps Deployment"
  log_info "   Environment: ${DEPLOYMENT_ENVIRONMENT}"
  log_info "   App Location: ${APP_LOCATION}"
  log_info "   Max Attempts: ${MAX_ATTEMPTS}"
  log_info "   Timeout: ${TIMEOUT_SECONDS}s (final attempt)"
  echo "============================================================"
  echo ""
}

# Print success footer
print_success() {
  local attempt=$1
  local elapsed=$2
  echo ""
  echo "============================================================"
  log_info "✅ Deployment successful! (attempt ${attempt}, ${elapsed}s)"
  echo "============================================================"
}

# Print failure footer
print_failure() {
  echo ""
  echo "============================================================"
  log_error "❌ Deployment failed after ${MAX_ATTEMPTS} attempts"
  echo "============================================================"
}

# Function to run deployment with timeout
run_deploy_with_timeout() {
  local attempt=$1
  local timeout=$2

  # Determine attempt strategy label
  local strategy_label="fail-fast"
  [ "$attempt" -eq "$MAX_ATTEMPTS" ] && strategy_label="extended"

  log_info "📋 Attempt ${attempt}/${MAX_ATTEMPTS} (${strategy_label}, ${timeout}s timeout)"

  local start_time
  start_time=$(date +%s)

  # Build SWA CLI command with optional verbose flag
  local swa_cmd=(
    npx --yes @azure/static-web-apps-cli deploy
    --deployment-token "${AZURE_STATIC_WEB_APPS_API_TOKEN}"
    --app-location "${APP_LOCATION}"
    --output-location "${OUTPUT_LOCATION}"
    --env "${DEPLOYMENT_ENVIRONMENT}"
    --no-use-keychain
  )

  # Add verbose flag if enabled
  if [[ -n "${VERBOSE_FLAGS}" ]]; then
    swa_cmd+=(${VERBOSE_FLAGS})
  fi

  # Run SWA CLI with timeout and capture output
  # Note: SWA CLI returns exit code 0 even on deployment failure — we must parse stdout
  local output_file
  output_file=$(mktemp)

  echo "::group::SWA CLI Output (attempt ${attempt})"

  local cli_exit_code=0
  if timeout "${timeout}s" "${swa_cmd[@]}" 2>&1 | tee "$output_file"; then
    cli_exit_code=0
  else
    cli_exit_code=$?
  fi

  echo "::endgroup::"

  local elapsed=$(($(date +%s) - start_time))

  # Check for deployment failure in output — SWA CLI returns 0 even when deployment fails!
  if grep -q "Deployment Failed" "$output_file" || grep -q "Status: Failed" "$output_file"; then
    local failure_reason
    failure_reason=$(grep -o "Deployment Failure Reason: .*" "$output_file" | head -1 | sed 's/Deployment Failure Reason: //' || echo "Unknown")
    log_error "   ✗ Failed: ${failure_reason} (${elapsed}s)"
    rm -f "$output_file"
    return 1
  fi

  # Check for success indicators in output
  if grep -q "Status: Succeeded" "$output_file" || grep -q "Deployment complete" "$output_file"; then
    log_info "   ✔ Deployed successfully (${elapsed}s)"
    rm -f "$output_file"
    return 0
  fi

  rm -f "$output_file"

  if [ $cli_exit_code -eq 0 ]; then
    log_info "   ✔ Completed (${elapsed}s)"
    return 0
  elif [ $cli_exit_code -eq 124 ]; then
    log_warn "   ⏱  Timed out after ${timeout}s"
    return $cli_exit_code
  else
    log_error "   ✗ Exit code ${cli_exit_code} (${elapsed}s)"
    return $cli_exit_code
  fi
}

# Main execution
print_header

total_start_time=$(date +%s)

# Retry loop with per-attempt timeout strategy:
#   Attempts 1-2: 300s (5 min) fail-fast — catches transient Azure slowness
#   Attempt 3:    1200s (20 min) extended — allows for genuinely slow cold starts
for attempt in $(seq 1 "$MAX_ATTEMPTS"); do
  if [ "$attempt" -eq "$MAX_ATTEMPTS" ]; then
    attempt_timeout="$TIMEOUT_SECONDS"
  else
    attempt_timeout="300"
  fi

  if run_deploy_with_timeout "$attempt" "$attempt_timeout"; then
    total_elapsed=$(($(date +%s) - total_start_time))
    print_success "$attempt" "$total_elapsed"
    echo "DEPLOY_SUCCESS=true" >>"${GITHUB_OUTPUT:-/dev/stdout}"
    echo "DEPLOY_ATTEMPT=$attempt" >>"${GITHUB_OUTPUT:-/dev/stdout}"
    echo "DEPLOY_ENVIRONMENT=${DEPLOYMENT_ENVIRONMENT}" >>"${GITHUB_OUTPUT:-/dev/stdout}"
    exit 0
  fi

  # If this was the last attempt, fail
  if [ "$attempt" -eq "$MAX_ATTEMPTS" ]; then
    print_failure
    echo "DEPLOY_SUCCESS=false" >>"${GITHUB_OUTPUT:-/dev/stdout}"
    exit 1
  fi

  log_info "   ↻ Retrying..."
  echo ""
done
