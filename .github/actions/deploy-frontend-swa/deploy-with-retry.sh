#!/bin/bash
# Deploy to Azure Static Web Apps with retry and timeout logic
# This script wraps the SWA CLI with per-attempt timeout and retry logic

set -euo pipefail

# Configuration from environment variables
: "${AZURE_STATIC_WEB_APPS_API_TOKEN:?Required}"
: "${APP_LOCATION:?Required}"
: "${OUTPUT_LOCATION:-}"
: "${DEPLOYMENT_ENVIRONMENT:=preview}"  # Default to preview, override for production or pr-{number}
: "${VERBOSE:=false}"
: "${MAX_ATTEMPTS:=3}"
: "${TIMEOUT_SECONDS:=480}"  # 8 minutes per attempt (SWA binary has 15min internal timeout)

# Export GitHub context for SWA CLI (fixes "Could not get repository branch/url" warnings)
# These are automatically available in GitHub Actions but need to be explicitly exported
export GITHUB_REPOSITORY="${GITHUB_REPOSITORY:-}"
export GITHUB_REF="${GITHUB_REF:-}"
export GITHUB_SHA="${GITHUB_SHA:-}"
export GITHUB_HEAD_REF="${GITHUB_HEAD_REF:-}"
export GITHUB_BASE_REF="${GITHUB_BASE_REF:-}"
export GITHUB_EVENT_NAME="${GITHUB_EVENT_NAME:-}"
export GITHUB_ACTOR="${GITHUB_ACTOR:-}"

# Set REPOSITORY_BASE for SWA CLI to detect branch (fixes "Could not get repository branch" warning)
# Format: owner/repo#branch
if [ -n "${GITHUB_REPOSITORY}" ] && [ -n "${GITHUB_HEAD_REF}" ]; then
  export REPOSITORY_BASE="${GITHUB_REPOSITORY}#${GITHUB_HEAD_REF}"
  echo "::debug::Set REPOSITORY_BASE=${REPOSITORY_BASE}"
elif [ -n "${GITHUB_REPOSITORY}" ] && [ -n "${GITHUB_REF##*/}" ]; then
  export REPOSITORY_BASE="${GITHUB_REPOSITORY}#${GITHUB_REF##*/}"
  echo "::debug::Set REPOSITORY_BASE=${REPOSITORY_BASE}"
fi

# Determine SWA CLI verbosity flags
VERBOSE_FLAGS=""
if [[ "${VERBOSE}" == "true" ]]; then
  VERBOSE_FLAGS="--verbose=silly"
  echo "::debug::Verbose logging enabled (--verbose=silly)"
fi

# Function to run deployment with timeout
run_deploy_with_timeout() {
  local attempt=$1
  local timeout=$2

  echo "::group::Deployment attempt $attempt of $MAX_ATTEMPTS to '${DEPLOYMENT_ENVIRONMENT}' environment (${timeout}s timeout)"
  echo "::debug::App location: ${APP_LOCATION}"
  echo "::debug::Output location: ${OUTPUT_LOCATION}"
  echo "::debug::Environment: ${DEPLOYMENT_ENVIRONMENT}"

  local start_time=$(date +%s)

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

  echo "::debug::Running command: ${swa_cmd[*]}"

  # Run SWA CLI with timeout and capture output
  # Note: timeout command is available in GitHub Actions runners (both Linux and macOS)
  # We need to capture output because SWA CLI returns exit code 0 even on deployment failure!
  local output_file
  output_file=$(mktemp)

  local cli_exit_code=0
  if timeout "${timeout}s" "${swa_cmd[@]}" 2>&1 | tee "$output_file"; then
    cli_exit_code=0
  else
    cli_exit_code=$?
  fi

  local elapsed=$(($(date +%s) - start_time))

  # Check for deployment failure in output - SWA CLI returns 0 even when deployment fails!
  # Look for explicit failure messages from the CLI
  if grep -q "Deployment Failed" "$output_file" || grep -q "Status: Failed" "$output_file"; then
    local failure_reason
    failure_reason=$(grep -o "Deployment Failure Reason: .*" "$output_file" | head -1 || echo "Unknown reason")
    echo "::warning::Deployment attempt $attempt failed: ${failure_reason} (${elapsed}s elapsed)"
    rm -f "$output_file"
    echo "::endgroup::"
    return 1
  fi

  rm -f "$output_file"

  if [ $cli_exit_code -eq 0 ]; then
    echo "::notice::Deployment to '${DEPLOYMENT_ENVIRONMENT}' succeeded on attempt $attempt (${elapsed}s elapsed)"
    echo "::endgroup::"
    return 0
  elif [ $cli_exit_code -eq 124 ]; then
    echo "::warning::Deployment attempt $attempt timed out after ${timeout}s"
    echo "::endgroup::"
    return $cli_exit_code
  else
    echo "::warning::Deployment attempt $attempt failed with exit code $cli_exit_code (${elapsed}s elapsed)"
    echo "::endgroup::"
    return $cli_exit_code
  fi
}

# Retry loop with per-attempt timeout strategy
# Strategy: Fail fast on attempts 1-2 (5 min timeout), longer timeout on final attempt
for attempt in $(seq 1 "$MAX_ATTEMPTS"); do
  # Determine timeout for this attempt
  if [ "$attempt" -eq "$MAX_ATTEMPTS" ]; then
    # Final attempt: Use configured timeout (default 600s = 10 minutes)
    # This allows more time for genuinely slow deployments
    attempt_timeout="$TIMEOUT_SECONDS"
    echo "::notice::Final attempt - using extended timeout of ${attempt_timeout}s"
  else
    # Attempts 1-2: Short timeout (5 minutes) for fail-fast retry
    # Azure SWA can be transiently slow; quick retry often succeeds
    attempt_timeout="300"
    echo "::notice::Retry attempt ${attempt} - using fail-fast timeout of ${attempt_timeout}s"
  fi

  if run_deploy_with_timeout "$attempt" "$attempt_timeout"; then
    echo "DEPLOY_SUCCESS=true" >> "${GITHUB_OUTPUT:-/dev/stdout}"
    echo "DEPLOY_ATTEMPT=$attempt" >> "${GITHUB_OUTPUT:-/dev/stdout}"
    echo "DEPLOY_ENVIRONMENT=${DEPLOYMENT_ENVIRONMENT}" >> "${GITHUB_OUTPUT:-/dev/stdout}"
    exit 0
  fi

  # If this was the last attempt, fail
  if [ "$attempt" -eq "$MAX_ATTEMPTS" ]; then
    echo "::error::All $MAX_ATTEMPTS deployment attempts to '${DEPLOYMENT_ENVIRONMENT}' failed"
    echo "DEPLOY_SUCCESS=false" >> "${GITHUB_OUTPUT:-/dev/stdout}"
    exit 1
  fi

  # Otherwise, log and continue to next attempt
  echo "Retrying immediately (attempt $((attempt + 1))/$MAX_ATTEMPTS)..."
done
