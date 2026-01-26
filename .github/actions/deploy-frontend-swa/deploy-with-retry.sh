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

  # Run SWA CLI with timeout
  # Note: timeout command is available in GitHub Actions runners (both Linux and macOS)
  if timeout "${timeout}s" "${swa_cmd[@]}"; then

    local elapsed=$(($(date +%s) - start_time))
    echo "::notice::Deployment to '${DEPLOYMENT_ENVIRONMENT}' succeeded on attempt $attempt (${elapsed}s elapsed)"
    echo "::endgroup::"
    return 0
  else
    local exit_code=$?
    local elapsed=$(($(date +%s) - start_time))

    if [ $exit_code -eq 124 ]; then
      echo "::warning::Deployment attempt $attempt timed out after ${timeout}s"
    else
      echo "::warning::Deployment attempt $attempt failed with exit code $exit_code (${elapsed}s elapsed)"
    fi

    echo "::endgroup::"
    return $exit_code
  fi
}

# Retry loop
for attempt in $(seq 1 "$MAX_ATTEMPTS"); do
  if run_deploy_with_timeout "$attempt" "$TIMEOUT_SECONDS"; then
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
