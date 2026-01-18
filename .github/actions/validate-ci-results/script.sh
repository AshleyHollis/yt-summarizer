#!/bin/bash

################################################################################
# Action: validate-ci-results / script.sh
#
# Purpose: Validates that all CI jobs passed or were correctly skipped based on
#          changed areas and branch context (main vs PR).
#
# Design: Replicates job condition logic to validate pipeline execution
# - MAIN BRANCH: All jobs MUST run and succeed (no skipping)
# - PR BRANCHES: Jobs can skip if their areas didn't change
#
# Inputs (Environment Variables):
#   IS_MAIN_BRANCH      - Whether this is the main branch (true/false)
#   CHANGED_AREAS       - Space-separated list of changed areas (e.g., "services/api services/shared")
#   ACR_CONFIGURED      - Whether ACR is configured (true/false)
#   TEST_SHARED_RESULT  - Result of test-shared job (success/failure/skipped)
#   TEST_API_RESULT     - Result of test-api job
#   TEST_WORKERS_RESULT - Result of test-workers job
#   TEST_FRONTEND_RESULT- Result of test-frontend job
#   VALIDATE_TERRAFORM_RESULT  - Result of validate-terraform job
#   KUBERNETES_VALIDATE_RESULT - Result of kubernetes-validate job
#   SECRET_SCANNING_RESULT     - Result of secret-scanning job
#   SECRET_SCANNING_SHOULD_RUN - Whether secret-scanning should have run
#   BUILD_IMAGES_RESULT        - Result of build-images job
#   BUILD_IMAGES_VALIDATE_RESULT - Result of build-images-validate job
#
# Logic:
#   1. Check if each job should have run based on changed areas
#   2. Validate job result matches expectation
#   3. Exit with code 0 if all checks pass, 1 if any fail
#
# Maintenance: When adding new jobs to ci.yml, add matching logic in should_run_job()
#
################################################################################

set -euo pipefail

# Helper to check if job should have run based on changed areas
should_run_job() {
  # Main branch: ALL jobs must run
  if [[ "$IS_MAIN_BRANCH" == "true" ]]; then
    return 0
  fi

  # PR branch: Check if areas changed
  case "$1" in
    "test-shared")
      [[ "$CHANGED_AREAS" =~ services/shared ]]
      ;;
    "test-api")
      [[ "$CHANGED_AREAS" =~ services/api ]] || [[ "$CHANGED_AREAS" =~ services/shared ]]
      ;;
    "test-workers")
      [[ "$CHANGED_AREAS" =~ services/workers ]] || [[ "$CHANGED_AREAS" =~ services/shared ]]
      ;;
    "test-frontend")
      [[ "$CHANGED_AREAS" =~ apps/web ]]
      ;;
    "validate-terraform")
      [[ "$CHANGED_AREAS" =~ infra/terraform ]]
      ;;
    "kubernetes-validate")
      [[ "$CHANGED_AREAS" =~ k8s ]]
      ;;
    "build-images")
      # Must have ACR configured AND (main branch OR changes to buildable areas)
      [[ "$ACR_CONFIGURED" == "true" ]] && \
      ([[ "$IS_MAIN_BRANCH" == "true" ]] || \
       [[ "$CHANGED_AREAS" =~ services/api ]] || \
       [[ "$CHANGED_AREAS" =~ services/workers ]] || \
       [[ "$CHANGED_AREAS" =~ services/shared ]] || \
       [[ "$CHANGED_AREAS" =~ apps/web ]] || \
       [[ "$CHANGED_AREAS" =~ docker ]])
      ;;
    *)
      return 1
      ;;
  esac
}

# Helper to check if job passed or was appropriately skipped
check_job() {
  local name=$1
  local result=$2

  if should_run_job "$name"; then
    if [ "$result" != "success" ]; then
      echo "❌ $name failed (result: $result)"
      return 1
    fi
    if [[ "$IS_MAIN_BRANCH" == "true" ]]; then
      echo "✅ $name passed (main branch - required)"
    else
      echo "✅ $name passed"
    fi
  else
    if [[ "$IS_MAIN_BRANCH" == "true" ]]; then
      echo "⚠️  $name skipped on main branch (unexpected!)"
    else
      echo "⏭️  $name skipped (not required)"
    fi
  fi
  return 0
}

EXIT_CODE=0

if [[ "$IS_MAIN_BRANCH" == "true" ]]; then
  echo "🔍 Checking CI results (MAIN BRANCH - full validation required)..."
else
  echo "🔍 Checking CI results (PR branch - smart skipping enabled)..."
fi
echo ""

# Check test jobs
check_job "test-shared" "${TEST_SHARED_RESULT}" || EXIT_CODE=1
check_job "test-api" "${TEST_API_RESULT}" || EXIT_CODE=1
check_job "test-workers" "${TEST_WORKERS_RESULT}" || EXIT_CODE=1
check_job "test-frontend" "${TEST_FRONTEND_RESULT}" || EXIT_CODE=1

# Check validation jobs
check_job "validate-terraform" "${VALIDATE_TERRAFORM_RESULT}" || EXIT_CODE=1
check_job "kubernetes-validate" "${KUBERNETES_VALIDATE_RESULT}" || EXIT_CODE=1

# Check secret scanning
if [[ "$IS_MAIN_BRANCH" == "true" ]] || [[ "${SECRET_SCANNING_SHOULD_RUN}" == "true" ]]; then
  if [ "${SECRET_SCANNING_RESULT}" != "success" ]; then
    echo "❌ secret-scanning failed"
    EXIT_CODE=1
  else
    echo "✅ secret-scanning passed"
  fi
else
  echo "⏭️  secret-scanning skipped (no code changes)"
fi

# Check build jobs - one must succeed if builds are required
if should_run_job "build-images"; then
  BUILD_PUSH="${BUILD_IMAGES_RESULT}"
  BUILD_VALIDATE="${BUILD_IMAGES_VALIDATE_RESULT}"

  if [ "$BUILD_PUSH" = "success" ] || [ "$BUILD_PUSH" = "skipped" -a "$BUILD_VALIDATE" = "success" ]; then
    echo "✅ Build validation passed"
  else
    echo "❌ Build jobs failed: build-images=$BUILD_PUSH, build-images-validate=$BUILD_VALIDATE"
    EXIT_CODE=1
  fi
else
  echo "⏭️  Build jobs skipped (no changes requiring image builds)"
fi

echo ""
if [ $EXIT_CODE -eq 0 ]; then
  echo "🎉 All CI checks passed!"
else
  echo "💥 One or more CI checks failed"
fi

exit $EXIT_CODE
