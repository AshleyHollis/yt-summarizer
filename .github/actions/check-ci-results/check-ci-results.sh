#!/bin/bash
# Purpose: Checks all CI job results and reports pass/fail status
# Inputs: All passed via GitHub Actions inputs as environment variables
# Outputs: Exit code 0 (all passed) or 1 (any failed)
# Logic:
#   1. Define check_job helper function
#   2. For each job, check if it should have run
#   3. If should_run=true, verify result=success; else skip
#   4. Collect exit codes and report overall status
#   5. Display summary with ✅/❌/⏭️ indicators

set -euo pipefail

# Helper to check if job passed or was appropriately skipped
check_job() {
  local name=$1
  local result=$2
  local should_run=$3

  if [ "$should_run" = "true" ]; then
    if [ "$result" != "success" ]; then
      echo "❌ $name failed (result: $result)"
      return 1
    fi
    echo "✅ $name passed"
  else
    echo "⏭️  $name skipped (not required)"
  fi
  return 0
}

EXIT_CODE=0

echo "Checking CI results..."
echo ""

# Check test jobs
check_job "test-shared" "$1" "$2" || EXIT_CODE=1
check_job "test-api" "$3" "$4" || EXIT_CODE=1
check_job "test-workers" "$5" "$6" || EXIT_CODE=1
check_job "test-frontend" "$7" "$8" || EXIT_CODE=1

# Check lint jobs
check_job "lint-python" "$9" "${10}" || EXIT_CODE=1
check_job "lint-frontend" "${11}" "${12}" || EXIT_CODE=1

# Check build/validation jobs
check_job "build-images-validate" "${13}" "${14}" || EXIT_CODE=1
check_job "validate-terraform" "${15}" "${16}" || EXIT_CODE=1
check_job "validate-kustomize" "${17}" "${18}" || EXIT_CODE=1
check_job "kubernetes-validate" "${19}" "${20}" || EXIT_CODE=1
check_job "secret-scanning" "${21}" "${22}" || EXIT_CODE=1

echo ""
if [ $EXIT_CODE -eq 0 ]; then
  echo "✅ All required CI checks passed"
else
  echo "❌ Some CI checks failed"
fi

exit $EXIT_CODE
