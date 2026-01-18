#!/bin/bash
# =============================================================================
# Validate Resource Quota
# =============================================================================
# PURPOSE:
#   Validates that Kubernetes manifest resources are within quota limits
#
# INPUTS (via environment variables):
#   MANIFEST_FILE       Path to the Kubernetes manifest file to validate
#   MAX_CPU             Maximum CPU requests in millicores
#   MAX_MEMORY          Maximum memory requests in Mi
#   RESOURCE_NAME       Name of the resource for error messages
#
# OUTPUTS:
#   Exit code 0 if validation passes, 1 if fails
#
# LOGIC:
#   1. Verify manifest file exists
#   2. Validate CPU quota if specified using Python script
#   3. Validate memory quota if specified using Python script
#   4. If no limits specified, skip validation
#   5. On failure, display manifest preview and exit with error
#
# =============================================================================
set -euo pipefail

if [ ! -f "${MANIFEST_FILE}" ]; then
  echo "::error::Manifest file not found: ${MANIFEST_FILE}"
  exit 1
fi

echo "Validating resource quotas for ${RESOURCE_NAME}..."

# Validate CPU if specified
if [ -n "${MAX_CPU}" ]; then
  if [ -f scripts/ci/validate_kustomize.py ]; then
    if ! python scripts/ci/validate_kustomize.py \
      --file "${MANIFEST_FILE}" \
      --max-cpu "${MAX_CPU}" \
      --name "${RESOURCE_NAME}"; then
      echo "::error::${RESOURCE_NAME} CPU requests exceed quota (${MAX_CPU}m)"
      echo "--- Manifest preview (first 200 lines) ---"
      head -n 200 "${MANIFEST_FILE}" || true
      exit 1
    fi
    echo "✅ CPU quota validation passed (max: ${MAX_CPU}m)"
  else
    echo "⚠️ Skipping CPU validation (validate_kustomize.py not found)"
  fi
fi

# Validate memory if specified
if [ -n "${MAX_MEMORY}" ]; then
  if [ -f scripts/ci/validate_kustomize.py ]; then
    if ! python scripts/ci/validate_kustomize.py \
      --file "${MANIFEST_FILE}" \
      --max-memory "${MAX_MEMORY}" \
      --name "${RESOURCE_NAME}"; then
      echo "::error::${RESOURCE_NAME} memory requests exceed quota " \
        "(${MAX_MEMORY}Mi)"
      echo "--- Manifest preview (first 200 lines) ---"
      head -n 200 "${MANIFEST_FILE}" || true
      exit 1
    fi
    echo "✅ Memory quota validation passed (max: ${MAX_MEMORY}Mi)"
  else
    echo "⚠️ Skipping memory validation (validate_kustomize.py not found)"
  fi
fi

if [ -z "${MAX_CPU}" ] && [ -z "${MAX_MEMORY}" ]; then
  echo "⚠️ No quota limits specified - skipping validation"
fi
