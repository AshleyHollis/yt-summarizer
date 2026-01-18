#!/bin/bash

################################################################################
# Action: validate-acr-image / check-acr-image.sh
#
# Purpose: Verifies that a specific image tag exists in Azure Container
#          Registry before attempting deployment. Provides actionable guidance
#          if image is missing.
#
# Inputs (Environment Variables):
#   REGISTRY          - Container registry name (without .azurecr.io suffix)
#   REPOSITORY        - Repository name (e.g., yt-summarizer-api)
#   TAG               - Image tag to validate
#   FAIL_IF_MISSING   - Whether to fail if image doesn't exist (default: true)
#
# Outputs:
#   Sets GitHub Actions outputs:
#     - exists=true|false
#     - digest=<manifest_digest>  (empty if not found)
#   Reports status via GitHub Actions commands (::error::, ::warning::, ::group::)
#
# Process:
#   1. Uses `az acr repository show` to check image existence
#   2. Extracts image digest from manifest if found
#   3. If missing and fail-if-missing=true, shows helpful diagnostic info
#   4. Lists available tags to help debugging
#   5. Provides actionable troubleshooting steps
#
# Error Handling:
#   - Exits with code 1 if image missing and fail-if-missing=true
#   - Handles jq JSON parsing failures gracefully
#   - Continues on AZ CLI errors if diagnostic commands fail
#
################################################################################

set -euo pipefail

REGISTRY="${REGISTRY:?REGISTRY not set}"
REPOSITORY="${REPOSITORY:?REPOSITORY not set}"
TAG="${TAG:?TAG not set}"
FAIL_IF_MISSING="${FAIL_IF_MISSING:?FAIL_IF_MISSING not set}"

echo "🔍 Validating image exists in ACR..."
echo "  Registry: ${REGISTRY}.azurecr.io"
echo "  Repository: ${REPOSITORY}"
echo "  Tag: ${TAG}"

# Try to get manifest for the specific tag
# This requires authentication, which should be set up by Azure Login action
MANIFEST=$(az acr repository show --name "$REGISTRY" --image "${REPOSITORY}:${TAG}" --output json 2>&1 || echo "")

if [ -z "$MANIFEST" ] || [[ "$MANIFEST" == *"not found"* ]] || [[ "$MANIFEST" == *"ResourceNotFound"* ]]; then
  echo "exists=false" >> $GITHUB_OUTPUT
  echo "digest=" >> $GITHUB_OUTPUT

  echo "::warning::❌ Image NOT found: ${REGISTRY}.azurecr.io/${REPOSITORY}:${TAG}"

  if [ "$FAIL_IF_MISSING" = "true" ]; then
    echo ""
    echo "::error::Required image does not exist in ACR!"
    echo "::error::  Registry: ${REGISTRY}.azurecr.io"
    echo "::error::  Image: ${REPOSITORY}:${TAG}"
    echo ""
    echo "::group::🔧 How to Fix This"
    echo "This usually means the CI workflow didn't complete successfully or didn't push images."
    echo ""
    echo "Options:"
    echo "  1. **Re-run the CI workflow** for the commit that changed code"
    echo "     - Go to Actions → CI → Find the run for this commit → Re-run failed jobs"
    echo ""
    echo "  2. **Check if CI completed successfully**"
    echo "     - The build-images job must succeed and push to ACR"
    echo "     - Check for authentication or permission errors"
    echo ""
    echo "  3. **Push a new commit with code changes** to trigger a fresh CI build"
    echo "     - This will ensure new images are built and pushed"
    echo ""
    echo "  4. **Verify Azure credentials** if this is the first deployment"
    echo "     - Ensure AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID are set"
    echo "     - Check that the service principal has AcrPush permissions"
    echo "::endgroup::"
    echo ""

    # List available tags for this repository to help debugging
    echo "::group::📦 Available Tags in ${REPOSITORY}"
    az acr repository show-tags \
      --name "$REGISTRY" \
      --repository "$REPOSITORY" \
      --orderby time_desc \
      --output table \
      --top 20 2>/dev/null || \
      echo "Could not list tags (permission issue or repository doesn't exist)"
    echo "::endgroup::"

    exit 1
  fi
else
  # Extract digest from manifest
  # Use set +e temporarily to prevent pipefail from stopping on jq errors
  set +e
  DIGEST=$(echo "$MANIFEST" | jq -r '.digest // ""' 2>/dev/null)
  set -e

  # Fallback if jq fails or returns null
  if [ -z "$DIGEST" ] || [ "$DIGEST" = "null" ]; then
    DIGEST=""
  fi

  echo "exists=true" >> $GITHUB_OUTPUT
  echo "digest=${DIGEST}" >> $GITHUB_OUTPUT

  echo "✅ Image exists in ACR"
  if [ -n "$DIGEST" ]; then
    echo "   Digest: ${DIGEST}"
  fi
fi
