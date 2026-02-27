#!/bin/bash
# Purpose: Validates that the image tag matches the expected format
# Args:
#   $1: CI_TAG - Image tag to validate
#   $2: EXPECTED_TAG - Expected tag format
# Outputs: Exit code 0 (valid) or 1 (invalid/mismatch)

set -euo pipefail

CI_TAG="${1:-}"
EXPECTED_TAG="${2:-}"

if [ -z "$CI_TAG" ]; then
  echo "::error::Image tag is empty. Aborting."
  exit 1
fi

# Allow 'latest' for K8s-only changes (production image reuse)
if [ "$CI_TAG" = "latest" ]; then
  echo "✅ Using production image tag: latest (K8s-only changes)"
  exit 0
fi

if [ "$CI_TAG" != "$EXPECTED_TAG" ]; then
  echo "::error::Image tag mismatch: CI='$CI_TAG' expected='$EXPECTED_TAG'. \
    Aborting to avoid inconsistent deployment."
  exit 1
fi

echo "✅ Image tag validated: $CI_TAG"
