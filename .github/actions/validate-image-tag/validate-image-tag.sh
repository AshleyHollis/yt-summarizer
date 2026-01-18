#!/bin/bash
# Purpose: Validates that the canonical image tag matches the expected tag
# Inputs:
#   CI_TAG: Image tag extracted from CI artifact
#   EXPECTED_TAG: Expected tag (computed by generate-image-tag action)
# Outputs: Exit code 0 (valid) or 1 (invalid/mismatch)
# Logic:
#   1. Check if CI_TAG is empty (error condition)
#   2. Allow 'latest' tag for K8s-only changes (production image reuse)
#   3. Compare CI_TAG against EXPECTED_TAG
#   4. Exit with error if mismatch to avoid inconsistent preview

set -euo pipefail

CI_TAG="${CI_TAG:-}"
EXPECTED_TAG="${EXPECTED_TAG:-}"

if [ -z "$CI_TAG" ]; then
  echo "::error::Canonical image_tag from CI is empty. Aborting."
  exit 1
fi

# Allow 'latest' for K8s-only changes (production image reuse)
if [ "$CI_TAG" = "latest" ]; then
  echo "✅ Using production image tag: latest (K8s-only changes)"
  exit 0
fi

if [ "$CI_TAG" != "$EXPECTED_TAG" ]; then
  echo "::error::Image tag mismatch: CI='$CI_TAG' expected='$EXPECTED_TAG'. \
    Aborting to avoid inconsistent preview."
  exit 1
fi

echo "✅ Image tag validated: $CI_TAG"
