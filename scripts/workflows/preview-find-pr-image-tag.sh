#!/bin/bash
# =============================================================================
# Find most recent image-building commit in PR history
# =============================================================================
# Used by: .github/workflows/preview.yml (get-production-tag job, lines 402-465)
# Purpose: For K8s-only changes, find deterministic image tag by walking PR
#          git history backwards to find last code change
#
# Inputs:
#   - PR_NUMBER: Pull request number
#   - BASE_BRANCH: Base branch (default: main)
#
# Outputs:
#   - image_tag: Either pr-{number}-{sha} or fallback production tag
#
# Logic:
#   1. Walk commits in PR from newest to oldest
#   2. Find first commit that changed code areas (services/*, apps/web, docker)
#   3. Generate tag: pr-{number}-{short_sha}
#   4. If no code changes found, fall back to production tag from main
#   5. Validate that production tag is deterministic (not "latest")
#
# Exit: Fails if no valid tag can be determined
# =============================================================================

set -e  # Exit on error

PR_NUMBER="${1}"
BASE_BRANCH="${2:-main}"

echo "🔍 Searching PR #$PR_NUMBER history for most recent code change..."

# Get list of commits in this PR (from base branch to HEAD)
git fetch origin "$BASE_BRANCH"
COMMITS=$(git rev-list "origin/$BASE_BRANCH"..HEAD)

FOUND_IMAGE_TAG=""
FOUND_COMMIT=""

# Walk commits from newest to oldest
for commit in $COMMITS; do
  SHORT_SHA=$(git rev-parse --short=7 "$commit")

  # Check if this commit changed code areas that trigger image builds
  # Skip merge commits by checking parent count
  PARENT_COUNT=$(git rev-list --parents -n 1 "$commit" | awk '{print NF-1}')

  if [ "$PARENT_COUNT" -le 1 ]; then
    # Regular commit, not a merge
    CHANGED_FILES=$(git diff-tree --no-commit-tree --name-only -r "$commit" 2>/dev/null || true)

    if echo "$CHANGED_FILES" | grep -qE '^(services/api|services/workers|services/shared|apps/web|docker)/'; then
      FOUND_COMMIT="$commit"
      FOUND_IMAGE_TAG="pr-${PR_NUMBER}-${SHORT_SHA}"
      echo "✅ Found code change at commit $SHORT_SHA"
      echo "   Files changed: $(echo "$CHANGED_FILES" | grep -E '^(services/api|services/workers|services/shared|apps/web|docker)/' | head -3 | tr '\n' ' ')"
      break
    fi
  fi
done

# If no code changes found in PR, fallback to production tag
if [ -z "$FOUND_IMAGE_TAG" ]; then
  echo "⚠️  No code changes found in PR history"
  echo "📦 Falling back to production image tag from main branch"

  # Read production kustomization.yaml for deterministic SHA-based tag
  git fetch origin main
  PROD_TAG=$(git show origin/main:k8s/overlays/prod/kustomization.yaml | grep -oP 'newTag: \K.*' | head -1)

  if [ -z "$PROD_TAG" ]; then
    echo "::error::Could not find production image tag in kustomization.yaml"
    exit 1
  fi

  if [ "$PROD_TAG" = "latest" ]; then
    echo "::error::Production kustomization is using 'latest' tag - not deterministic!"
    echo "::error::Production deployment must use SHA-based tags (e.g., sha-abc123f)"
    exit 1
  fi

  echo "✅ Using production tag: $PROD_TAG"
  FOUND_IMAGE_TAG="$PROD_TAG"
fi

echo "image_tag=$FOUND_IMAGE_TAG" >> $GITHUB_OUTPUT
echo "🎯 Final image tag for K8s-only preview: $FOUND_IMAGE_TAG"
