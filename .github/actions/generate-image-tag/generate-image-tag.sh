#!/bin/bash
# Purpose: Generate image tag from PR number and commit SHA
# Inputs:
#   PR_NUMBER: Pull request number (optional)
#   COMMIT_SHA: Commit SHA (optional, defaults to HEAD)
#   BRANCH_NAME: Branch name (optional)
#   TAG_PREFIX: Tag prefix mode (auto/pr/sha/branch, default: auto)
# Outputs:
#   image_tag: Generated image tag
#   short_sha: Short commit SHA (7 characters)
#   tag_type: Type of tag generated (pr/sha/branch)
# Logic:
#   1. Determine short SHA from commit-sha or git HEAD
#   2. If TAG_PREFIX=auto, determine tag type based on context
#   3. Generate tag according to type:
#      - pr: "pr-{number}-{sha}"
#      - branch: "branch-{sanitized_name}-{sha}"
#      - sha: "sha-{sha}"
#   4. Sanitize branch names (replace invalid chars with dash)

set -euo pipefail

PR_NUMBER="${PR_NUMBER:-}"
COMMIT_SHA="${COMMIT_SHA:-}"
BRANCH_NAME="${BRANCH_NAME:-}"
TAG_PREFIX="${TAG_PREFIX:-auto}"

# Derive short SHA from provided commit-sha if given, otherwise fall back to HEAD
if [ -n "$COMMIT_SHA" ] && [ "$COMMIT_SHA" != "null" ]; then
  SHORT_SHA=$(git rev-parse --short=7 "$COMMIT_SHA")
else
  SHORT_SHA=$(git rev-parse --short=7 HEAD)
fi

# Determine tag type and generate tag
if [ "$TAG_PREFIX" = "auto" ]; then
  if [ -n "$PR_NUMBER" ] && [ "$PR_NUMBER" != "null" ]; then
    IMAGE_TAG="pr-${PR_NUMBER}-${SHORT_SHA}"
    TAG_TYPE="pr"
  elif [ -n "$BRANCH_NAME" ] && [ "$BRANCH_NAME" != "main" ] && \
    [ "$BRANCH_NAME" != "master" ]; then
    # Sanitize branch name for Docker tag
    CLEAN_BRANCH=$(echo "$BRANCH_NAME" | sed 's/[^a-zA-Z0-9._-]/-/g' | \
      cut -c1-128)
    IMAGE_TAG="branch-${CLEAN_BRANCH}-${SHORT_SHA}"
    TAG_TYPE="branch"
  else
    IMAGE_TAG="sha-${SHORT_SHA}"
    TAG_TYPE="sha"
  fi
else
  # Use explicit prefix
  if [ "$TAG_PREFIX" = "pr" ] && [ -n "$PR_NUMBER" ]; then
    IMAGE_TAG="pr-${PR_NUMBER}-${SHORT_SHA}"
    TAG_TYPE="pr"
  elif [ "$TAG_PREFIX" = "branch" ] && [ -n "$BRANCH_NAME" ]; then
    CLEAN_BRANCH=$(echo "$BRANCH_NAME" | sed 's/[^a-zA-Z0-9._-]/-/g' | \
      cut -c1-128)
    IMAGE_TAG="branch-${CLEAN_BRANCH}-${SHORT_SHA}"
    TAG_TYPE="branch"
  else
    IMAGE_TAG="sha-${SHORT_SHA}"
    TAG_TYPE="sha"
  fi
fi

echo "Generated image tag: $IMAGE_TAG (type: $TAG_TYPE)"
echo "image_tag=$IMAGE_TAG" >> $GITHUB_OUTPUT
echo "short_sha=$SHORT_SHA" >> $GITHUB_OUTPUT
echo "tag_type=$TAG_TYPE" >> $GITHUB_OUTPUT
