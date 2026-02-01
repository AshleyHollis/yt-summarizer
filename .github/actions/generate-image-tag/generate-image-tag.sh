#!/bin/bash
################################################################################
# Action: generate-image-tag / generate-image-tag.sh
#
# Purpose: Generate image tag from PR number and commit SHA
#
# Inputs (Environment Variables):
#   PR_NUMBER  - Pull request number (optional)
#   COMMIT_SHA - Commit SHA (optional, defaults to HEAD)
#   BRANCH_NAME - Branch name (optional)
#   TAG_PREFIX - Tag prefix mode (auto/pr/sha/branch, default: auto)
#
# Outputs:
#   image_tag - Generated image tag
#   short_sha - Short commit SHA (7 characters)
#   tag_type  - Type of tag generated (pr/sha/branch)
#
# Logic:
#   1. Determine short SHA from commit-sha or git HEAD
#   2. If TAG_PREFIX=auto, determine tag type based on context
#   3. Generate tag according to type:
#      - pr: "pr-{number}-{sha}"
#      - branch: "branch-{sanitized_name}-{sha}"
#      - sha: "sha-{sha}"
#   4. Sanitize branch names (replace invalid chars with dash)
################################################################################

set -euo pipefail

PR_NUMBER="${PR_NUMBER:-}"
COMMIT_SHA="${COMMIT_SHA:-}"
BRANCH_NAME="${BRANCH_NAME:-}"
TAG_PREFIX="${TAG_PREFIX:-auto}"

################################################################################
# Header
################################################################################
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║  Generate Image Tag                                                          ║"
echo "╠══════════════════════════════════════════════════════════════════════════════╣"
if [ -n "$PR_NUMBER" ] && [ "$PR_NUMBER" != "null" ]; then
echo "║  PR Number:   #${PR_NUMBER}"
fi
if [ -n "$COMMIT_SHA" ] && [ "$COMMIT_SHA" != "null" ]; then
echo "║  Commit SHA:  ${COMMIT_SHA:0:7}"
fi
if [ -n "$BRANCH_NAME" ]; then
echo "║  Branch:      ${BRANCH_NAME}"
fi
echo "║  Tag Prefix:  ${TAG_PREFIX}"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""

################################################################################
# Derive short SHA
################################################################################
echo "[INFO] ⏳ Determining short SHA..."

if [ -n "$COMMIT_SHA" ] && [ "$COMMIT_SHA" != "null" ]; then
  SHORT_SHA=$(git rev-parse --short=7 "$COMMIT_SHA")
  echo "[INFO] ✓ Using provided commit: ${SHORT_SHA}"
else
  SHORT_SHA=$(git rev-parse --short=7 HEAD)
  echo "[INFO] ✓ Using HEAD: ${SHORT_SHA}"
fi

################################################################################
# Generate tag based on context
################################################################################
echo "[INFO] ⏳ Generating image tag..."

if [ "$TAG_PREFIX" = "auto" ]; then
  if [ -n "$PR_NUMBER" ] && [ "$PR_NUMBER" != "null" ]; then
    IMAGE_TAG="pr-${PR_NUMBER}-${SHORT_SHA}"
    TAG_TYPE="pr"
    echo "[INFO] ✓ Auto-detected PR context"
  elif [ -n "$BRANCH_NAME" ] && [ "$BRANCH_NAME" != "main" ] && [ "$BRANCH_NAME" != "master" ]; then
    # Sanitize branch name for Docker tag
    CLEAN_BRANCH=$(echo "$BRANCH_NAME" | sed 's/[^a-zA-Z0-9._-]/-/g' | cut -c1-128)
    IMAGE_TAG="branch-${CLEAN_BRANCH}-${SHORT_SHA}"
    TAG_TYPE="branch"
    echo "[INFO] ✓ Auto-detected branch context"
  else
    IMAGE_TAG="sha-${SHORT_SHA}"
    TAG_TYPE="sha"
    echo "[INFO] ✓ Using SHA-only tag"
  fi
else
  # Use explicit prefix
  if [ "$TAG_PREFIX" = "pr" ] && [ -n "$PR_NUMBER" ]; then
    IMAGE_TAG="pr-${PR_NUMBER}-${SHORT_SHA}"
    TAG_TYPE="pr"
  elif [ "$TAG_PREFIX" = "branch" ] && [ -n "$BRANCH_NAME" ]; then
    CLEAN_BRANCH=$(echo "$BRANCH_NAME" | sed 's/[^a-zA-Z0-9._-]/-/g' | cut -c1-128)
    IMAGE_TAG="branch-${CLEAN_BRANCH}-${SHORT_SHA}"
    TAG_TYPE="branch"
  else
    IMAGE_TAG="sha-${SHORT_SHA}"
    TAG_TYPE="sha"
  fi
  echo "[INFO] ✓ Using explicit prefix: ${TAG_PREFIX}"
fi

################################################################################
# Set outputs
################################################################################
echo "image_tag=$IMAGE_TAG" >> $GITHUB_OUTPUT
echo "short_sha=$SHORT_SHA" >> $GITHUB_OUTPUT
echo "tag_type=$TAG_TYPE" >> $GITHUB_OUTPUT

################################################################################
# Summary
################################################################################
echo ""
echo "[INFO] Generated tag: ${IMAGE_TAG}"
echo "[INFO] Tag type:      ${TAG_TYPE}"
echo "[INFO] Short SHA:     ${SHORT_SHA}"
echo ""
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║  Result: ✓ SUCCESS                                                           ║"
echo "║  Tag: ${IMAGE_TAG}"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
