#!/bin/bash

################################################################################
# Action: detect-pr-code-changes / detect-changes.sh
#
# Purpose: Detects whether a PR contains changes that require image building or
#          deployment. Uses git diff for reliability and handles force preview
#          labels. Returns true only for changes in code directories that
#          actually trigger CI image builds.
#
# Inputs (Environment Variables):
#   BASE_SHA          - Base commit SHA to compare against (default: origin/main)
#   HEAD_SHA          - Head commit SHA to compare (default: HEAD)
#   FORCE_LABELS      - Comma-separated list of labels that force deployment
#   PR_NUMBER         - PR number to check for force labels (optional)
#   FORCE_DEPLOY      - Force deployment regardless of changes (from workflow)
#   GITHUB_TOKEN      - GitHub API token for label fetching
#   GITHUB_REPOSITORY - Repo name for API calls
#   GITHUB_EVENT_NAME - Event type (pull_request, workflow_dispatch)
#
# Outputs:
#   Sets GitHub Actions outputs:
#     - needs_image_build=true|false
#     - needs_deployment=true|false
#   Reports analysis via echo
#
# Process:
#   1. Checks for force preview labels if PR provided
#   2. Handles workflow_dispatch triggers (always force deploy)
#   3. Extracts all changed files using git diff
#   4. Falls back to git log if diff fails
#   5. Filters files by type (code, docker, k8s configs)
#   6. Determines if image build or deployment needed
#
# Error Handling:
#   - Returns no-deployment on git command failures (conservative)
#   - Continues on GitHub API failures
#   - Doesn't fail; always provides output even if detection uncertain
#
################################################################################

set -euo pipefail

BASE_SHA="${BASE_SHA:-origin/main}"
HEAD_SHA="${HEAD_SHA:-HEAD}"
FORCE_LABELS="${FORCE_LABELS:-}"
PR_NUMBER="${PR_NUMBER:-}"
FORCE_DEPLOY="${FORCE_DEPLOY:-false}"
GITHUB_TOKEN="${GITHUB_TOKEN:-}"
GITHUB_REPOSITORY="${GITHUB_REPOSITORY:-}"
GITHUB_EVENT_NAME="${GITHUB_EVENT_NAME:-}"

################################################################################
# Header
################################################################################
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║  Detect PR Code Changes                                                      ║"
echo "╠══════════════════════════════════════════════════════════════════════════════╣"
echo "║  Base SHA: ${BASE_SHA:0:40}"
echo "║  Head SHA: ${HEAD_SHA:0:40}"
echo "║  Event:    ${GITHUB_EVENT_NAME}"
if [ -n "$PR_NUMBER" ]; then
echo "║  PR:       #${PR_NUMBER}"
fi
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""

################################################################################
# Check for force preview labels
################################################################################
FORCE_DEPLOY=false

if [ -n "$PR_NUMBER" ] && [ -n "$FORCE_LABELS" ]; then
  echo "[INFO] ⏳ Checking for force preview labels on PR #$PR_NUMBER..."

  # Get PR labels using GitHub API
  if [ -n "$GITHUB_TOKEN" ]; then
    API_URL="https://api.github.com/repos/$GITHUB_REPOSITORY/pulls/$PR_NUMBER"
    LABELS=$(curl -s -H "Authorization: token $GITHUB_TOKEN" -H "Accept: application/vnd.github.v3+json" "$API_URL" | jq -r '.labels[].name' 2>/dev/null || echo "")

    if [ -n "$LABELS" ]; then
      echo "[INFO]   Labels found: $(echo "$LABELS" | tr '\n' ', ' | sed 's/,$//')"

      # Check if any force label is present
      IFS=',' read -ra LABEL_ARRAY <<< "$FORCE_LABELS"
      for label in "${LABEL_ARRAY[@]}"; do
        label=$(echo "$label" | xargs)  # trim whitespace
        if echo "$LABELS" | grep -q "^$label$"; then
          echo "[INFO] ✓ Force preview label '$label' found"
          FORCE_DEPLOY=true
          break
        fi
      done
    else
      echo "[WARN] ⚠️ Could not fetch PR labels"
    fi
  else
    echo "[WARN] ⚠️ No GITHUB_TOKEN available for API calls"
  fi
fi

# For manual workflow_dispatch triggers, always force deploy (no PR context needed)
if [ "$GITHUB_EVENT_NAME" = "workflow_dispatch" ] || [ "$FORCE_DEPLOY" = "true" ]; then
  echo "[INFO] ✓ Force deployment requested"
  FORCE_DEPLOY=true
fi

if [ "$FORCE_DEPLOY" = "true" ]; then
  echo ""
  echo "[INFO] 🚀 Force deploying - using existing images"
  echo "needs_image_build=false" >> $GITHUB_OUTPUT
  echo "needs_deployment=true" >> $GITHUB_OUTPUT
  echo "needs_backend_deployment=true" >> $GITHUB_OUTPUT
  echo ""
  echo "╔══════════════════════════════════════════════════════════════════════════════╗"
  echo "║  Result: Force deploy enabled                                                ║"
  echo "║  needs_image_build=false | needs_deployment=true | needs_backend_deployment=true ║"
  echo "╚══════════════════════════════════════════════════════════════════════════════╝"
  exit 0
fi

################################################################################
# Detect changed files
################################################################################
echo "[INFO] ⏳ Detecting changed files..."

# For PRs, use merge-base to ensure reliable diff
if [ "$GITHUB_EVENT_NAME" = "pull_request" ]; then
  MERGE_BASE=$(git merge-base "$BASE_SHA" "$HEAD_SHA" 2>/dev/null || echo "$BASE_SHA")
  echo "[INFO]   Using merge-base: ${MERGE_BASE:0:7}"
  FILES=$(git diff --name-only "$MERGE_BASE" "$HEAD_SHA" 2>/dev/null || echo "")
else
  FILES=$(git diff --name-only "$BASE_SHA" "$HEAD_SHA" 2>/dev/null || echo "")
fi

FILE_COUNT=$(echo "$FILES" | grep -c . || echo "0")
echo "[INFO]   Found $FILE_COUNT changed file(s)"

# If still empty, try git show for all commits in the range
if [ -z "$FILES" ]; then
  echo "[INFO] ↻ git diff failed, trying git log --name-only..."
  if [ "$GITHUB_EVENT_NAME" = "pull_request" ]; then
    FILES=$(git log --name-only --pretty=format: "$MERGE_BASE..$HEAD_SHA" 2>/dev/null | sed '/^$/d' | sort | uniq || echo "")
  else
    FILES=$(git log --name-only --pretty=format: "$BASE_SHA..$HEAD_SHA" 2>/dev/null | sed '/^$/d' | sort | uniq || echo "")
  fi
  FILE_COUNT=$(echo "$FILES" | grep -c . || echo "0")
  echo "[INFO]   Found $FILE_COUNT file(s) via git log"
fi

if [ -z "$FILES" ]; then
  echo "[WARN] ⚠️ Could not fetch changed files - assuming no deployment needed"
  echo "needs_image_build=false" >> $GITHUB_OUTPUT
  echo "needs_deployment=false" >> $GITHUB_OUTPUT
  echo "needs_backend_deployment=false" >> $GITHUB_OUTPUT
  echo ""
  echo "╔══════════════════════════════════════════════════════════════════════════════╗"
  echo "║  Result: No changes detected (conservative)                                  ║"
  echo "║  needs_image_build=false | needs_deployment=false | needs_backend_deployment=false ║"
  echo "╚══════════════════════════════════════════════════════════════════════════════╝"
  exit 0
fi

################################################################################
# Analyze files for build/deployment triggers
################################################################################
echo ""
echo "[INFO] ⏳ Analyzing files for build/deployment triggers..."

# Check for changes that require image building vs changes that require deployment
#
# IMAGE BUILD TRIGGERS (CI actually builds new images):
# - services/api/** (API service)
# - services/workers/** (background workers)
# - services/shared/** (shared libraries)
# - apps/web/** (frontend application)
# - **/Dockerfile* (Docker files)
# - docker-compose*.yml (compose files)
# - .dockerignore (docker config)
#
# DEPLOYMENT TRIGGERS (changes that affect what gets deployed):
# - All image build triggers above
# - k8s/** (Kubernetes manifests - change deployment config)
#
# This allows K8s-only changes to trigger preview deployments using existing images

HAS_IMAGE_BUILD=false
HAS_DEPLOYMENT=false
SKIP_COUNT=0
BUILD_COUNT=0
DEPLOY_COUNT=0

while IFS= read -r file; do
  if [[ -n "$file" ]]; then
    # Skip docs, specs, and markdown files
    if [[ "$file" =~ ^docs/ ]] || [[ "$file" =~ ^specs/ ]] || [[ "$file" =~ \.md$ ]]; then
      SKIP_COUNT=$((SKIP_COUNT + 1))
    # Check if file triggers image building
    elif [[ "$file" =~ ^services/api/ ]] || \
      [[ "$file" =~ ^services/workers/ ]] || \
      [[ "$file" =~ ^services/shared/ ]] || \
      [[ "$file" =~ ^apps/web/ ]] || \
      [[ "$file" =~ /Dockerfile ]] || \
      [[ "$file" =~ ^docker-compose.*\.yml$ ]] || \
      [[ "$file" == .dockerignore ]]; then
      BUILD_COUNT=$((BUILD_COUNT + 1))
      HAS_IMAGE_BUILD=true
      HAS_DEPLOYMENT=true
      HAS_BACKEND_DEPLOYMENT=true
    # Check for Kubernetes manifests (triggers backend deployment)
    elif [[ "$file" =~ ^k8s/ ]]; then
      DEPLOY_COUNT=$((DEPLOY_COUNT + 1))
      HAS_DEPLOYMENT=true
    else
      SKIP_COUNT=$((SKIP_COUNT + 1))
    fi
  fi
done <<< "$FILES"

echo "[INFO]   Build triggers:  $BUILD_COUNT file(s)"
echo "[INFO]   Deploy triggers: $DEPLOY_COUNT file(s)"
echo "[INFO]   Skipped:         $SKIP_COUNT file(s)"

################################################################################
# Set outputs
################################################################################
echo "needs_image_build=$HAS_IMAGE_BUILD" >> $GITHUB_OUTPUT
echo "needs_deployment=$HAS_DEPLOYMENT" >> $GITHUB_OUTPUT
echo "needs_backend_deployment=$HAS_BACKEND_DEPLOYMENT" >> $GITHUB_OUTPUT

################################################################################
# Summary
################################################################################
echo ""
echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║  Result: Analysis complete                                                   ║"
echo "║  needs_image_build=${HAS_IMAGE_BUILD} | needs_deployment=${HAS_DEPLOYMENT} | needs_backend_deployment=${HAS_BACKEND_DEPLOYMENT}"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
