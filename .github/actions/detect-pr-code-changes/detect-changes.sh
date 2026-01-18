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

echo "Comparing: $BASE_SHA...$HEAD_SHA"

# Check for force preview labels if PR number provided
FORCE_DEPLOY=false
if [ -n "$PR_NUMBER" ] && [ -n "$FORCE_LABELS" ]; then
  echo "Checking for force preview labels on PR #$PR_NUMBER..."

  # Get PR labels using GitHub API
  if [ -n "$GITHUB_TOKEN" ]; then
    API_URL="https://api.github.com/repos/$GITHUB_REPOSITORY/pulls/$PR_NUMBER"
    LABELS=$(curl -s -H "Authorization: token $GITHUB_TOKEN" -H "Accept: application/vnd.github.v3+json" "$API_URL" | jq -r '.labels[].name' 2>/dev/null || echo "")

    if [ -n "$LABELS" ]; then
      echo "PR labels: $LABELS"

      # Check if any force label is present
      IFS=',' read -ra LABEL_ARRAY <<< "$FORCE_LABELS"
      for label in "${LABEL_ARRAY[@]}"; do
        label=$(echo "$label" | xargs)  # trim whitespace
        if echo "$LABELS" | grep -q "^$label$"; then
          echo "✅ Force preview label '$label' found - forcing deployment"
          FORCE_DEPLOY=true
          break
        fi
      done
    else
      echo "Could not fetch PR labels"
    fi
  else
    echo "No GITHUB_TOKEN available for API calls"
  fi
fi

# For manual workflow_dispatch triggers, always force deploy (no PR context needed)
if [ "$GITHUB_EVENT_NAME" = "workflow_dispatch" ] || [ "$FORCE_DEPLOY" = "true" ]; then
  echo "🚀 Force deployment requested - proceeding with deployment"
  FORCE_DEPLOY=true
fi

if [ "$FORCE_DEPLOY" = "true" ]; then
  echo "needs_image_build=false" >> $GITHUB_OUTPUT
  echo "needs_deployment=true" >> $GITHUB_OUTPUT
  echo "🚀 Force deploying - using existing images"
  exit 0
fi

# Get all changed files using git diff
# Use merge-base for reliable comparison
echo "🔍 Attempting to detect changed files..."
echo "   BASE_SHA: $BASE_SHA"
echo "   HEAD_SHA: $HEAD_SHA"

# For PRs, use merge-base to ensure reliable diff
if [ "$GITHUB_EVENT_NAME" = "pull_request" ]; then
  MERGE_BASE=$(git merge-base "$BASE_SHA" "$HEAD_SHA" 2>/dev/null || echo "$BASE_SHA")
  echo "   Using merge-base: $MERGE_BASE"
  FILES=$(git diff --name-only "$MERGE_BASE" "$HEAD_SHA" 2>/dev/null || echo "")
else
  FILES=$(git diff --name-only "$BASE_SHA" "$HEAD_SHA" 2>/dev/null || echo "")
fi

echo "   git diff result: $(echo "$FILES" | wc -l) files found"

# If still empty, try git show for all commits in the range
if [ -z "$FILES" ]; then
  echo "   git diff failed, trying git log --name-only..."
  if [ "$GITHUB_EVENT_NAME" = "pull_request" ]; then
    FILES=$(git log --name-only --pretty=format: "$MERGE_BASE..$HEAD_SHA" 2>/dev/null | sed '/^$/d' | sort | uniq || echo "")
  else
    FILES=$(git log --name-only --pretty=format: "$BASE_SHA..$HEAD_SHA" 2>/dev/null | sed '/^$/d' | sort | uniq || echo "")
  fi
  echo "   git log result: $(echo "$FILES" | wc -l) files found"
fi

if [ -z "$FILES" ]; then
  echo "⚠️ Could not fetch changed files - assuming no deployment needed for safety"
  echo "needs_image_build=false" >> $GITHUB_OUTPUT
  echo "needs_deployment=false" >> $GITHUB_OUTPUT
  exit 0
fi

echo "Files changed in this comparison:"
echo "$FILES"

# Check if any file would trigger image building in CI
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
echo "🔍 Analyzing files for build/deployment triggers..."
while IFS= read -r file; do
  if [[ -n "$file" ]]; then
    echo "  📄 Processing: $file"
    # Skip docs, specs, and markdown files
    if [[ "$file" =~ ^docs/ ]] || [[ "$file" =~ ^specs/ ]] || [[ "$file" =~ \.md$ ]]; then
      echo "     [skip] docs/specs/markdown"
    # Check if file triggers image building
    elif [[ "$file" =~ ^services/api/ ]] || \
      [[ "$file" =~ ^services/workers/ ]] || \
      [[ "$file" =~ ^services/shared/ ]] || \
      [[ "$file" =~ ^apps/web/ ]] || \
      [[ "$file" =~ /Dockerfile ]] || \
      [[ "$file" =~ ^docker-compose.*\.yml$ ]] || \
      [[ "$file" == .dockerignore ]]; then
      echo "     [BUILD] triggers image build"
      HAS_IMAGE_BUILD=true
      HAS_DEPLOYMENT=true
    # Check if file triggers deployment (but not image build)
    elif [[ "$file" =~ ^k8s/ ]]; then
      echo "     [DEPLOY] triggers deployment (K8s config)"
      HAS_DEPLOYMENT=true
    else
      echo "     [skip] does not trigger build or deployment"
    fi
  fi
done <<< "$FILES"

echo "📊 Analysis Results:"
echo "   needs_image_build=$HAS_IMAGE_BUILD"
echo "   needs_deployment=$HAS_DEPLOYMENT"

# Set outputs
echo "needs_image_build=$HAS_IMAGE_BUILD" >> $GITHUB_OUTPUT
echo "needs_deployment=$HAS_DEPLOYMENT" >> $GITHUB_OUTPUT
