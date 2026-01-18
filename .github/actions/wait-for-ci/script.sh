#!/bin/bash

################################################################################
# Action: wait-for-ci / script.sh
#
# Purpose: Wait for CI workflow to complete successfully and retrieve image tag artifact.
#          Exits early on CI failure to avoid wasting CPU cycles on doomed deployments.
#
# Inputs (Environment Variables):
#   GITHUB_TOKEN       - GitHub token for API access
#   COMMIT_SHA         - Commit SHA to check CI status for
#   TIMEOUT_SECONDS    - Maximum time to wait (default: 1800 = 30 min)
#   INTERVAL_SECONDS   - Interval between checks in seconds (default: 30)
#   GITHUB_REPOSITORY  - GitHub repository (owner/repo format)
#
# Outputs (via $GITHUB_OUTPUT):
#   image_tag          - Image tag fetched from CI artifacts (if available)
#
# Artifact Retrieval:
#   - Downloads 'image-tag' artifact from successful CI run
#   - If no artifact exists, returns empty string
#   - Preview workflow validates and skips deployment if no images available
#
# Exit Behavior:
#   - Exit 0: CI succeeded (with or without image-tag artifact)
#   - Exit 1: CI failed, was cancelled, or timeout reached
#
################################################################################

set -euo pipefail

GITHUB_TOKEN="${GITHUB_TOKEN:-}"
COMMIT_SHA="${COMMIT_SHA:-}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-1800}"
INTERVAL_SECONDS="${INTERVAL_SECONDS:-30}"
GITHUB_REPOSITORY="${GITHUB_REPOSITORY:-}"

if [[ -z "$GITHUB_TOKEN" ]] || [[ -z "$COMMIT_SHA" ]]; then
  echo "::error::GITHUB_TOKEN and COMMIT_SHA are required"
  exit 1
fi

echo "⏳ Waiting for CI workflow to complete..."
echo "   Commit: $COMMIT_SHA"
echo "   Timeout: $TIMEOUT_SECONDS seconds"
echo "   Check interval: $INTERVAL_SECONDS seconds"

start_time=$(date +%s)
end_time=$((start_time + TIMEOUT_SECONDS))
attempt=1

while [ $(date +%s) -lt $end_time ]; do
  current_time=$(date +%s)
  elapsed=$((current_time - start_time))
  echo "🔍 [$(date '+%H:%M:%S')] Attempt $attempt (elapsed: ${elapsed}s) - Checking CI status..."

  # Get CI workflow runs for this commit (remove event filter to catch all triggers)
  response=$(curl -s -H "Authorization: token $GITHUB_TOKEN" \
    -H "Accept: application/vnd.github.v3+json" \
    "https://api.github.com/repos/$GITHUB_REPOSITORY/actions/runs?head_sha=$COMMIT_SHA")

  # Debug: Show total workflow runs found
  total_runs=$(echo "$response" | jq -r '.total_count // 0')
  echo "   📊 Found $total_runs total workflow runs for commit $COMMIT_SHA"

  # Extract CI workflow run (filter by workflow name "CI")
  ci_run=$(echo "$response" | jq -r '.workflow_runs[] | select(.name == "CI") | .id' | head -1)
  if [ -z "$ci_run" ]; then
    echo "   ❌ No CI workflow run found yet for commit $COMMIT_SHA"
  else
    ci_status=$(echo "$response" | jq -r ".workflow_runs[] | select(.id == ($ci_run | tonumber)) | .status")
    ci_conclusion=$(echo "$response" | jq -r ".workflow_runs[] | select(.id == ($ci_run | tonumber)) | .conclusion")
    echo "   🔗 CI Run ID: $ci_run | Status: $ci_status | Conclusion: $ci_conclusion"

    if [ "$ci_status" = "completed" ]; then
      if [ "$ci_conclusion" = "success" ]; then
        echo "✅ CI workflow completed successfully (took ${elapsed}s)"

        # Attempt to download the image-tag artifact from the CI run (if it exists)
        artifacts_response=$(curl -s -H "Authorization: token $GITHUB_TOKEN" \
          -H "Accept: application/vnd.github.v3+json" \
          "https://api.github.com/repos/$GITHUB_REPOSITORY/actions/runs/$ci_run/artifacts")

        artifact_id=$(echo "$artifacts_response" | jq -r '.artifacts[] | select(.name == "image-tag") | .id' | head -1)
        if [ -n "$artifact_id" ]; then
          echo "   🔽 Found image-tag artifact (id: $artifact_id), downloading..."
          archive_url=$(echo "$artifacts_response" | jq -r ".artifacts[] | select(.id == ($artifact_id | tonumber)) | .archive_download_url")
          curl -s -L -H "Authorization: token $GITHUB_TOKEN" -o /tmp/artifacts.zip "$archive_url"
          mkdir -p /tmp/artifacts && unzip -o /tmp/artifacts.zip -d /tmp/artifacts >/dev/null

          if [ -f /tmp/artifacts/image-tag.txt ]; then
            TAG=$(cat /tmp/artifacts/image-tag.txt | tr -d '\r\n')
            echo "   ✅ Retrieved image tag from artifact: $TAG"
            echo "image_tag=$TAG" >> $GITHUB_OUTPUT
          else
            echo "   ⚠️ image-tag artifact found but file not present"
            echo "image_tag=" >> $GITHUB_OUTPUT
          fi
        else
          echo "   ⚠️ No image-tag artifact found on CI run"
          echo "image_tag=" >> $GITHUB_OUTPUT
        fi

        exit 0
      elif [ "$ci_conclusion" = "failure" ]; then
        echo "::error::CI workflow failed. Stopping preview deployment."
        exit 1
      elif [ "$ci_conclusion" = "cancelled" ]; then
        echo "::error::CI workflow was cancelled. Stopping preview deployment."
        exit 1
      else
        echo "::error::CI workflow completed with unexpected conclusion: $ci_conclusion"
        exit 1
      fi
    fi
  fi

  # Wait before next check
  attempt=$((attempt + 1))
  sleep $INTERVAL_SECONDS
done

echo "::error::Timeout waiting for CI workflow to complete after $TIMEOUT_SECONDS seconds"
exit 1
