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

# Validate required tools
for tool in curl jq unzip; do
  if ! command -v "$tool" &>/dev/null; then
    echo "::error::Required tool '$tool' not found in PATH"
    exit 1
  fi
done

GITHUB_TOKEN="${GITHUB_TOKEN:-}"
COMMIT_SHA="${COMMIT_SHA:-}"
PR_NUMBER="${PR_NUMBER:-}"
TIMEOUT_SECONDS="${TIMEOUT_SECONDS:-1800}"
INTERVAL_SECONDS="${INTERVAL_SECONDS:-30}"
WORKFLOW_FILE="${WORKFLOW_FILE:-ci.yml}"
WORKFLOW_EVENT="${WORKFLOW_EVENT:-}"
GITHUB_REPOSITORY="${GITHUB_REPOSITORY:-}"

if [[ -z "$GITHUB_TOKEN" ]] || [[ -z "$COMMIT_SHA" ]]; then
  echo "::error::GITHUB_TOKEN and COMMIT_SHA are required"
  exit 1
fi

if [[ -z "$GITHUB_REPOSITORY" ]]; then
  echo "::error::GITHUB_REPOSITORY is required"
  exit 1
fi

# Function to check PR state (returns 0=open/unknown, 1=closed)
check_pr_state() {
  local pr_number="$1"
  
  # Skip check if no PR number provided
  if [[ -z "$pr_number" ]]; then
    return 0
  fi

  # Query GitHub API for PR state
  local http_code
  local response
  response=$(curl -s -w "\n%{http_code}" \
    -H "Authorization: token $GITHUB_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/$GITHUB_REPOSITORY/pulls/$pr_number")
  
  http_code=$(echo "$response" | tail -n1)
  local body=$(echo "$response" | head -n-1)

  # Handle HTTP errors
  if [[ "$http_code" != "200" ]]; then
    echo "   ⚠️ Failed to check PR state (HTTP $http_code), assuming open"
    return 0
  fi

  # Parse PR state
  local pr_state=$(echo "$body" | jq -r '.state // empty')
  
  if [[ "$pr_state" == "closed" ]]; then
    return 1
  fi
  
  return 0
}

echo "⏳ Waiting for CI workflow to complete..."
echo "   Commit: $COMMIT_SHA"
echo "   Timeout: $TIMEOUT_SECONDS seconds"
echo "   Check interval: $INTERVAL_SECONDS seconds"

start_time=$(date +%s)
end_time=$((start_time + TIMEOUT_SECONDS))
attempt=1

while [ $(date +%s) -lt $end_time ]; do
  # Check if PR is still open
  if ! check_pr_state "$PR_NUMBER"; then
    echo "::notice::PR $PR_NUMBER is closed; skipping wait for CI."
    echo "image_tag=" >> ${GITHUB_OUTPUT:-/dev/null}
    echo "ci_run_id=" >> ${GITHUB_OUTPUT:-/dev/null}
    exit 0
  fi

  current_time=$(date +%s)
  elapsed=$((current_time - start_time))
  echo "🔍 [$(date '+%H:%M:%S')] Attempt $attempt (elapsed: ${elapsed}s) - Checking CI status..."

  # Get CI workflow runs for this commit
  query="head_sha=$COMMIT_SHA"
  if [ -n "$WORKFLOW_EVENT" ]; then
    query="$query&event=$WORKFLOW_EVENT"
  fi
  
  response=$(curl -s -w "\n%{http_code}" \
    -H "Authorization: token $GITHUB_TOKEN" \
    -H "Accept: application/vnd.github.v3+json" \
    "https://api.github.com/repos/$GITHUB_REPOSITORY/actions/workflows/$WORKFLOW_FILE/runs?$query")
  
  http_code=$(echo "$response" | tail -n1)
  body=$(echo "$response" | head -n-1)

  # Handle API errors
  if [[ "$http_code" != "200" ]]; then
    echo "   ⚠️ GitHub API returned HTTP $http_code, retrying..."
    attempt=$((attempt + 1))
    sleep $INTERVAL_SECONDS
    continue
  fi

  # Debug: Show total workflow runs found
  total_runs=$(echo "$body" | jq -r '.total_count // 0')
  echo "   📊 Found $total_runs total workflow runs for commit $COMMIT_SHA"

  # Extract latest CI workflow run
  ci_run=$(echo "$body" | jq -r '.workflow_runs[0].id // empty')
  if [ -z "$ci_run" ]; then
    echo "   ❌ No CI workflow run found yet for commit $COMMIT_SHA"
  else
    ci_status=$(echo "$body" | jq -r ".workflow_runs[0].status // empty")
    ci_conclusion=$(echo "$body" | jq -r ".workflow_runs[0].conclusion // empty")
    echo "   🔗 CI Run ID: $ci_run | Status: $ci_status | Conclusion: $ci_conclusion"

    if [ "$ci_status" = "completed" ]; then
      if [ "$ci_conclusion" = "success" ]; then
        echo "✅ CI workflow completed successfully (took ${elapsed}s)"

        echo "ci_run_id=$ci_run" >> ${GITHUB_OUTPUT:-/dev/null}

        # Attempt to download the image-tag artifact from the CI run (if it exists)
        artifacts_response=$(curl -s -w "\n%{http_code}" \
          -H "Authorization: token $GITHUB_TOKEN" \
          -H "Accept: application/vnd.github.v3+json" \
          "https://api.github.com/repos/$GITHUB_REPOSITORY/actions/runs/$ci_run/artifacts")
        
        artifacts_http_code=$(echo "$artifacts_response" | tail -n1)
        artifacts_body=$(echo "$artifacts_response" | head -n-1)

        if [[ "$artifacts_http_code" == "200" ]]; then
          artifact_id=$(echo "$artifacts_body" | jq -r '.artifacts[] | select(.name == "image-tag") | .id' | head -1)
          if [ -n "$artifact_id" ]; then
            echo "   🔽 Found image-tag artifact (id: $artifact_id), downloading..."
            archive_url=$(echo "$artifacts_body" | jq -r ".artifacts[] | select(.id == ($artifact_id | tonumber)) | .archive_download_url")
            
            if curl -s -L -H "Authorization: token $GITHUB_TOKEN" -o /tmp/artifacts.zip "$archive_url"; then
              mkdir -p /tmp/artifacts && unzip -o /tmp/artifacts.zip -d /tmp/artifacts >/dev/null 2>&1

              if [ -f /tmp/artifacts/image-tag.txt ]; then
                TAG=$(cat /tmp/artifacts/image-tag.txt | tr -d '\r\n')
                echo "   ✅ Retrieved image tag from artifact: $TAG"
                echo "image_tag=$TAG" >> ${GITHUB_OUTPUT:-/dev/null}
              else
                echo "   ⚠️ image-tag artifact found but file not present"
                echo "image_tag=" >> ${GITHUB_OUTPUT:-/dev/null}
              fi
            else
              echo "   ⚠️ Failed to download artifact, continuing without image tag"
              echo "image_tag=" >> ${GITHUB_OUTPUT:-/dev/null}
            fi
          else
            echo "   ⚠️ No image-tag artifact found on CI run"
            echo "image_tag=" >> ${GITHUB_OUTPUT:-/dev/null}
          fi
        else
          echo "   ⚠️ Failed to fetch artifacts (HTTP $artifacts_http_code)"
          echo "image_tag=" >> ${GITHUB_OUTPUT:-/dev/null}
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
