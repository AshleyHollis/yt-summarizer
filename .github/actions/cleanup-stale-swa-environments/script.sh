#!/bin/bash

################################################################################
# Action: cleanup-stale-swa-environments / script.sh
#
# Purpose: Finds and deletes Azure Static Web Apps staging environments for
#          closed/merged PRs using Azure CLI and GitHub API.
#
# Inputs (Environment Variables):
#   GITHUB_TOKEN           - GitHub token for API access
#   SWA_NAME               - Azure Static Web App name
#   RESOURCE_GROUP         - Azure resource group name
#   SUBSCRIPTION_ID        - Azure subscription ID
#   DRY_RUN                - If "true", only report what would be deleted (default: false)
#   MIN_AGE_HOURS          - Minimum age in hours before a closed PR environment is
#                            considered stale (default: 1)
#
# Outputs (via $GITHUB_OUTPUT):
#   deleted_count          - Number of environments deleted/would be deleted
#   stale_prs              - Comma-separated list of PR numbers with stale environments
#
# Logic Flow:
#   1. Set Azure subscription context
#   2. List all SWA environments/builds
#   3. Fetch list of open PRs for quick lookup
#   4. For each environment:
#      a. Extract PR number from various sources (buildId, hostname, branch)
#      b. Check if environment is stale (PR closed, branch deleted, orphaned)
#      c. Verify stale age against min-age-hours threshold
#      d. Delete or report deletion (if dry-run)
#   5. Output summary with deleted count and affected PR numbers
#
# Safety Measures:
#   - Never deletes "default" (production) environment
#   - Handles multiple date formats (Linux, macOS)
#   - Graceful error handling for missing PR metadata
#   - Dry-run mode for preview of deletions
#
################################################################################

set -euo pipefail

# Set subscription context
echo "🔧 Setting Azure subscription context..."
az account set --subscription "$SUBSCRIPTION_ID"

# List all SWA environments/builds
echo "📋 Listing SWA environments for $SWA_NAME..."
environments=$(az staticwebapp environment list \
  -n "$SWA_NAME" \
  -g "$RESOURCE_GROUP" \
  -o json 2>/dev/null || echo "[]")

if [[ "$environments" == "[]" ]]; then
  echo "⚠️  No environments found or unable to list environments"
  echo "deleted_count=0" >> $GITHUB_OUTPUT
  echo "stale_prs=" >> $GITHUB_OUTPUT
  exit 0
fi

# Get list of all open PRs for quick lookup
echo "📋 Fetching open PRs from GitHub..."
open_prs=$(gh pr list --state open --json number --jq '.[].number' | tr '\n' ' ' || echo "")
echo "Currently open PRs: ${open_prs:-none}"

# Create associative array of open PRs
declare -A active_prs
for pr in $open_prs; do
  active_prs[$pr]=1
done

deleted_count=0
deleted_prs=()
current_time=$(date +%s)
min_age_seconds=$((MIN_AGE_HOURS * 3600))

echo ""
echo "🔍 Checking each SWA environment for staleness..."
echo ""

# Process each environment
echo "$environments" | jq -r '.[] | @json' | while IFS= read -r env_json; do
  env_name=$(echo "$env_json" | jq -r '.name // empty')
  build_id=$(echo "$env_json" | jq -r '.properties.buildId // .name // empty')
  hostname=$(echo "$env_json" | jq -r '.properties.hostname // empty')
  pull_request_title=$(echo "$env_json" | jq -r '.properties.pullRequestTitle // empty')
  source_branch=$(echo "$env_json" | jq -r '.properties.sourceBranch // empty')
  created_time=$(echo "$env_json" | jq -r '.properties.createdTimeUtc // empty')

  [[ -z "$env_name" ]] && continue

  # Safety: Never delete production/default
  if [[ "$env_name" == "default" ]]; then
    echo "  ℹ️  Skipping production environment: default"
    continue
  fi

  echo "📦 Environment: $env_name"
  echo "  Build ID: $build_id"
  echo "  Hostname: $hostname"
  echo "  PR Title: ${pull_request_title:-none}"
  echo "  Branch: ${source_branch:-none}"

  # Extract PR number from metadata
  pr_number=""

  # Method 1: Check if buildId is numeric (often the PR number)
  if [[ "$build_id" =~ ^[0-9]+$ ]]; then
    pr_number="$build_id"
    echo "  🔍 Detected PR number from buildId: $pr_number"
  fi

  # Method 2: Extract from hostname pattern (e.g., hostname-123.region.azurestaticapps.net)
  if [[ -z "$pr_number" ]] && [[ "$hostname" =~ -([0-9]+)\. ]]; then
    pr_number="${BASH_REMATCH[1]}"
    echo "  🔍 Detected PR number from hostname: $pr_number"
  fi

  # Method 3: Check if pullRequestTitle is set (indicates PR environment)
  if [[ -z "$pr_number" ]] && [[ -n "$pull_request_title" && "$pull_request_title" != "null" ]]; then
    echo "  🔍 PR environment detected but number unknown, checking branch..."
    # Try to find PR by branch name
    if [[ -n "$source_branch" && "$source_branch" != "null" ]]; then
      branch_pr=$(gh pr list --state all --head "$source_branch" --json number --jq '.[0].number // empty' || echo "")
      if [[ -n "$branch_pr" ]]; then
        pr_number="$branch_pr"
        echo "  🔍 Found PR number from branch: $pr_number"
      fi
    fi
  fi

  # Determine if environment is stale
  is_stale=false
  stale_reason=""

  if [[ -n "$pr_number" ]]; then
    # Check if PR exists and is open
    if [[ -v active_prs[$pr_number] ]]; then
      echo "  ✅ PR #$pr_number is open - keeping environment"
    else
      # PR is closed or doesn't exist - check age
      pr_closed_at=$(gh pr view "$pr_number" --json closedAt --jq '.closedAt // empty' 2>/dev/null || echo "")

      if [[ -z "$pr_closed_at" ]]; then
        # PR doesn't exist at all (deleted)
        is_stale=true
        stale_reason="PR #$pr_number doesn't exist (deleted)"
      else
        # PR is closed - check age
        closed_timestamp=$(date -d "$pr_closed_at" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "$pr_closed_at" +%s 2>/dev/null || echo "0")
        age_seconds=$((current_time - closed_timestamp))
        age_hours=$((age_seconds / 3600))

        if [[ $age_seconds -ge $min_age_seconds ]]; then
          is_stale=true
          stale_reason="PR #$pr_number closed ${age_hours}h ago (threshold: ${MIN_AGE_HOURS}h)"
        else
          echo "  ⏳ PR #$pr_number closed recently (${age_hours}h ago) - keeping for now"
        fi
      fi
    fi
  else
    # No PR number detected - check if it's a branch environment or orphaned
    if [[ -n "$source_branch" && "$source_branch" != "null" ]]; then
      echo "  🔍 Branch environment: $source_branch"
      # Check if branch still exists
      branch_exists=$(gh api repos/{owner}/{repo}/branches 2>/dev/null | jq -r --arg branch "$source_branch" '.[] | select(.name == $branch) | .name' || echo "")

      if [[ -z "$branch_exists" ]]; then
        # Branch doesn't exist - check environment age
        if [[ -n "$created_time" && "$created_time" != "null" ]]; then
          created_timestamp=$(date -d "$created_time" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "$created_time" +%s 2>/dev/null || echo "0")
          age_seconds=$((current_time - created_timestamp))
          age_hours=$((age_seconds / 3600))

          if [[ $age_seconds -ge $min_age_seconds ]]; then
            is_stale=true
            stale_reason="Branch '$source_branch' doesn't exist, environment ${age_hours}h old"
          else
            echo "  ⏳ Branch '$source_branch' doesn't exist but environment too recent (${age_hours}h) - keeping for now"
          fi
        else
          # No creation time but branch doesn't exist - assume stale if old enough
          is_stale=true
          stale_reason="Branch '$source_branch' doesn't exist"
        fi
      else
        echo "  ✅ Branch '$source_branch' exists - keeping environment"
      fi
    else
      # No PR number AND no branch info - orphaned environment
      echo "  ⚠️  Orphaned environment (no PR/branch metadata)"

      # Check age if available
      if [[ -n "$created_time" && "$created_time" != "null" ]]; then
        created_timestamp=$(date -d "$created_time" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "$created_time" +%s 2>/dev/null || echo "0")
        age_seconds=$((current_time - created_timestamp))
        age_hours=$((age_seconds / 3600))

        if [[ $age_seconds -ge $min_age_seconds ]]; then
          is_stale=true
          stale_reason="Orphaned environment, ${age_hours}h old (threshold: ${MIN_AGE_HOURS}h)"
        else
          echo "  ⏳ Orphaned but recent (${age_hours}h) - keeping for now"
        fi
      else
        # No metadata at all - orphaned environment, should be deleted
        # Try to find any matching PR by environment name
        name_pr=$(gh pr list --state all --json number,title --jq ".[] | select(.title | contains(\"$env_name\")) | .number" | head -1 || echo "")

        if [[ -n "$name_pr" ]]; then
          echo "  🔍 Found potential PR by name search: #$name_pr"
          pr_number="$name_pr"
          # Check PR status
          pr_closed_at=$(gh pr view "$pr_number" --json closedAt --jq '.closedAt // empty' 2>/dev/null || echo "")
          if [[ -n "$pr_closed_at" ]]; then
            closed_timestamp=$(date -d "$pr_closed_at" +%s 2>/dev/null || date -j -f "%Y-%m-%dT%H:%M:%SZ" "$pr_closed_at" +%s 2>/dev/null || echo "0")
            age_seconds=$((current_time - closed_timestamp))
            age_hours=$((age_seconds / 3600))

            if [[ $age_seconds -ge $min_age_seconds ]]; then
              is_stale=true
              stale_reason="Orphaned environment linked to closed PR #$pr_number (${age_hours}h ago)"
            fi
          fi
        else
          # No PR match and no metadata - delete orphaned environment
          echo "  🗑️  No PR/branch metadata found - marking as stale orphaned environment"
          is_stale=true
          stale_reason="Orphaned environment with no PR/branch metadata"
        fi
      fi
    fi
  fi

  # Delete if stale
  if [[ "$is_stale" == "true" ]]; then
    echo "  🗑️  STALE: $stale_reason"

    if [[ "$DRY_RUN" == "true" ]]; then
      echo "  [DRY RUN] Would delete environment: $env_name"
      deleted_count=$((deleted_count + 1))
      [[ -n "$pr_number" ]] && deleted_prs+=("$pr_number")
    else
      echo "  🗑️  Deleting environment: $env_name..."

      # Delete and capture result (don't pipe through grep as it affects exit code)
      delete_output=$(az staticwebapp environment delete \
        -n "$SWA_NAME" \
        -g "$RESOURCE_GROUP" \
        --environment-name "$env_name" \
        --yes \
        2>&1)
      delete_exit_code=$?

      if [[ $delete_exit_code -eq 0 ]]; then
        echo "    ✅ Successfully deleted environment: $env_name"
        deleted_count=$((deleted_count + 1))
        [[ -n "$pr_number" ]] && deleted_prs+=("$pr_number")
      else
        echo "    ❌ Failed to delete environment: $env_name"
        echo "    Error: $delete_output"
      fi
    fi
  fi

  echo ""
done

# Output results
echo "deleted_count=$deleted_count" >> $GITHUB_OUTPUT

if [[ ${#deleted_prs[@]} -gt 0 ]]; then
  stale_list=$(IFS=,; echo "${deleted_prs[*]}")
  echo "stale_prs=$stale_list" >> $GITHUB_OUTPUT
else
  echo "stale_prs=" >> $GITHUB_OUTPUT
fi

if [[ "$DRY_RUN" == "true" ]]; then
  echo "✅ [DRY RUN] Would delete $deleted_count environment(s)"
else
  echo "✅ Deleted $deleted_count environment(s)"
fi
