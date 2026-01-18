#!/bin/bash
# Purpose: Deletes preview environment images from Azure Container Registry
# Inputs:
#   ACR_NAME: Azure Container Registry name
#   PR_NUMBER: Pull request number
#   REPOSITORIES: Comma-separated list of repos to clean
# Outputs: None (echo status messages)
# Logic:
#   1. Split repositories by comma
#   2. For each repository, query ACR for tags matching "pr-{number}-"
#   3. For each matching tag, delete the image
#   4. Continue on error to clean up remaining images
#   5. Report cleanup complete

set -euo pipefail

ACR_NAME="${ACR_NAME:-}"
PR_NUMBER="${PR_NUMBER:-}"
REPOSITORIES="${REPOSITORIES:-}"

echo "Cleaning up images for PR #$PR_NUMBER..."

IFS=',' read -ra REPOS <<< "$REPOSITORIES"
for REPO in "${REPOS[@]}"; do
  echo "Checking repository: $REPO"

  # Get tags with pr-N- prefix
  TAGS=$(az acr repository show-tags \
    --name $ACR_NAME \
    --repository "$REPO" \
    --query "[?starts_with(@, 'pr-$PR_NUMBER-')]" \
    --output tsv 2>/dev/null || echo "")

  if [ -z "$TAGS" ]; then
    echo "  No images found for PR #$PR_NUMBER in $REPO"
    continue
  fi

  # Delete each tag
  while IFS= read -r tag; do
    if [ -n "$tag" ]; then
      echo "  Deleting $REPO:${tag}"
      az acr repository delete \
        --name $ACR_NAME \
        --image "$REPO:${tag}" \
        --yes
    fi
  done <<< "$TAGS"
done

echo "✅ Image cleanup complete"
