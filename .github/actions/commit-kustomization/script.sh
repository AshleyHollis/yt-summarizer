#!/bin/bash
# =============================================================================
# Commit Kustomization Changes
# =============================================================================
# PURPOSE:
#   Commits and pushes kustomization changes to the repository
#
# INPUTS (via environment variables):
#   FILE_PATH        Path to the kustomization file to commit
#   COMMIT_MESSAGE   Commit message to use
#   GIT_BRANCH       Branch to push to
#
# OUTPUTS (via $GITHUB_OUTPUT):
#   committed        Whether changes were committed (true/false)
#
# LOGIC:
#   1. Configure git user as github-actions bot
#   2. Stage the file for commit
#   3. Check if there are staged changes
#   4. If no changes, output committed=false
#   5. If changes exist, commit and push, output committed=true
#
# =============================================================================
set -euo pipefail

git config user.name "github-actions[bot]"
git config user.email "github-actions[bot]@users.noreply.github.com"

git add "${FILE_PATH}"

if git diff --staged --quiet; then
  echo "No changes to commit"
  echo "committed=false" >> "$GITHUB_OUTPUT"
else
  git commit -m "${COMMIT_MESSAGE}"
  git push origin "${GIT_BRANCH}"
  echo "✅ Committed and pushed changes"
  echo "committed=true" >> "$GITHUB_OUTPUT"
fi
