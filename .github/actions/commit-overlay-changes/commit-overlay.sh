#!/bin/bash
# Purpose: Commit and push Kubernetes overlay changes to PR branch
# Inputs:
#   PR_NUMBER: Pull request number
#   IMAGE_TAG: Docker image tag used
#   COMMIT_SHA: Commit SHA being deployed
#   PR_BRANCH: PR branch name
# Outputs: None (commits and pushes to remote)
# Logic:
#   1. Configure git user for commits
#   2. Sanity check: ensure overlay has non-empty newTag
#   3. Stage overlay directory changes
#   4. If changes exist, commit with descriptive message
#   5. Push changes to PR branch
#   6. Report success or no changes

set -euo pipefail

PR_NUMBER="${PR_NUMBER:-}"
IMAGE_TAG="${IMAGE_TAG:-}"
COMMIT_SHA="${COMMIT_SHA:-}"
PR_BRANCH="${PR_BRANCH:-}"

git config user.name "github-actions[bot]"
git config user.email "github-actions[bot]@users.noreply.github.com"

git fetch origin "${PR_BRANCH}"
git checkout -B "${PR_BRANCH}" "origin/${PR_BRANCH}"

# Sanity: ensure generated overlay contains a non-empty newTag
if grep -q "newTag: \"\"" k8s/overlays/preview/kustomization.yaml; then
  echo "::error::Generated overlay has empty newTag - aborting commit"
  echo "--- overlay ---"
  cat k8s/overlays/preview/kustomization.yaml
  echo "--- end overlay ---"
  exit 1
fi

git add k8s/overlays/preview/

if git diff --staged --quiet; then
  echo "No changes to commit"
else
  git commit -m "chore(preview): update image tags for PR #${PR_NUMBER}

Image tag: ${IMAGE_TAG}
Commit: ${COMMIT_SHA}

[skip ci]"

  git push origin $PR_BRANCH
  echo "✅ Pushed overlay changes to $PR_BRANCH"
fi
