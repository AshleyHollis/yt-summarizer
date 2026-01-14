# Preview Deployment Fixes - Task List

## Status: IN PROGRESS
**Started:** 2026-01-12T03:50:00Z

---

## Task 1: Fix Preview Workflow Image Tag Resolution for K8s-Only Changes
**Status:** NOT STARTED
**Priority:** HIGH

### Requirements:
- For K8s-only changes (needs_image_build=false), use deterministic image tag
- Strategy:
  1. Walk backwards through PR's git history
  2. Find most recent commit that changed code (services/apps/docker)
  3. Use that commit's image tag: pr-<number>-<sha>
  4. If no commits in PR built images, fallback to production tag (read prod kustomization.yaml file)
- This ensures K8s changes are tested with the PR's own code, not random production code
- Fully deterministic as it's tied to git history

### Files to Modify:
- `.github/workflows/preview.yml` - Update find-pr-image-tag job

### Acceptance Criteria:
- [ ] Script walks PR commit history correctly
- [ ] Finds most recent code change in PR and uses pr-X-sha tag
- [ ] Falls back to prod kustomization.yaml when PR has no code changes
- [ ] All image tags are deterministic (no "latest")

---

## Task 2: Improve Verify Deployment Diagnostics
**Status:** NOT STARTED
**Priority:** MEDIUM

### Requirements:
- Verify deployment scripts should be smarter and provide better output
- Should dig deeper into Argo CD/AKS to figure out if/why Argo CD is not syncing
- Should check why deployments/pods are failing
- Don't just loop and wait - do checks while waiting or pre-checks
- Check for errors proactively

### Files to Modify:
- `.github/actions/verify-deployment-image/action.yml`
- `.github/actions/wait-for-argocd-sync/action.yml`
- `.github/actions/health-check-preview/action.yml`

### Improvements Needed:
- [ ] Check Argo CD Application status and sync state
- [ ] Display Argo CD sync errors if any
- [ ] Check deployment rollout status
- [ ] Show pod status and events
- [ ] Display container logs if pods are failing
- [ ] Check for image pull errors
- [ ] Verify service endpoints exist
- [ ] Better formatted output with clear sections

---

## Task 3: Investigate and Fix Argo CD Sync Issue
**Status:** NOT STARTED
**Priority:** HIGH

### Problem:
```
✅ api deployment exists
Current image: acrytsummprd.azurecr.io/yt-summarizer-api:latest
⚠️ Image tag mismatch - Argo CD may still be syncing
```

Argo CD is not syncing the tag that we put into the kustomization.yaml file.

### Investigation Steps:
- [ ] Check Argo CD ApplicationSet configuration
- [ ] Verify Git repository source configuration
- [ ] Check if Argo CD has permissions to read the PR branch
- [ ] Verify ApplicationSet is generating Application correctly
- [ ] Check Application sync policy (auto vs manual)
- [ ] Review Argo CD logs for sync errors
- [ ] Check if GitHub token/credentials are configured correctly

### Files to Check:
- `k8s/argocd/preview-appset.yaml`
- GitHub token ExternalSecret configuration
- Argo CD Application generated for this PR

### Acceptance Criteria:
- [ ] Understand root cause of why Argo CD shows "latest" instead of SHA tag
- [ ] Fix configuration issue
- [ ] Verify Argo CD syncs correct image tag from kustomization.yaml
- [ ] Document fix in this file

---

## Progress Log

### 2026-01-12T03:50:00Z
- Created task list
- Starting work on tasks...
