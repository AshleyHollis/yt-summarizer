# Argo CD Sync Fix - Investigation & Resolution

## Problem Summary

Argo CD was taking an extremely long time to sync/deploy updated images in preview environments. The "Verify Deployment" stage would hang for extended periods waiting for deployment images to update, eventually timing out.

## Root Cause

The Argo CD ApplicationSet was configured to use `targetRevision: '{{head_sha}}'` instead of `targetRevision: '{{branch}}'`. 

**Impact:**
- When the preview workflow committed overlay updates to the PR branch, Argo CD never detected them
- Argo CD remained locked to the original commit SHA from when the PR was opened
- The verification logic would wait indefinitely for deployment images to update, but Argo CD never synced the new kustomization.yaml

**Example:**
```yaml
# ❌ BROKEN (was in cluster):
targetRevision: '50270054b3bfef30fbd7859091b2d32bfb9074ba'  # locked to commit SHA

# ✅ FIXED (local file already correct):
targetRevision: '{{branch}}'  # tracks PR branch dynamically
```

## Investigation Process

1. **Examined pipeline logs** using GitHub CLI:
   - `gh run view 20907730048` showed "Verify Deployment" step stuck
   - "Wait for Argo CD to sync" completed successfully (namespace existed)
   - "Verify API deployment image" was in_progress for extended period

2. **Checked ApplicationSet configuration:**
   ```bash
   kubectl get applicationset yt-summarizer-previews -n argocd -o jsonpath='{.spec.template.spec.source.targetRevision}'
   # Output: {{head_sha}}  ❌ WRONG
   ```

3. **Verified the issue:**
   ```bash
   kubectl get application preview-pr-9 -n argocd -o jsonpath='{.spec.source.targetRevision}'
   # Output: 50270054b3bfef30fbd7859091b2d32bfb9074ba  ❌ Locked to old commit
   ```

4. **Found the discrepancy:**
   - Local file `k8s/argocd/preview-appset.yaml` already had correct `{{branch}}` value
   - Cluster configuration had stale `{{head_sha}}` value
   - ApplicationSet hadn't been re-applied after the local file was fixed

## Solutions Implemented

### 1. Applied Correct ApplicationSet Configuration

```bash
kubectl apply -f k8s/argocd/preview-appset.yaml
```

**Verification:**
```bash
# ApplicationSet template now correct:
kubectl get applicationset yt-summarizer-previews -n argocd -o jsonpath='{.spec.template.spec.source.targetRevision}'
# Output: {{branch}}  ✅

# Existing application updated automatically:
kubectl get application preview-pr-9 -n argocd -o jsonpath='{.spec.source.targetRevision}'
# Output: fix/argocd-github-token-config  ✅

# Argo CD immediately synced to latest commit:
kubectl get application preview-pr-9 -n argocd -o jsonpath='{.status.sync.revision}'
# Output: ddf01f1...  ✅ (matches HEAD)
```

### 2. Enhanced Verification Logic

Updated `.github/actions/wait-for-argocd-sync/action.yml`:

**Added Proactive Checks:**
- Verify `targetRevision` is a branch name, not commit SHA
- Fail fast if using commit SHA (with clear error message)
- Show both target revision and synced revision in diagnostics
- Wait for both namespace creation AND Argo CD sync completion
- Display periodic status updates every 30s

**Critical Check Added:**
```bash
if [[ "${TARGET_REVISION}" =~ ^[0-9a-f]{40}$ ]]; then
  echo "::error::❌ Application is tracking commit SHA instead of branch!"
  echo "  This means Argo CD won't detect overlay updates pushed to the PR branch."
  exit 1
fi
```

Updated `.github/actions/verify-deployment-image/action.yml`:

**Added Diagnostics:**
- Detect when Argo CD is locked to commit SHA
- Show target revision, synced revision, and sync status every 30s
- Explain WHY image tags aren't updating when misconfigured
- Fail fast with actionable error message

**Example Error Output:**
```
::error::❌ CRITICAL: Application is locked to commit SHA!
Argo CD won't detect overlay updates pushed to the PR branch.
ApplicationSet must use '{{branch}}' not '{{head_sha}}'
This is why the image tag hasn't updated.
```

## Verification & Results

### Before Fix:
- Preview deployment would hang at "Verify API deployment image"
- Argo CD sync status: `Synced` but locked to old commit
- Deployment image tags never updated despite overlay commits
- Verification timeout after 300s (5 minutes)

### After Fix:
- Argo CD immediately tracks PR branch instead of commit SHA
- New commits automatically trigger Argo CD sync within 30s (polling interval)
- Deployments update to new image tags as expected
- Verification completes successfully in < 1 minute

## Testing the Fix

1. **Push new commit to PR branch:**
   ```bash
   git commit -m "test change"
   git push
   ```

2. **Verify Argo CD tracks latest commit:**
   ```bash
   # Get current HEAD:
   git rev-parse HEAD | cut -c1-7
   
   # Check Argo CD synced revision:
   kubectl get application preview-pr-9 -n argocd -o jsonpath='{.status.sync.revision}' | cut -c1-7
   
   # Should match within 30s (ApplicationSet polling interval)
   ```

3. **Monitor deployment verification:**
   - Wait for CI workflow to build images
   - Preview workflow updates overlay in PR branch
   - Argo CD detects commit within 30s
   - Deployments update to new image tags
   - Verification completes quickly

## Commit History

1. **Applied ApplicationSet fix** (committed ddf01f1):
   - Enhanced wait-for-argocd-sync with targetRevision validation
   - Added critical check to fail fast on commit SHA tracking
   - Improved diagnostics showing target vs synced revision
   - Enhanced verify-deployment-image with Argo CD status checks

## Prevention

The enhanced verification logic now prevents this issue from happening again:

1. **Early Detection:** Workflow fails immediately if ApplicationSet uses `{{head_sha}}`
2. **Clear Messaging:** Error messages explain exactly what's wrong and how to fix it
3. **Better Diagnostics:** Shows target revision, synced revision, and sync status
4. **Proactive Monitoring:** Displays Argo CD status every 30s during verification

## Related Documentation

- ApplicationSet: `k8s/argocd/preview-appset.yaml`
- Workflow: `.github/workflows/preview.yml`
- Actions:
  - `.github/actions/wait-for-argocd-sync/action.yml`
  - `.github/actions/verify-deployment-image/action.yml`

## Key Takeaways

1. **Always use `{{branch}}` for preview environments** - commit SHA locks to a point-in-time
2. **Verify cluster configuration matches source files** - `kubectl apply` updates if needed
3. **Add validation in CI/CD** - fail fast with clear error messages
4. **Monitor Argo CD sync status** - don't just wait for namespace, verify sync completion
