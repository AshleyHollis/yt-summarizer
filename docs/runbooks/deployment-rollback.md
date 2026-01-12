# Deployment Rollback Procedure

This runbook covers procedures for rolling back deployments when issues are detected.

## Table of Contents

1. [Quick Reference](#quick-reference)
2. [When to Rollback](#when-to-rollback)
3. [Rollback Methods](#rollback-methods)
4. [Environment-Specific Procedures](#environment-specific-procedures)
5. [Post-Rollback Verification](#post-rollback-verification)
6. [Root Cause Analysis](#root-cause-analysis)

## Quick Reference

### Emergency Rollback (30 seconds)

```bash
# Staging
argocd app rollback yt-summarizer-staging

# Production
argocd app rollback yt-summarizer-production
```

### Verify Rollback

```bash
kubectl get pods -n yt-summarizer
curl https://api.yt-summarizer.com/health
```

## When to Rollback

### Immediate Rollback Required

- ❌ Application crashes on startup
- ❌ Critical functionality broken (can't process videos)
- ❌ Database errors affecting all users
- ❌ Security vulnerability introduced
- ❌ Complete service unavailability

### Evaluate Before Rollback

- ⚠️ Increased error rates (but service functional)
- ⚠️ Performance degradation
- ⚠️ Minor feature bugs
- ⚠️ Partial functionality issues

### Monitor, Don't Rollback

- ✅ Cosmetic issues
- ✅ Non-critical feature bugs
- ✅ Issues affecting < 5% of requests
- ✅ Issues with known workarounds

## Rollback Methods

### Method 1: Argo CD Rollback (Recommended)

**Fastest method** - Uses Argo CD's built-in history

```bash
# View deployment history
argocd app history yt-summarizer-production

# Output:
# ID  DATE                           REVISION
# 5   2024-01-15 14:30:00 +0000 UTC  sha-abc1234
# 4   2024-01-14 10:15:00 +0000 UTC  sha-def5678
# 3   2024-01-13 09:00:00 +0000 UTC  sha-ghi9012

# Rollback to previous revision
argocd app rollback yt-summarizer-production

# Or rollback to specific revision
argocd app rollback yt-summarizer-production 4
```

**Pros**: Instant, preserves history
**Cons**: Only works if Argo CD is functional

### Method 2: Git Revert (GitOps Rollback)

**Use when**: Argo CD is unreachable or you need a permanent fix

```bash
# 1. Identify the bad commit that updated production images
git log --oneline k8s/overlays/prod/

# Example output:
# abc1234 chore(deploy): update production images to sha-def5678
# xyz7890 chore(deploy): update production images to sha-abc1234  <- rollback to this

# 2. Revert the bad commit
git revert abc1234 --no-edit

# 3. Push to trigger Argo CD sync
git push origin main

# 4. Verify Argo CD picks up the change
argocd app sync yt-summarizer-prod
argocd app get yt-summarizer-prod
```

**Pros**: Creates audit trail, permanent fix in git history
**Cons**: Slower (~2-3 minutes), requires git access

### Method 3: Restore Previous Image Directly

**Use when**: You know the exact previous image digest

```bash
# 1. Update kustomization.yaml with previous image
cd k8s/overlays/prod

# Edit kustomization.yaml to restore previous image:
# images:
# - name: api
#   newName: acrytsummprd.azurecr.io/yt-summarizer-api
#   newTag: sha-<previous-good-sha>

# 2. Commit and push
git add kustomization.yaml
git commit -m "fix: rollback to previous stable version"
git push origin main
```

**Pros**: Precise control over which version to restore
**Cons**: Manual process, requires knowing the previous image tag

### Method 3: Kubectl Direct Apply

**Use when**: Both Argo CD and Git are unavailable

```bash
# Get previous image tag from git history
git show HEAD~1:k8s/overlays/production/kustomization.yaml

# Manually update deployment
kubectl set image deployment/api \
  api=acrytsumm.azurecr.io/api:sha-previous \
  -n yt-summarizer

kubectl set image deployment/transcribe-worker \
  worker=acrytsumm.azurecr.io/workers:sha-previous \
  -n yt-summarizer

# Repeat for other workers...
```

**Pros**: Works when other systems are down
**Cons**: Drift from Git state, manual process

### Method 4: Scale and Replace

**Use when**: Need immediate relief while debugging

```bash
# Scale down problematic deployment
kubectl scale deployment api --replicas=0 -n yt-summarizer

# Apply known-good manifests
kubectl apply -f <path-to-backup-manifests>

# Scale back up
kubectl scale deployment api --replicas=1 -n yt-summarizer
```

## Environment-Specific Procedures

### Staging Rollback

1. **Immediate Action** (< 1 minute):
```bash
argocd app rollback yt-summarizer-staging
```

2. **Verify**:
```bash
kubectl get pods -n yt-summarizer
argocd app get yt-summarizer-staging
```

3. **Notify Team**: Post in team channel

### Production Rollback

1. **Assess Severity** (30 seconds):
   - Check error rates in monitoring
   - Verify user impact

2. **Immediate Action** (< 1 minute):
```bash
argocd app rollback yt-summarizer-production
```

3. **Verify Service** (2 minutes):
```bash
# Check pods
kubectl get pods -n yt-summarizer

# Check health
curl -s https://api.yt-summarizer.com/health | jq

# Check recent errors
kubectl logs -l app=api -n yt-summarizer --tail=50
```

4. **Notify Stakeholders**:
   - Post incident in #incidents channel
   - Update status page if applicable

5. **Prevent Re-deploy**:
```bash
# Disable auto-sync temporarily
argocd app set yt-summarizer-production --sync-policy none
```

## Post-Rollback Verification

### Immediate Checks (5 minutes)

```bash
# 1. All pods running
kubectl get pods -n yt-summarizer
# Expect: All pods STATUS=Running, READY=1/1

# 2. Services responding
curl -s https://api.yt-summarizer.com/health
# Expect: {"status": "healthy"}

# 3. No crash loops
kubectl get pods -n yt-summarizer -w
# Watch for 2 minutes, no restarts

# 4. Argo CD sync status
argocd app get yt-summarizer-production
# Expect: Health=Healthy, Sync=Synced
```

### Extended Checks (30 minutes)

```bash
# 1. Check error rates
kubectl logs -l app=api -n yt-summarizer --since=30m | grep -i error | wc -l

# 2. Check worker processing
kubectl logs -l app=transcribe-worker -n yt-summarizer --tail=100

# 3. Database connectivity
kubectl exec -it deployment/api -n yt-summarizer -- python -c "from shared.database import get_session; print('DB OK')"
```

### Functional Verification

1. Submit a test video for processing
2. Verify transcription completes
3. Verify summarization completes
4. Check UI displays results correctly

## Root Cause Analysis

### After Stabilization

1. **Gather Evidence**:
```bash
# Export logs from time of incident
kubectl logs -l app=api -n yt-summarizer --since=2h > api-logs.txt

# Export events
kubectl get events -n yt-summarizer --sort-by='.lastTimestamp' > events.txt

# Export deployment history
argocd app history yt-summarizer-production > deploy-history.txt
```

2. **Compare Changes**:
```bash
# Get the problematic commit
git log --oneline -5

# View the changes
git diff <good-commit> <bad-commit>
```

3. **Create Incident Report**:
   - Timeline of events
   - Root cause identification
   - Impact assessment
   - Prevention measures

### Before Re-deploying

1. ✅ Root cause identified and fixed
2. ✅ Changes tested in staging
3. ✅ Review by another team member
4. ✅ Rollback plan documented
5. ✅ Monitoring alerts set up
6. ✅ Re-enable Argo CD auto-sync:

```bash
argocd app set yt-summarizer-production --sync-policy automated --auto-prune
```

## Rollback Checklist

### Pre-Rollback

- [ ] Confirm issue requires rollback (not a transient error)
- [ ] Identify the target rollback version
- [ ] Notify team of impending rollback

### During Rollback

- [ ] Execute rollback command
- [ ] Monitor pod status
- [ ] Verify health endpoints

### Post-Rollback

- [ ] Confirm service is stable
- [ ] Disable auto-sync to prevent accidental re-deploy
- [ ] Notify stakeholders
- [ ] Begin root cause analysis

### Recovery

- [ ] Root cause identified
- [ ] Fix implemented and tested
- [ ] Changes reviewed
- [ ] Re-enable auto-sync
- [ ] Deploy fix
- [ ] Monitor for issues
- [ ] Close incident
