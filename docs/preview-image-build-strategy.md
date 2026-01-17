# Preview Image Build Strategy

## Overview

The preview deployment pipeline uses a **two-path image strategy** to create isolated, deterministic preview environments for each pull request while optimizing build efficiency.

## Decision Tree

```
┌────────────────────────────────────────────────────────────┐
│  PR Opened/Updated                                         │
└────────────────────────────────────────────────────────────┘
                          │
                          ↓
            ┌─────────────────────────┐
            │  Detect Changes         │
            │  (git diff base..HEAD)  │
            └─────────────────────────┘
                          │
          ┌───────────────┴───────────────┐
          │                               │
          ↓                               ↓
    CODE CHANGES?                   K8S-ONLY CHANGES?
    (services/*, apps/web,          (k8s/* only)
     docker/*)                      
          │                               │
          ↓                               ↓
  ┌─────────────────────┐       ┌─────────────────────┐
  │ WAIT FOR CI BUILD   │       │ FIND PR IMAGE TAG   │
  │ • CI workflow runs  │       │ • Search PR history │
  │ • Builds pr-N-sha   │       │ • Find last code    │
  │ • Pushes to ACR     │       │   change commit     │
  │ • Preview waits     │       │ • Use pr-N-oldsha   │
  │ • Extracts tag      │       │ • OR prod SHA tag   │
  └─────────────────────┘       └─────────────────────┘
          │                               │
          └───────────────┬───────────────┘
                          ↓
            ┌─────────────────────────┐
            │  Validate Image in ACR  │
            │  • Check image exists   │
            │  • Test K8s can pull    │
            └─────────────────────────┘
                          │
                          ↓
            ┌─────────────────────────┐
            │  Update Preview Overlay │
            │  • Use determined tag   │
            │  • Commit to PR branch  │
            └─────────────────────────┘
                          │
                          ↓
            ┌─────────────────────────┐
            │  ArgoCD Auto-Sync       │
            │  • Watches PR branch    │
            │  • Pulls from ACR       │
            │  • Deploys to preview-  │
            │    pr-{number} ns       │
            └─────────────────────────┘
```

## Image Tagging

### Format

**Preview images use PR-scoped tags:**
- Format: `pr-{number}-{7-char-sha}`
- Example: `pr-42-abc1234`
- PR #42, commit `abc1234`

**Fallback tags (K8s-only PRs):**
- Format: `sha-{7-char-sha}` (production tag)
- Example: `sha-e43f28a`
- Used when: PR has no code changes, only K8s config

### Why PR-Scoped Tags?

| Benefit | Description |
|---------|-------------|
| **Isolation** | Each PR gets unique image tags |
| **Deterministic** | Each tag maps to exact PR + commit |
| **Testable** | Can test specific PR versions |
| **Traceable** | Easy to find which PR deployed what |
| **Cleanup** | PR-scoped tags cleaned up when PR closes |

## Path 1: Code Changes (Wait for CI)

### Triggers
Changes to any of:
- `services/api/**` - FastAPI application code
- `services/workers/**` - Background workers
- `services/shared/**` - Shared Python libraries
- `apps/web/**` - Next.js frontend
- `docker/**` or `**/Dockerfile*` - Container definitions

### Workflow
1. **detect-changes** job identifies code changes → `needs_image_build = true`
2. **CI workflow** (separate) triggers in parallel:
   - Runs tests
   - Builds images tagged as `pr-{number}-{sha}`
   - Pushes to ACR: `acrytsummprd.azurecr.io/yt-summarizer-api:pr-42-abc1234`
3. **wait-for-ci** job in preview workflow:
   - Finds CI workflow run for same commit
   - Waits up to 30 minutes for completion
   - Extracts image tag from CI artifacts
   - **Fails if CI fails** (no fallback)
4. **validate-acr-image** action:
   - Verifies image exists in ACR
   - Tests K8s can pull image (dry-run)
5. **update-overlay** job:
   - Updates `k8s/overlays/preview/kustomization.yaml`
   - Commits to PR branch
6. **ArgoCD** detects commit → syncs to `preview-pr-{number}` namespace

### Example
```yaml
# PR #42 changes services/api/routes.py (commit abc1234)
# → CI builds pr-42-abc1234
# → Preview waits for CI
# → Updates preview overlay:

images:
  - name: yt-summarizer-api
    newName: acrytsummprd.azurecr.io/yt-summarizer-api
    newTag: pr-42-abc1234  # ← PR-scoped tag from CI
```

## Path 2: K8s-Only Changes (Find PR Image)

### Triggers
Changes to:
- `k8s/**` - Kubernetes manifests (resource limits, env vars, ingress)

**AND** no changes to code paths (services/*, apps/web, docker)

### Workflow
1. **detect-changes** job identifies K8s-only → `needs_image_build = false`
2. **get-production-tag** job runs:
   - Fetches full git history for PR branch
   - Walks commits from newest to oldest
   - Searches for most recent commit that changed code
   - If found: Uses `pr-{number}-{that-commit-sha}`
   - If not found: Falls back to production kustomization SHA tag
3. **validate-acr-image** action verifies image exists
4. **update-overlay** job updates preview with found tag
5. **ArgoCD** syncs K8s changes only (same image, new config)

### Example: Code Exists in PR History
```bash
# PR #42 history:
# - abc1234: Update k8s resource limits (current commit)
# - def5678: Add new API endpoint (previous commit) ← FOUND
# - main: Base branch

# Result: Uses pr-42-def5678 (from earlier commit in same PR)
```

### Example: No Code in PR History
```bash
# PR #42 history:
# - abc1234: Update k8s ingress (current commit)
# - main: Base branch

# No code changes found in PR
# Reads production kustomization → sha-e43f28a
# Result: Uses sha-e43f28a (stable production image)
```

### Why Search PR History?

**Goal**: Test K8s changes against the PR's own code, not random production code.

| Approach | Traceability | Consistency | Determinism |
|----------|--------------|-------------|-------------|
| **Search PR history** ✅ | Excellent | PR-scoped | Perfect |
| **Use latest PR build** ❌ | Poor | Timing-dependent | Non-deterministic |
| **Use production tag** ⚠️ | Good | Not PR-scoped | Deterministic |

**Decision**: Search PR history first, fallback to production if needed.

## Comparison with Production Workflow

| Aspect | Preview | Production |
|--------|---------|------------|
| **Tag format** | `pr-{number}-{sha}` | `sha-{sha}` |
| **Build location** | CI workflow (separate) | Production workflow (inline) |
| **Code changes** | Wait for CI images | Build images directly |
| **No code changes** | Search PR history | Read current prod kustomization |
| **Fallback** | Production SHA tag | None needed |
| **Update target** | PR branch overlay | Main branch overlay |
| **ArgoCD watches** | PR branches | Main branch only |
| **Namespace** | `preview-pr-{number}` | `yt-summarizer` |
| **Concurrency** | Max 3 previews | Single production |
| **Cleanup** | PR close → delete | Never deleted |

## Preview Lifecycle

```
┌─────────────────────────────────────────────────────────────┐
│  1. PR OPENED/UPDATED                                       │
│     PR #42, Commit: abc1234                                 │
│     Changes: services/api/routes.py                         │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  2. CI WORKFLOW BUILDS IMAGE (parallel)                     │
│     Tag: pr-42-abc1234                                      │
│     Runs tests, builds, pushes to ACR                       │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  3. PREVIEW WORKFLOW WAITS FOR CI                           │
│     Finds CI run for commit abc1234                         │
│     Waits for completion (up to 30 min)                     │
│     Extracts image tag: pr-42-abc1234                       │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  4. PREVIEW OVERLAY UPDATED (PR branch)                     │
│     File: k8s/overlays/preview/kustomization.yaml           │
│     newTag: pr-42-abc1234                                   │
│     Committed to PR #42 branch                              │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  5. ARGOCD AUTO-SYNC                                        │
│     Watches: PR #42 branch                                  │
│     Pulls: acrytsummprd.azurecr.io/.../pr-42-abc1234       │
│     Deploys: To namespace preview-pr-42                     │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  6. PREVIEW RUNNING                                         │
│     Backend: pr-42.yt-summarizer.apps.ashleyhollis.com     │
│     Frontend: SWA preview URL                               │
│     Namespace: preview-pr-42                                │
│     Images: pr-42-abc1234                                   │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  7. PR MERGED/CLOSED                                        │
│     Cleanup workflow triggered                              │
│     - Deletes namespace preview-pr-42                       │
│     - Deletes SWA preview environment                       │
│     - ACR images remain (retention policy cleans later)     │
└─────────────────────────────────────────────────────────────┘
```

## When Images Are Built

| Change Type | Example Files | Builds Image? | Tag Used |
|-------------|---------------|---------------|----------|
| API code | `services/api/main.py` | ✅ Yes (CI) | `pr-42-{new-sha}` |
| Worker code | `services/workers/transcribe.py` | ✅ Yes (CI) | `pr-42-{new-sha}` |
| Shared lib | `services/shared/db/models.py` | ✅ Yes (CI) | `pr-42-{new-sha}` |
| Frontend | `apps/web/src/App.tsx` | ✅ Yes (CI) | `pr-42-{new-sha}` |
| Dockerfile | `services/api/Dockerfile` | ✅ Yes (CI) | `pr-42-{new-sha}` |
| K8s config | `k8s/base/deployment.yaml` | ❌ No | `pr-42-{old-sha}` or `sha-*` |
| Resource limits | `k8s/overlays/preview/patches/` | ❌ No | `pr-42-{old-sha}` or `sha-*` |
| Docs | `docs/api.md`, `README.md` | ❌ No | N/A (skipped) |
| CI workflows | `.github/workflows/*.yml` | ❌ No | N/A (skipped) |

## Concurrency and Queuing

### Max Previews Limit
- **Limit**: 3 concurrent preview environments
- **Reason**: Prevent resource exhaustion on AKS cluster
- **Behavior**: If 3 previews exist, new PRs queued

### Queue Mechanism
```yaml
check-concurrency:
  - Count active preview namespaces
  - If count < 3: can_deploy = true
  - If count >= 3: can_deploy = false, post queue message
```

### What Happens When Queued?
1. PR gets comment: "⏳ Preview Queued"
2. Workflow does NOT fail (just waits)
3. When another PR closes → slot opens
4. User must re-trigger preview (push new commit or manual workflow)

## E2E Testing

### When E2E Runs
- After preview deployment succeeds
- Tests against live preview environment
- Uses Playwright to test full user flows

### Test Environment
```yaml
BASE_URL: {SWA-preview-url}
NEXT_PUBLIC_API_URL: https://pr-42.yt-summarizer.apps.ashleyhollis.com
USE_EXTERNAL_SERVER: true
```

### What Gets Tested
- Video submission flow
- Authentication (Auth0)
- API health checks
- UI rendering
- TLS certificates

## Cleanup Strategy

### Automatic Cleanup (PR Close)
```yaml
# Triggered when PR closed/merged
cleanup:
  - Delete AKS namespace: preview-pr-{number}
  - Delete SWA environment
  - ACR images remain (separate retention policy)
```

### Stale Environment Cleanup
```yaml
# Before each SWA deployment
cleanup-stale-swa-environments:
  - Checks last 50 PRs
  - Finds closed PRs > 1 hour old
  - Deletes their SWA environments
  - Prevents quota exhaustion
```

### Manual Cleanup
```bash
# Delete specific preview namespace
kubectl delete namespace preview-pr-42

# Delete SWA environment
az staticwebapp environment delete \
  --name swa-ytsumm-prd \
  --environment-name pr-42
```

## Troubleshooting

### "CI workflow not found"
- **Cause**: PR pushed before CI workflow was created
- **Fix**: Push new commit to trigger both CI and preview
- **Prevention**: Ensure CI workflow exists before opening PRs

### "Image not found in ACR"
- **Cause**: CI failed or didn't push image
- **Fix**: Check CI workflow logs, fix issues, re-run
- **Prevention**: CI must succeed before preview deploys

### "Max previews reached"
- **Cause**: 3 other PRs have active previews
- **Fix**: Close/merge other PRs or wait for cleanup
- **Prevention**: Close PRs promptly after merge

### "Preview using production tag"
- **Cause**: K8s-only PR with no code changes in PR history
- **Why**: Intentional fallback to stable production image
- **Safe**: Production tag validated before use

### "ArgoCD not syncing"
- **Cause**: Overlay commit failed or ArgoCD not watching PR branch
- **Fix**: Check commit logs, verify ArgoCD application config
- **Prevention**: Monitor overlay commit step for failures

## Best Practices

1. ✅ **Keep PRs focused**
   - Smaller PRs = faster CI builds
   - Easier to review and test

2. ✅ **Let CI complete before deploying**
   - Preview waits automatically
   - Don't force-deploy without images

3. ✅ **Test against your preview**
   - Use preview URL: `https://pr-42.yt-summarizer...`
   - Don't test against production

4. ✅ **Close PRs after merge**
   - Frees up preview slots
   - Automatic cleanup triggered

5. ✅ **Monitor E2E test results**
   - Check PR comments for test status
   - Fix failures before merging

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│  PREVIEW DEPLOYMENT ARCHITECTURE                            │
└─────────────────────────────────────────────────────────────┘

  PR Branch                CI Workflow              Preview Workflow
  ─────────               ────────────              ────────────────
     │                         │                           │
     │  Push commit           │                           │
     ├────────────────────────┤                           │
     │                         │                           │
     │                    Build & Test                     │
     │                    pr-42-abc1234                    │
     │                         │                           │
     │                    Push to ACR                      │
     │                         │                           │
     │                         │      Wait for CI          │
     │                         ├──────────────────────────>│
     │                         │                           │
     │                         │      Extract tag          │
     │                         │<──────────────────────────┤
     │                         │                           │
     │                         │                      Validate ACR
     │                         │                           │
     │      Update overlay     │                      Update overlay
     │<────────────────────────────────────────────────────┤
     │                         │                           │
     │  pr-42-abc1234          │                           │
     │  in kustomization       │                           │
     │                         │                           │
     ▼                         ▼                           ▼

  ArgoCD watches PR branch
  ────────────────────────
         │
    Detect change
         │
    Pull from ACR: pr-42-abc1234
         │
    Deploy to: preview-pr-42
         │
         ▼

  Preview Environment
  ───────────────────
  - Namespace: preview-pr-42
  - API: pr-42.yt-summarizer.apps.ashleyhollis.com
  - SWA: {unique-swa-url}
  - Images: pr-42-abc1234
```

## Related Documentation

- [Production Image Strategy](./production-image-build-strategy.md) - Main branch deployment
- [CI Workflow](../.github/workflows/ci.yml) - Where images are built
- [Preview Cleanup](../.github/workflows/cleanup-preview.yml) - Resource cleanup
- [Change Detection](../scripts/ci/detect-changes.ps1) - What triggers builds

## Questions?

**Q: Why separate CI and Preview workflows?**
A: Allows CI to run tests in parallel with linting. Preview waits for all CI checks to pass.

**Q: Can I deploy a preview without code changes?**
A: Yes, K8s-only changes deploy automatically with existing images.

**Q: What if CI fails?**
A: Preview workflow fails too (no fallback). Fix CI first, then re-run.

**Q: How long does preview deployment take?**
A: 
- With CI images: ~3-5 minutes (wait + deploy)
- K8s-only: ~2-3 minutes (no build needed)

**Q: Can I force a specific image tag?**
A: Not recommended. Use workflow_dispatch for testing, but trust the automated logic.
