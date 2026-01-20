# SWA Deployment Troubleshooting Log

**Date**: 2026-01-21  
**Branch**: `fix/swa-backend-integration-baseline`  
**PR**: #69  
**Problem**: SWA deployments failing with "warmup timeout" after integrating Auth0 backend changes

## Context

### Last Successful Deployment
- **Commit**: `129645c` (main branch)
- **Date**: 2026-01-20 10:32 AM
- **Run**: #21168195199
- **Note**: Frontend was SKIPPED in this run (not actually deployed)

### Current State
- **Branch**: `fix/swa-backend-integration-baseline`
- **Latest Commit**: `43d50e3` - "fix: add SWA runtime app settings configuration to production workflow"
- **SWA Resource**: Freshly recreated (old stuck, new clean)
  - Old: `proud-coast-0bd36cb00.6.azurestaticapps.net`
  - New: `proud-smoke-05b9a9c00.4.azurestaticapps.net`
- **Deployment Token**: Regenerated and updated in GitHub secrets

### Key Finding: Configuration Difference

**Main branch (working)**:
```yaml
output_location: .next
```

**Our branch (failing)**:
```yaml
output_location: ""  # Empty string - correct per MS docs but failing
```

### Code Analysis
- ✅ **NO functional code changes** between `129645c` and current HEAD
- ✅ **Dependencies identical** (package.json unchanged)
- ✅ **Next.js config unchanged** (only formatting)
- ❌ **Workflow config changed**: `output_location` setting

## Tests Performed

### Test 0: Baseline Investigation (COMPLETED)
**Hypothesis**: Code changes broke SWA deployment  
**Method**: Git diff comparison between `129645c` and HEAD  
**Result**: ❌ REJECTED - Only formatting changes, no functional code changes  
**Conclusion**: Problem is NOT in the application code

---

### Test 1: Revert output_location to .next
**Hypothesis**: Empty `output_location` is causing SWA deployment failures  
**Method**: Change `output_location` from `""` back to `.next` in deploy-prod.yml  
**Expected**: Deployment succeeds (matches main branch config)  
**Status**: PENDING

**Steps**:
1. Update `.github/workflows/deploy-prod.yml`
2. Change `output_location: ""` to `output_location: .next`
3. Commit and push
4. Trigger deployment via GitHub Actions
5. Monitor deployment logs

**If SUCCEEDS**: Empty output_location is the root cause  
**If FAILS**: Continue to Test 2

---

### Test 2: SWA CLI Deployment (Fallback)
**Hypothesis**: GitHub Action has issues, direct SWA CLI might work  
**Method**: Use `swa deploy` with minimal config  
**Status**: NOT STARTED

**Known Issue**: SWA CLI hangs on large Next.js apps (131MB, 3586 files)  
**Mitigations**:
- Use `--verbose` flag to see where it hangs
- Try with production build already completed
- May need to increase timeout

---

### Test 3: Standalone Server Bundle
**Hypothesis**: SWA doesn't handle .next/standalone correctly  
**Method**: Deploy without standalone, just standard .next  
**Status**: NOT STARTED

---

## Root Cause Analysis

### Working Theory
Azure SWA's Next.js integration may have specific requirements for `output_location`:
1. **Empty string** (`""`) = Tells SWA "no separate output folder, use app root"
2. **`.next`** = Tells SWA "build output is in .next folder"

For Next.js with hybrid rendering:
- Microsoft docs say use empty string
- But main branch uses `.next` and works
- Our branch uses empty string and fails

**Possible explanations**:
1. SWA platform changed behavior recently
2. Empty string triggers different code path that's broken
3. Auth0 app settings + empty output_location = conflict
4. .next folder structure differs from what SWA expects

### Questions to Answer
- [ ] Why does `.next` work when docs say use empty string?
- [ ] What does SWA actually do differently with empty vs `.next`?
- [ ] Is there a recent SWA platform change?
- [ ] Does the build artifact structure matter?

---

## Decision Log

### Decision 1: Quick Fix First
**Date**: 2026-01-21  
**Rationale**: Need working deployment ASAP, investigate properly later  
**Action**: Revert to `.next` to match main branch  
**Risk**: Low - main branch proves this works

---

## References
- [Microsoft Docs: SWA + Next.js](https://learn.microsoft.com/azure/static-web-apps/deploy-nextjs-hybrid)
- [PR #69](https://github.com/AshleyHollis/yt-summarizer/pull/69)
- [Last successful run](https://github.com/AshleyHollis/yt-summarizer/actions/runs/21168195199)
- [Baseline branch commit history](https://github.com/AshleyHollis/yt-summarizer/commits/fix/swa-backend-integration-baseline)

---

## Next Steps
1. ✅ Document current state
2. ⏳ Test 1: Revert output_location
3. ⏳ Monitor deployment
4. ⏳ Document findings
5. ⏳ Implement proper fix with understanding
