## DB Investigator — 2026-04-06

### Task
Review global-setup readiness mechanism and identify why ~15 tests skip with data-conditional failures despite database being populated.

### Outcome
- **Status:** ✅ Complete (code fix implemented)
- **Commit:** `fix(e2e): correct global-setup readiness check to verify DB-completed status` (`be0b4e40`)
- **Root Cause Found & Fixed:** Global-setup checked only segment count; didn't verify Relationships worker completion

### Method
- Analyzed `/copilot/coverage` endpoint (vector store segments)
- Traced video processing pipeline: Transcribe → Summarize → Embed → Relationships
- Verified `processing_status='completed'` is set by Relationships worker only
- Cross-checked library API `?status=completed` response

### Root Cause

**Timing Gap in CI:**
- Global-setup was declared ready when `segmentCount ≥ 30` (coverage endpoint)
- But Relationships worker had NOT finished yet
- Library API `/library?status=completed` returned 0
- Tests using `@query "status=completed"` got no results → skip

**Worker Sequence:**
1. Transcribe worker: processes audio → stores transcription
2. Summarize worker: generates summary
3. Embed worker: vectorizes segments → stores embeddings
4. Relationships worker: builds relationship graph → **sets `processing_status='completed'`**

### Solution Implemented

**Before:**
```
CHECK: segmentCount ≥ MIN_SEGMENTS_REQUIRED
If TRUE → declare ready
```

**After:**
```
CHECK: segmentCount ≥ MIN_SEGMENTS_REQUIRED
AND: library API returns ≥ MIN_COMPLETED_VIDEOS with status=completed
If BOTH TRUE → declare ready
```

This ensures Relationships worker has finished before tests start.

### Secondary Finding — ROPC Dead Code

- `injectAuth0Token()` function in global-setup.ts
- Auth0 preview app doesn't have ROPC (password-realm) grant enabled
- Always returns 403
- Token written to localStorage is ignored by Auth0 SDK (uses cookies)
- **Decision:** Flag for cleanup (approved by Dallas)

### Preview API Health Baseline

- 15 completed videos
- 239 segments
- Status: Healthy

### Files Modified
- `apps/web/e2e/global-setup.ts`

### Key Learning
When global-setup checks "environment is ready", trace ALL workers in the pipeline, not just the most obvious one. In this case, coverage segments don't guarantee completion — Relationships worker runs last and is the authoritative source.