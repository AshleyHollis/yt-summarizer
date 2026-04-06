# E2E Test Suite Audit and Performance Optimization

**Coordinator**: Scribe  
**Topic**: E2E test suite audit and performance optimization  
**Branch**: `test/e2e-env-verification` (PR #186)  
**Result**: All changes committed ✅

## Summary

Ashley requested the team to review the first-ever passing E2E run in preview, confirm correctness, identify fixable skips, and optimize speed.

**CI Run 24013899275 (preview)**: 658 passed, 43 skipped, 1 flaky, 34.4 min wall-clock

### What Happened

1. **Coordinator** read CI logs and summarized findings to the squad
2. **Kane** (background) audited all 43 skips — confirmed they were properly handled on branch:
   - 26 by-design (OAuth, session timeout, feature flags)
   - 9 data-conditional (missing fixture data)
   - 8 LIVE_PROCESSING guards (require live processing server)
   - ✅ No bare stubs remaining
3. **Lambert** (background) identified performance opportunities:
   - Workers 4→6: estimated ~23 min from 34.4 min (58% reduction)
   - Removed redundant `waitForTimeout(2000)` in copilot.spec.ts
   - Documented channel-ingest serial mode as correct/by-design
4. **Coordinator** committed Lambert's changes: `perf(e2e): increase workers 4→6, remove redundant waitForTimeout in copilot tests`
5. **Kane** confirmed flaky test threshold was already fixed (3500→10000ms) on branch

## Files Changed

- `apps/web/playwright.config.ts` — workers 4→6
- `apps/web/e2e/copilot.spec.ts` — remove waitForTimeout(2000), extend toBeVisible to 7s

## Key Decisions

### E2E worker count: 6 (was 4)
- **By**: Lambert + Coordinator
- **Rationale**: Tests are safely isolated; LIVE_PROCESSING=false in CI means no shared-state writes
- **Estimated impact**: ~34 min → ~23 min wall-clock time
- **Rollback**: Change workers back to 4 if flakiness increases

## Agents Used

- **Kane** (background, claude-sonnet-4.6) — E2E skip audit + flaky test analysis
- **Lambert** (background, claude-sonnet-4.6) — Performance optimization analysis + implementation

## Learnings

**Kane**: All 43 skips on the branch are properly categorized with clear rationale — no bare stubs remain. The flaky test threshold fix was already in place.

**Lambert**: Playwright worker count is safe to scale; no shared state issues in CI. Redundant waits were successfully removed. Channel-ingest serial mode has no CI performance impact (runs inside LIVE_PROCESSING skip block).
