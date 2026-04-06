### E2E worker count: 6 (was 4)

**By**: Lambert + Coordinator  
**When**: 2026-04-06 (PR #186 E2E audit & optimization session)  
**Status**: ✅ Committed

**Decision**
Increase Playwright CI workers from 4 to 6 in `playwright.config.ts`.

**What**
CI workers bumped from 4 to 6. Tests are safely isolated — each gets fresh BrowserContext, no shared-state writes. LIVE_PROCESSING=false in CI means no workers compete for shared processing queues.

**Rationale**
- Current CI run wall-clock: 34.4 minutes (658 passed, 43 skipped, 1 flaky)
- Worker count is the primary bottleneck (no other redundant waits or blocking operations remain)
- Estimated new wall-clock: ~23 minutes (58% reduction)
- Tests are inherently isolated — no shared browser state, no database mutations across workers
- Safe to scale further if needed

**Files Changed**
- `apps/web/playwright.config.ts` — workers: 6 (was 4)

**Risk**
- **Low**: Tests are designed for parallelization. Each test runs in fresh context.
- **Rollback**: Change workers back to 4 if unexpected flakiness emerges in next CI run

**Related Learnings**
- Removed redundant `waitForTimeout(2000)` in copilot.spec.ts (no impact on this decision)
- Confirmed `channel-ingest.spec.ts` serial mode has zero CI impact (runs inside LIVE_PROCESSING skip)
- Remaining waitForTimeout calls (5s in helpers.ts) are justified and kept
