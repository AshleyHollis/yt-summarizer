---
description: Verify implementation by running all test suites and confirming functionality works
---

## User Input

```text
$ARGUMENTS
```

You **MUST** consider the user input before proceeding (if not empty).

## Purpose

This prompt runs a complete verification of the current implementation to ensure:
1. All test suites pass (API, Frontend, E2E)
2. Core user workflows function correctly
3. Implementation matches specification

## ⚠️ CRITICAL: This is a QUALITY GATE

**No implementation should be considered "done" until this verification passes.**

## Execution Steps

1. **Setup Check**: Verify required services are running:
   - Check if Aspire backend is running at http://localhost:8000/health
   - Check if frontend is running at http://localhost:3000
   - If not running, provide these startup commands and STOP:
     ```powershell
     # Start Aspire (non-blocking - runs in background process)
     Start-Process -FilePath "dotnet" -ArgumentList "run", "--project", "services\aspire\AppHost\AppHost.csproj" -WorkingDirectory "$PWD"
     
     # Start frontend (in separate terminal)
     cd apps/web && npm run dev
     ```

2. **Run API Tests** (MUST PASS 100%):
   ```powershell
   cd services/api
   python -m pytest tests/ -v -p no:asyncio
   ```
   - Record: Total tests, Passed, Failed
   - If ANY fail: List failures and STOP

3. **Run Frontend Unit Tests** (MUST PASS 100%):
   ```powershell
   cd apps/web
   npm run test:run
   ```
   - Record: Total tests, Passed, Failed
   - If ANY fail: List failures and STOP

4. **Run E2E Tests** (MUST PASS 100%):
   ```powershell
   cd apps/web
   $env:USE_EXTERNAL_SERVER = "true"; npx playwright test
   ```
   - Record: Total tests, Passed, Failed
   - If ANY fail: List failures and STOP

5. **Update Verification Checklist**:
   - Open `specs/[feature]/checklists/verification.md`
   - Mark all passing test gates as [X]
   - Record test counts and date

6. **Report Results**:
   ```
   ## Verification Report
   
   | Suite | Total | Passed | Failed | Status |
   |-------|-------|--------|--------|--------|
   | API   | X     | X      | 0      | ✅/❌  |
   | Frontend | X  | X      | 0      | ✅/❌  |
   | E2E   | X     | X      | 0      | ✅/❌  |
   
   **Overall**: PASS/FAIL
   **Date**: YYYY-MM-DD
   ```

## Failure Handling

If ANY test fails:
1. **DO NOT** mark tasks as complete
2. **DO NOT** proceed to next phase
3. **LIST** all failing tests with error messages
4. **SUGGEST** fixes for common issues
5. **REQUIRE** re-running verification after fixes

## Success Criteria

Verification passes ONLY when:
- [ ] API tests: 100% pass rate
- [ ] Frontend tests: 100% pass rate
- [ ] E2E tests: 100% pass rate
- [ ] Verification checklist updated
