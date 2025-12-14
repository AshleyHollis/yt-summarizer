---
description: Run complete test verification to ensure implementation works correctly
---

## User Input

```text
$ARGUMENTS
```

You **MUST** consider the user input before proceeding (if not empty).

## Outline

This agent verifies that implementation actually works by running all test suites and confirming 100% pass rate.

### 1. Prerequisites Check

Run health checks to ensure services are available:

```powershell
# Check API health
Invoke-WebRequest -Uri "http://localhost:8000/health" -Method GET -ErrorAction SilentlyContinue

# Check frontend
Invoke-WebRequest -Uri "http://localhost:3000" -Method GET -ErrorAction SilentlyContinue
```

If services are NOT running:
- Display startup commands
- **STOP** and wait for user to start services

### 2. Run Test Suites

Execute ALL test suites in order. Each MUST pass 100%:

**API Tests:**
```powershell
cd services/api
python -m pytest tests/ -v -p no:asyncio
```

**Frontend Tests:**
```powershell
cd apps/web
npm run test:run
```

**E2E Tests (requires running services):**
```powershell
cd apps/web
$env:USE_EXTERNAL_SERVER = "true"; npx playwright test
```

### 3. Evaluate Results

For each test suite:
- Count total tests
- Count passed tests
- Count failed tests
- Calculate pass rate

**If pass rate < 100% for ANY suite:**
- List all failing tests with error messages
- Suggest fixes
- Mark verification as **FAILED**
- **DO NOT** update any task status

**If pass rate = 100% for ALL suites:**
- Mark verification as **PASSED**
- Update verification checklist

### 4. Update Verification Checklist

Only if ALL tests pass:
- Open `specs/001-product-spec/checklists/verification.md`
- Mark test gate items as [X]
- Record test counts
- Record verification date

### 5. Generate Report

Output a verification report:

```markdown
## 🧪 Verification Report

**Date**: [DATE]
**Status**: ✅ PASSED / ❌ FAILED

| Test Suite | Total | Passed | Failed | Rate |
|------------|-------|--------|--------|------|
| API        | X     | X      | X      | X%   |
| Frontend   | X     | X      | X      | X%   |
| E2E        | X     | X      | X      | X%   |
| **Total**  | X     | X      | X      | X%   |

### Next Steps
- [If PASSED]: Implementation verified. Tasks can be marked complete.
- [If FAILED]: Fix failing tests before marking tasks complete.
```

## Critical Rules

1. **NEVER** mark tasks [X] if any test fails
2. **ALWAYS** run all three test suites
3. **ALWAYS** require 100% pass rate
4. **STOP** immediately on failure and report issues
