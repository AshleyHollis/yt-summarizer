```chatagent
---
description: Run complete test verification to ensure implementation works correctly - ALL AUTOMATED
---

## User Input

```text
$ARGUMENTS
```

You **MUST** consider the user input before proceeding (if not empty).

## Outline

This agent verifies that implementation actually works by running ALL automated test suites and confirming 100% pass rate.

** ALL VERIFICATION IS AUTOMATED - NO MANUAL TESTING**

### 1. Prerequisites Check

Run health checks to ensure services are available:

```powershell
# Check API health
Invoke-WebRequest -Uri "http://localhost:8000/health" -Method GET -ErrorAction SilentlyContinue

# Check frontend
Invoke-WebRequest -Uri "http://localhost:3000" -Method GET -ErrorAction SilentlyContinue
```

If services are NOT running, provide these startup commands:

```powershell
# Start Aspire in background (NEVER use blocking 'aspire run' or 'dotnet run')
Start-Process -FilePath "dotnet" -ArgumentList "run", "--project", "services\aspire\AppHost\AppHost.csproj" -WindowStyle Hidden
Start-Sleep -Seconds 30  # Wait for services to initialize

# Start frontend dev server in background
Start-Process -FilePath "npm" -ArgumentList "run", "dev" -WorkingDirectory "apps\web" -WindowStyle Hidden
Start-Sleep -Seconds 10
```

 **CRITICAL**: Never use `aspire run` or `dotnet run` directly - they block the terminal and prevent subsequent commands.

- **STOP** and wait for user to start services

### 2. Run ALL Automated Test Suites

Execute ALL test suites in order. Each MUST pass 100%:

**API Tests:**
```powershell
cd services/api
python -m pytest tests/ -v -p no:asyncio
```

**Worker Tests (including Message Contracts):**
```powershell
cd services/workers
python -m pytest tests/ -v -p no:asyncio
```

**Shared Package Tests:**
```powershell
cd services/shared
python -m pytest tests/ -v -p no:asyncio
```

**Frontend Unit Tests:**
```powershell
cd apps/web
npm run test:run
```

**E2E Tests (requires running services):**
```powershell
cd apps/web
$env:USE_EXTERNAL_SERVER = "true"; npx playwright test
```

### 3. Test Coverage Categories

Verify tests exist for each category:

**Unit Tests:**
- [ ] API route handlers
- [ ] Service layer business logic
- [ ] Frontend components
- [ ] Worker processing logic

**Integration Tests:**
- [ ] API  Database integration
- [ ] Worker  Queue integration
- [ ] Cross-service communication

**Message Contract Tests:**
- [ ] Message dataclass required fields
- [ ] Data propagation through pipeline
- [ ] Enum/status consistency between services
- [ ] Full pipeline message flow

**E2E Tests:**
- [ ] User Story flows automated
- [ ] Error handling scenarios
- [ ] Edge cases

### 4. Evaluate Results

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

### 5. Update Verification Checklist

Only if ALL tests pass:
- Open `specs/[feature]/checklists/verification.md`
- Mark test gate items as [X]
- Record test counts
- Record verification date

### 6. Generate Report

Output a verification report:

```markdown
##  Verification Report

**Date**: [DATE]
**Status**:  PASSED /  FAILED
**Manual Tests Required**: 0 (ALL AUTOMATED)

| Test Suite | Total | Passed | Failed | Rate |
|------------|-------|--------|--------|------|
| API        | X     | X      | X      | X%   |
| Workers    | X     | X      | X      | X%   |
| Shared     | X     | X      | X      | X%   |
| Frontend   | X     | X      | X      | X%   |
| E2E        | X     | X      | X      | X%   |
| **Total**  | X     | X      | X      | X%   |

### Test Coverage Summary
- Unit Tests: /
- Integration Tests: /
- Message Contract Tests: /
- E2E Tests: /

### Next Steps
- [If PASSED]: Implementation verified. Tasks can be marked complete.
- [If FAILED]: Fix failing tests before marking tasks complete.
```

## Critical Rules

1. **NEVER** mark tasks [X] if any test fails
2. **ALWAYS** run ALL automated test suites (API, Workers, Shared, Frontend, E2E)
3. **ALWAYS** require 100% pass rate
4. **NO MANUAL TESTING** - all verification is automated
5. **STOP** immediately on failure and report issues

```
