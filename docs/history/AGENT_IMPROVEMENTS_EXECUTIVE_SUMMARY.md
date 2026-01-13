# Agent Configuration Best Practices Update - Executive Summary

**Date**: 2026-01-13
**Constitution Version**: 1.2.0 (Final)

---

## 🎯 Problem Identified

You were absolutely right. We were taking repeated shortcuts instead of enforcing best practices:

### ❌ Critical Shortcuts Being Taken

1. **Tests treated as optional** (violated Constitution VI.5)
   - speckit.tasks agent: "Tests are OPTIONAL - only include if explicitly requested"
   - developers could skip writing tests entirely
   - constitution said tests were "SHOULD" instead of "MUST"

2. **Manual E2E test skipping** (violated Constitution VI.5)
   - speckit.implement agent: `-SkipE2E` allowed for "faster development iteration"
   - developers could mark tasks complete without E2E tests
   - constitution had no enforcement of 100% pass rate

3. **No background process enforcement** (violated Constitution IV)
   - verification agent provided manual service startup instructions
   - constitution prohibited `aspire run` but agents didn't enforce it
   - risk: long-running processes killed on next command

4. **Constitution compliance not automatic** (violated Constitution VII.2)
   - amendments didn't require updating dependent agents
   - outdated agent configs could persist indefinitely

---

## ✅ Changes Applied

### 1. Constitution v1.0.2 → v1.1.0 (MAJOR)

**VI. Engineering Quality - Testing** (NOW NON-NEGOTIABLE)

```diff
- Unit tests: MUST cover business logic and transformation functions.
- Integration tests: SHOULD cover database access and job processing.
- Smoke tests: SHOULD verify deployment succeeded and critical paths work.
+ Unit tests: MUST cover business logic, transformation functions, data models, and service methods.
+ Integration tests: MUST cover database access, message contracts, and cross-service communication.
+ E2E tests: MUST cover all user story acceptance criteria and critical user journeys.
+ Test-driven development: Tests MUST be written before implementation and fail initially.
+ 100% pass rate required: NO task may be marked complete until ALL automated tests pass.
+ No skipping allowed: `-SkipE2E` or any partial test skipping is prohibited for task completion.
+ Smoke tests: SHOULD verify deployment succeeded and critical paths work.
```

**IV. Reliability & Operations** (NEW SECTION)

```diff
+ 1. Automated service management: ALL background services MUST use official background process pattern:
+    ```powershell
+    # Start Aspire in background (detached) - REQUIRED for non-blocking execution
+    Start-Process -FilePath "dotnet" -ArgumentList "run", "--project", "services\aspire\AppHost\AppHost.csproj" -WindowStyle Hidden
+    Start-Sleep -Seconds 30
+    ```
+    - ⚠️ PROHIBITED: Never use `aspire run` or `dotnet run` directly
+    - Verification agents MUST use existing background processes or start them via PowerShell Start-Process
+    - Fixed ports: API runs on `http://localhost:8000`, Web runs on `http://localhost:3000`
```

**VII. Change Management** (ENHANCED)

```diff
- Update Sync Impact Report.
- Propagate changes to dependent templates.
+ Update Sync Impact Report.
+ Propagate changes to dependent templates.
+ ALL dependent agents MUST be checked and updated to reflect new principles
```

### 2. Agent Updates Enforcing Best Practices

**speckit.tasks.agent.md**
```diff
- **Tests are OPTIONAL**: Only generate test tasks if explicitly requested...
+ **Tests are NON-NEGOTIABLE (Constitution VI.5)**:
+ - **ALWAYS** generate test tasks - NEVER skip or make them optional
+ - Required test types per Constitution:
+   - Unit tests: MUST cover business logic, transformation functions, data models, service methods
+   - Integration tests: MUST cover database access, message contracts, cross-service communication
+   - E2E tests: MUST cover all user story acceptance criteria and critical user journeys
+ - Test-driven approach: Tests MUST be written and FAIL before implementation tasks
+ - **NO EXCEPTIONS**: Even if spec doesn't mention tests, they MUST be included
```

**tasks-template.md**
```diff
- **Tests**: The examples below include test tasks. Tests are OPTIONAL...
+ **Tests**: The examples below include test tasks. Tests are **NON-NEGOTIABLE**...
+ - **ALL features MUST include unit, integration, and E2E tests**. Tests are NEVER optional.
```

**run-tests.ps1**
```diff
- Use -SkipE2E for faster development iteration.
- .PARAMETER SkipE2E
    Skip E2E tests (faster, but incomplete verification)
+ WARNING: -SkipE2E is for development iteration ONLY - per Constitution VI.5...
+ .PARAMETER SkipE2E
    Skip E2E tests (DEVELOPMENT ONLY - do NOT use for final verification per Constitution VI.5)
```

**AGENTS.md** (updated Test Enforcement section)
```diff
### Options:
# Run ALL tests (default - includes E2E, requires Aspire)
.\scripts\run-tests.ps1
- # Skip E2E for faster development iteration
- .\scripts\run-tests.ps1 -SkipE2E
# Run specific component only
.\scripts\run-tests.ps1 -Component api

### Rules:
1. **NEVER mark a task [X] if tests fail**
2. **NEVER rationalize skipping E2E tests** - they catch integration issues that unit tests miss
3. **If Aspire isn't running, the script will start it automatically**
4. **Unit tests alone are NOT sufficient** - E2E tests are required for completion verification
+ ### Options:
+ # Run ALL tests (default - includes E2E, requires Aspire)
+ .\scripts\run-tests.ps1
+ # Run specific component only
+ .\scripts\run-tests.ps1 -Component api
+
+ ### Rules (Constitution VI.5 - NON-NEGOTIABLE):
+ 1. **NEVER mark a task [X] if ANY tests fail** (100% pass rate required)
+ 2. **E2E tests are MANDATORY** - they catch integration issues that unit tests miss
+ 3. **NEVER use -SkipE2E for task completion** - this is for development iteration only
+ 4. **If Aspire isn't running, use Start-Process per Constitution IV.1** (not `aspire run`)
+ 5. **Unit + Integration + E2E tests are ALL REQUIRED** per Constitution VI.5
```

---

## 📊 Impact Summary

### Before vs After

| Aspect | Before | After |
|---------|---------|--------|
| **Test Status** | OPTIONAL (spec must request) | **MANDATORY** (always required) |
| **Test Coverage** | Unit ("MUST"), Integration ("SHOULD") | Unit + Integration + E2E (**ALL MUST**) |
| **E2E Tests** | Can skip (-SkipE2E allowed) | **PROHIBITED** for task completion |
| **Pass Rate** | Not enforced | **100% required** |
| **TDD** | Not required | Tests **MUST fail initially** |
| **Background Processes** | Manual, inconsistent | **MUST use Start-Process** |
| **Constitution Enforcement** | Manual ("ERROR if unjustified") | **Required** in agents |

---

## 🚨 Still Needs Work (High Priority)

The following agents still need updates:

### 1. **speckit.implement.agent.md** (Section 10)
**Current**: Mentions `-SkipE2E` as acceptable option
**Fix Required**: Remove or deprecate `-SkipE2E` mention, add constitutional warning

### 2. **speckit.verify.agent.md** (Section 1)
**Current**: Manual service startup instructions
**Fix Required**: Use automated background process verification per Constitution IV.1

### 3. **speckit.clarify.agent.md** (Line 42)
**Current**: Allows skipping clarification for "exploratory spike"
**Fix Required**: Warn that constitutional requirements must still be met even if skipping

### 4. **speckit.checklist.agent.md**
**Current**: Template has mixed-purpose items (requirements quality + implementation testing)
**Fix Required**: Split into separate templates for different purposes

---

## 🎓 What This Means for Development

### For AI Agents

✅ **Tests are now non-negotiable**:
- Every feature spec requires a full test suite
- No feature can skip unit, integration, or E2E tests
- Test-driven development is now required

✅ **Background processes are enforced**:
- All services MUST start via `Start-Process -WindowStyle Hidden`
- Manual `aspire run` is prohibited in all agents
- Verification happens automatically

✅ **Constitution is authoritative**:
- All agents must check constitution compliance
- Amendments trigger agent update review
- No agent can override constitutional principles

### For Developers

✅ **Testing is always required**:
- Cannot skip tests even for "simple" features
- Must write tests BEFORE implementation (they must fail)
- Cannot mark tasks complete until 100% pass rate

✅ **E2E tests are mandatory**:
- `-SkipE2E` is ONLY for development iteration
- Final verification REQUIRES E2E tests
- Feature is incomplete without E2E passing

✅ **Service management is consistent**:
- Always use background process pattern
- Never use blocking `aspire run` or `dotnet run`
- Verification is automated

---

## 📋 Next Steps

### Immediate (High Priority)
1. **Update speckit.implement.agent.md** - Remove `-SkipE2E` mentions
2. **Update speckit.verify.agent.md** - Add background process checks
3. **Update speckit.clarify.agent.md** - Add constitutional warnings
4. **Update speckit.checklist.agent.md** - Split template purposes

### Short Term
1. **Create test scenario** - Verify enforcement works end-to-end
2. **Update documentation** - Update any remaining references to old patterns
3. **Train team** - Explain new non-negotiable testing requirements

### Long Term
1. **Automated compliance checking** - Add CI checks for constitutional violations
2. **Constitution audit** - Regular review of agent configurations
3. **Metrics tracking** - Track test coverage and pass rates over time

---

## 📚 References

- Updated Constitution: `.specify/memory/constitution.md` (v1.1.0)
- Implementation Summary: `AGENT_IMPROVEMENTS_SUMMARY.md`
- Agent Configs: `.github/agents/*.agent.md`
- Templates: `.specify/templates/*.md`

---

**✅ Status**: Constitution v1.1.0 Live - Best Practices Now Enforced

**⚠️ Action Required**: Update remaining high-priority agents to complete enforcement
