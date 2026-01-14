# Agent Configuration Improvements - Implementation Summary

**Date**: 2026-01-13
**Constitution Version**: 1.1.0

---

## Scope

This update addresses critical shortcuts in agent configurations that violate constitutional principles and prevent proper best practice enforcement. The changes align all agents with the **NON-NEGOTIABLE** testing requirements mandated by Constitution VI.5.

---

## Critical Issues Fixed

### ✅ 1. Test Enforcement (Constitution VI.5 Violation)

**Problem**: Multiple agents treated tests as optional:
- `speckit.tasks.agent.md`: "Tests are OPTIONAL - only include them if explicitly requested"
- `speckit.implement.agent.md`: Allowed `-SkipE2E` "for faster development iteration"
- Constitution VI.5 said tests were "MUST" and "SHOULD" creating ambiguity

**Fix Applied**:
- Updated Constitution VI.5 to be **NON-NEGOTIABLE** with explicit requirements:
  - **MUST** include unit, integration, AND E2E tests (was optional)
  - Tests MUST be written before implementation (TDD)
  - 100% pass rate required before ANY task can be marked complete
  - **PROHIBITED**: `-SkipE2E` or partial test skipping for task completion

- Updated agents to enforce:
  - `speckit.tasks.agent.md`: Tests ALWAYS included, NEVER optional
  - `tasks-template.md`: Tests NON-NEGOTIABLE, always required
  - Added TDD requirement: Tests MUST fail initially
  - All test categories (unit, integration, E2E) are mandatory

### ✅ 2. Automated Service Management (Constitution IV Violation)

**Problem**:
- No enforcement of background process pattern across agents
- Manual service startup instructions in `speckit.verify.agent.md`
- Violates Constitution IV.4 which prohibits `aspire run` directly

**Fix Applied**:
- Added Constitution IV.1: **Automated Service Management**
  - Mandatory background process pattern for ALL agents
  - Powershell `Start-Process` requirement
  - Prohibited: Never use `aspire run` or `dotnet run` for follow-up commands
  - Agents MUST verify background processes before tests
  - Startup help ONLY via Start-Process pattern

- Updated Constitution IV.4:
  - Simplified dev environment guidance
  - Added: "Background process checks REQUIRED"
  - All agents MUST verify services via background processes

### ✅ 3. Constitution Compliance Enforcement (Constitution VII.2)

**Problem**: Constitution amendments didn't require updating dependent agents:
- No mechanism to ensure agents reflect new principles
- Outdated agent config could persist indefinitely

**Fix Applied**:
- Updated Constitution VII.2 Amendment Process:
  - Added: "ALL dependent agents MUST be checked and updated"
  - Makes agent updates part of amendment process required

### ✅ 4. Script Documentation Warnings

**Problem**: Test scripts allowed `-SkipE2E` without constitutional warnings:
- No indication that skipping violates Constitution VI.5
- Developers might skip E2E for production verification

**Fix Applied**:
- Updated `scripts/run-tests.ps1` documentation:
  - Added WARNING: "-SkipE2E is for development iteration ONLY"
  - Explicit reference to Constitution VI.5
  - Clarified: "do NOT use for final verification per Constitution VI.5"

---

## Constititution Changes (Version 1.0.2 → 1.1.0)

### Principles Updated

#### VI. Engineering Quality (Testing)
**Before**:
- Unit tests: MUST cover business logic and transformation functions.
- Integration tests: SHOULD cover database access and job processing.
- Smoke tests: SHOULD verify deployment succeeded and critical paths work.

**After**:
- Unit tests: **MUST** cover business logic, transformation functions, data models, and service methods.
- Integration tests: **MUST** cover database access, message contracts, and cross-service communication.
- E2E tests: **MUST** cover all user story acceptance criteria and critical user journeys.
- Test-driven development: Tests **MUST** be written before implementation and fail initially.
- 100% pass rate required: NO task may be marked complete until ALL automated tests pass.
- No skipping allowed: `-SkipE2E` or any partial test skipping is prohibited for task completion.
- Smoke tests: SHOULD verify deployment succeeded and critical paths work.

#### IV. Reliability & Operations
**New Section**: IV.1 - Automated service management
- Added mandatory background process pattern
- Powershell code example with `Start-Process -WindowStyle Hidden`
- Prohibited `aspire run` and `dotnet run` for follow-up commands
- All agents MUST verify services via background processes

#### VII. Change Management (Amendment Process)
**Updated** VII.2:
- Added: "ALL dependent agents MUST be checked and updated" to reflect new principles

---

## Agent Updates

### speckit.tasks.agent.md
**Changed**:
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

### tasks-template.md
**Changed**:
```diff
- **Tests**: The examples below include test tasks. Tests are OPTIONAL...
+ **Tests**: The examples below include test tasks. Tests are **NON-NEGOTIABLE** per Constitution VI.5...
+ - **ALL features MUST include unit, integration, and E2E tests**. Tests are NEVER optional.
```

### run-tests.ps1
**Changed**:
```diff
- Use -SkipE2E for faster development iteration.
- .PARAMETER SkipE2E
    Skip E2E tests (faster, but incomplete verification)
+ WARNING: -SkipE2E is for development iteration ONLY - per Constitution VI.5, E2E tests are REQUIRED for task completion.
+ .PARAMETER SkipE2E
    Skip E2E tests (DEVELOPMENT ONLY - do NOT use for final verification per Constitution VI.5)
```

---

## Remaining Work Required

### ⚠️ High Priority

**speckit.implement.agent.md**
- Section 10 mentions `-SkipE2E` option as acceptable for "faster development iteration"
- Update to: "NEVER use -SkipE2E for task completion - per Constitution VI.5, 100% pass rate required"
- Remove or deprecate the -SkipE2E mention in "Completion validation" section

**speckit.verify.agent.md**
- Manual service startup instructions need automated enforcement
- Update section "1. Prerequisites Check" to use automated background process verification
- Add check for Aspire background process before running tests
- Remove manual instructions that violate Constitution IV.1

**speckit.clarify.agent.md**
- Line 42: "Note: This clarification workflow is expected to run (and be completed) BEFORE invoking `/speckit.plan`. If the user explicitly states they are skipping clarification (e.g., exploratory spike), you may proceed, but must warn that downstream rework risk increases."
- Update to: "Skipping clarification (exploratory spike) is permitted but flagged - ensure all constitutional requirements are still met"

**speckit.checklist.agent.md**
- Template includes verification checklist items that test implementation rather than requirements quality
- Need to separate:
  - Requirements quality testing (correct purpose)
  - Implementation testing (violation - should be in verification agent only)

### 📝 Medium Priority

**speckit.plan.agent.md**
- Section "Constitution Check" says "ERROR if violations unjustified"
- Needs: Automated validation of constitutional compliance before proceeding
- Should reference specific violated principles with justification requirement

**speckit.analyze.agent.md**
- Constitution compliance exists but no enforcement mechanism
- Should flag constitutional violations as CRITICAL (currently does)

**checklist-template.md**
- Contains mixed-purpose items (requirements quality vs implementation verification)
- Split template into:
  - `requirements-quality-template.md` (correct usage)
  - `implementation-verification-template.md` (for verify agent)

---

## Testing Strategy for These Changes

1. **Constitution Update Verification**:
   - [ ] Run `speckit.implement` on a new feature
   - [ ] Verify tests are ALWAYS generated even without explicit request
   - [ ] Verify -SkipE2E is NOT accepted for task completion

2. **Background Process Enforcement**:
   - [ ] Run `speckit.verify` without Aspire running
   - [ ] Verify agent starts Aspire via Start-Process pattern
   - [ ] Verify manual `aspire run` is NOT used

3. **Agent Compliance**:
   - [ ] Review all agents for remaining constitutional violations
   - [ ] Run semantic search for "OPTIONAL" + "test" patterns
   - [ ] Update any remaining violations

---

## Migration Guide for Existing Features

For in-progress features that were using the old optional test approach:

1. **If tests were already written**:
   - No action needed - continue with implementation

2. **If tests were skipped**:
   - Stop implementation
   - Generate full test suite per Constitution VI.5:
     - Unit tests for all business logic
     - Integration tests for database/message contracts
     - E2E tests for all user stories
   - Ensure tests fail initially (TDD)
   - Complete implementation
   - Run 100% test pass rate verification

3. **If using -SkipE2E**:
   - Change to: `.\scripts\run-tests.ps1` (no -SkipE2E flag)
   - Fix any E2E test failures
   - Only mark tasks complete after 100% pass rate

---

## Next Steps

1. **High Priority**: Update remaining agents (speckit.implement, speckit.verify, speckit.checklist)
2. **Documentation**: Update AGENTS.md to reflect new constitutional requirements
3. **Testing**: Create test scenario to verify enforcement works
4. **Training**: Note the change for anyone using old workflow patterns

---

## References

- Constitution: `.specify/memory/constitution.md` (v1.1.0)
- Agent Configs: `.github/agents/*.agent.md`
- Templates: `.specify/templates/*.md`
- Test Script: `scripts/run-tests.ps1`
