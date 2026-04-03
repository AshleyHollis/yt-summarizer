# Tasks: {feature-name}

## Overview
- **Total Tasks**: {count}
- **Workflow**: {POC-first | TDD Red-Green-Yellow | Bug TDD}
- **Intent**: {GREENFIELD | MID_SIZED | REFACTOR | BUG_FIX | TRIVIAL}

### Phase Distribution
| Phase | Tasks | Percentage |
|-------|-------|-----------|
| {phase name} | {count} | {percent}% |

## Completion Criteria
- [ ] All tasks checked off
- [ ] All tests passing (zero regressions)
- [ ] CI green
- [ ] PR created and reviewed
- [ ] All review comments resolved

## Task Writing Guide

**Sizing**: Max 4 Do steps, max 3 files per task. Split if exceeded.

**Markers**:
- `[P]` — parallel-eligible (no unmet dependencies)
- `[VERIFY]` — quality checkpoint (breaks parallel groups)

**Principles**:
1. Done when > Do — the Done when is the contract, Do steps are guidance
2. All verification MUST be automated — no manual checks
3. One logical concern per task — no bundling unrelated changes
4. Surgical — touch only what the task requires

---

## Phase 1: {phase name}

- [ ] 1.1 {task title} [P]
  - **Agent**: {Lead | Frontend | Backend | Tester}
  - **Do**:
    1. {Specific action with file paths}
    2. {Next action}
  - **Files**: {file1}, {file2}
  - **Done when**: {Declarative success criteria}
  - **Verify**: `{automated command}`
  - **Commit**: `{conventional commit message}`
  - _Requirements: FR-1, AC-1.1_

- [ ] V1 [VERIFY] Quality check
  - **Agent**: Tester
  - **Do**: Run quality commands and verify all pass
  - **Verify**: `{lint cmd} && {typecheck cmd}`
  - **Done when**: No lint errors, no type errors
  - **Commit**: `chore({scope}): pass quality checkpoint` (if fixes needed)

---

## Final Verification

- [ ] V4 [VERIFY] Full local CI
  - **Agent**: Tester
  - **Do**: Run complete local CI pipeline
  - **Verify**: `{lint} && {typecheck} && {test} && {build}`
  - **Done when**: All commands exit 0

- [ ] V5 [VERIFY] CI pipeline passes
  - **Agent**: Tester
  - **Do**: Verify GitHub Actions checks are green
  - **Verify**: `gh pr checks --watch`
  - **Done when**: All CI checks pass

- [ ] V6 [VERIFY] Acceptance criteria checklist
  - **Agent**: Tester
  - **Do**: Programmatically verify each AC-* is satisfied
  - **Verify**: `{automated AC verification commands}`
  - **Done when**: All acceptance criteria confirmed
