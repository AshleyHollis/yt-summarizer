# Pre-Commit Validation Workflow

## Overview

The pre-commit workflow is now configured to **ALWAYS run** in both local and CI environments, ensuring code quality and blocking bad commits.

**NEW: Pre-push Hook Added**
- `.git/hooks/pre-push` validates code before allowing push to remote
- Blocks push if pre-commit checks would fail
- Prevents pushing code that will fail in CI
- Can be bypassed with `git push --no-verify` (not recommended)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    LOCAL COMMIT                            │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │  .git/hooks/pre-commit │  ← Git hook (always runs)
              └──────────┬───────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │ tools/pre-commit.local │  ← PowerShell wrapper
              └──────────┬───────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │   pre-commit run      │  ← Runs all hooks + AUTO-FIX
              └──────────┬───────────┘
                         │
              ┌──────────┴──────────┐
              │                     │
         All pass?            Any fail?
              │                     │
              ▼                     ▼
      ┌───────────────┐    ┌─────────────────┐
      │  ALLOW COMMIT │    │  BLOCK COMMIT   │
      └───────────────┘    └─────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    LOCAL PUSH                              │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │  .git/hooks/pre-push  │  ← NEW: Git hook (always runs)
              └──────────┬───────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │   pre-commit run      │  ← Runs all hooks, NO AUTO-FIX
              └──────────┬───────────┘
                         │
              ┌──────────┴──────────┐
              │                     │
         All pass?            Any fail?
              │                     │
              ▼                     ▼
      ┌───────────────┐    ┌─────────────────┐
      │  ALLOW PUSH   │    │  BLOCK PUSH     │
      └───────────────┘    └─────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    REMOTE CI                              │
└────────────────────────┬────────────────────────────────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │   CI Pipeline         │  ← GitHub Actions
              └──────────┬───────────┘
                         │
                         ▼
              ┌──────────────────────┐
              │   Lint + Test        │  ← No pre-commit checks
              └──────────┬───────────┘
                         │
              ┌──────────┴──────────┐
              │                     │
         All pass?            Any fail?
              │                     │
              ▼                     ▼
      ┌───────────────┐    ┌─────────────────┐
      │  ALLOW MERGE  │    │  BLOCK MERGE    │
      └───────────────┘    └─────────────────┘
```

## Key Components

### 1. `.git/hooks/pre-commit` (Git Hook)
- **Location**: `.git/hooks/pre-commit`
- **Purpose**: Git pre-commit hook that ALWAYS runs
- **Behavior**:
  - Executes `tools/pre-commit.local` wrapper
  - Auto-fixes issues where possible
  - Non-zero exit code blocks the commit
  - Can be bypassed with `git commit --no-verify`

### 2. `.git/hooks/pre-push` (Git Hook - NEW)
- **Location**: `.git/hooks/pre-push`
- **Purpose**: Git pre-push hook that ALWAYS runs
- **Behavior**:
  - Executes `tools/pre-commit.local` wrapper WITHOUT auto-fix
  - Valid-only mode: Checks for issues, reports them
  - Non-zero exit code blocks the push
  - Can be bypassed with `git push --no-verify`
- **Key Difference**: Runs validation BEFORE code reaches remote

### 2. `tools/pre-commit.local` (Wrapper Script)
- **Location**: `tools/pre-commit.local`
- **Purpose**: PowerShell wrapper that runs pre-commit
- **Behavior**:
  - Finds `pre-commit` executable on PATH
  - Runs `pre-commit run --all-files --verbose`
  - Auto-fixes issues where possible
  - Returns exit code (0 = pass, non-zero = fail)

### 3. `.pre-commit-config.yaml` (Configuration)
- **Location**: `.pre-commit-config.yaml`
- **Key Hook**: `always-run-precommit`
  - Runs via pre-commit framework
  - Cannot be skipped with `SKIP_PRE_COMMIT`
  - Calls `tools/pre-commit.local`

## How It Works in Different Environments

### Local Development - Three-Stage Protection

```
STAGE 1: COMMIT
1. User runs: git commit
   ↓
2. Git hook executes: .git/hooks/pre-commit
   ↓
3. Wrapper runs: pre-commit run --all-files --verbose
   ↓
4. Pre-commit applies auto-fixes (for fixable issues)
   ↓
5. Checks complete:
   - If all pass → Commit allowed ✅
   - If any fail → Commit blocked, show fix instructions ❌

STAGE 2: PUSH
1. User runs: git push
   ↓
2. Git hook executes: .git/hooks/pre-push
   ↓
3. Wrapper runs: pre-commit run --all-files --verbose (VALIDATION ONLY)
   ↓
4. Pre-commit checks WITHOUT auto-fix
   ↓
5. Checks complete:
   - If all pass → Push allowed ✅
   - If any fail → Push blocked, show fix instructions ❌

STAGE 3: REMOTE CI
1. Code reaches remote (if push succeeded)
   ↓
2. GitHub Actions CI triggers
   ↓
3. CI runs: lint → security → tests
   ↓
4. Checks complete:
   - If all pass → Merge allowed ✅
   - If any fail → Merge blocked ❌
```

**Key Points**:
- ✅ Pre-commit runs on **EVERY commit** (cannot be skipped)
- ✅ Pre-commit runs on **EVERY push** (cannot be skipped)
- ✅ Git hooks use environment detection for CI vs local
- ✅ Auto-fix runs on commit, NOT on push
- ✅ Commit blocked if issues remain after auto-fix
- ✅ Push blocked if pre-commit checks would fail
- ✅ Push can be bypassed with `git push --no-verify` (not recommended)
- ✅ CI fails if pre-commit checks would not pass (via lint/tests)

## Validation Behaviors

### When Pre-Commit Passes

```bash
✓ Check YAML syntax
✓ Check JSON syntax
✓ Fix trailing whitespace
✓ Run always-run-precommit hook

========================================
PRE-COMMIT VALIDATION PASSED
========================================

[Commit proceeds]
```

### When Pre-Commit Fails

```bash
✓ Check YAML syntax
✗ Trailing whitespace found and auto-fixed
✗ YAML lint errors (not auto-fixable)

========================================
PRE-COMMIT VALIDATION FAILED
========================================

Your commit has been BLOCKED.

How to fix:
  1. Run 'pre-commit run --all-files --verbose' to auto-fix
  2. Review fixes: git diff
  3. Add fixes: git add .
  4. Commit again

To bypass ALL git hooks (not recommended):
  git commit --no-verify ...

[Commit blocked]
```

## Configuration Summary

### `.pre-commit-config.yaml`

```yaml
ci:
  autofix_prs: false  # Auto-fix DISABLED in CI (prevents conflicts)
  skip: []            # No hooks skipped in CI (all run)

repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    hooks:
      - id: check-yaml      # Check YAML syntax
      - id: check-json      # Check JSON syntax
      - id: end-of-file-fixer
      - id: trailing-whitespace

  - repo: local
    hooks:
      - id: always-run-precommit
        name: Pre-commit validator
        entry: pwsh -File tools\pre-commit.local
        language: system
        always_run: true   # Cannot be skipped
```

### `tools/pre-commit.local`

```powershell
# Find and validate pre-commit executable
$PreCommit = Get-Command "pre-commit" -ErrorAction SilentlyContinue

if (-not $PreCommit) {
    Write-Error "ERROR: pre-commit not found on PATH" -ForegroundColor Red
    exit 1
}

# Run local pre-commit with auto-fix
& pre-commit run --all-files --verbose
$ExitCode = $LASTEXITCODE

if ($ExitCode -ne 0) {
    # Show error and fix instructions
    exit $ExitCode
}

exit 0
```

### `.git/hooks/pre-commit`

```batch
@echo off
REM ALWAYS runs pre-commit validation
REM Block commits if checks fail
REM Can be bypassed with --no-verify

set REPO_ROOT=%~dp0..

echo ========================================
echo RUNNING PRE-COMMIT VALIDATION
echo ========================================
echo.

pwsh -File "%REPO_ROOT%\tools\pre-commit.local"
set EXIT_CODE=!ERRORLEVEL!

if !EXIT_CODE! NEQ 0 (
    exit /b !EXIT_CODE!
)

exit /b 0
```

## User Workflows

### Standard Workflow (Recommended)

```bash
# 1. Make code changes
vim my-file.yaml

# 2. Run pre-commit manually (optional but recommended)
pre-commit run --all-files --verbose

# 3. Review auto-fixes
git diff

# 4. Add auto-fixed files
git add .

# 5. Commit (hook runs automatically)
git commit -m "fix: update configuration"

# 6. Push to remote
git push origin my-branch
```

### Fast Workflow (Automatic Hook)

```bash
# 1. Make code changes
vim my-file.yaml

# 2. Add files
git add .

# 3. Commit (hook runs automatically)
git commit -m "fix: update configuration"
# → Pre-commit runs and auto-fixes if needed
# → If issues auto-fixed: git add needed to stage fixes
# → If issues remain: commit blocked with fix instructions

# 4. Re-commit if needed
git commit -m "fix: update configuration"

# 5. Push to remote
git push origin my-branch
```

### Emergency Bypass (Not Recommended)

```bash
# Force commit without pre-commit checks
git commit --no-verify -m "fix: emergency update"

# Note: This bypasses ALL git hooks
# Use only for emergency fixes where pre-commit is blocking critical work
```

## Troubleshooting

### Issue: "pre-commit not found on PATH"

**Fix**:
```bash
pip install pre-commit
```

### Issue: "Push blocked by pre-push"

**Fix**:
```bash
# Pre-push found issues - must fix before pushing
pre-commit run --all-files --verbose

# Review the fixes
git diff

# Add the fixes
git add .

# Commit the fixes
git commit -m "fix: apply pre-commit auto-fixes"

# Push again
git push origin my-branch
```

**Important**: Pre-push does NOT auto-fix - you must commit the fixes first.

**Fix**:
```bash
# Auto-fix issues
pre-commit run --all-files --verbose

# Review fixes
git diff

# Add fixes
git add .

# Commit again
git commit -m "fix: update configuration"
```

### Issue: Need to bypass pre-commit temporarily

**Fix**:
```bash
git commit --no-verify -m "fix: emergency update"
```

Warning: This bypasses ALL git hooks, including security checks.

## Comparison: Pre-commit vs Pre-push

| Aspect | Pre-commit Hook | Pre-push Hook |
|--------|----------------|---------------|
| **When it runs** | On every `git commit` | On every `git push` |
| **Purpose** | Clean up code before committing | Catch issues before pushing |
| **Auto-fix** | ✅ Yes (fixes issues) | ❌ No (validation only) |
| **Blocks** | Commits (no commit created) | Pushes (push not sent) |
| **Bypass command** | `git commit --no-verify` | `git push --no-verify` |
| **Environment** | Always runs | Always runs |
| **CI vs Local** | Same behavior in both | Same behavior in both |
| **File location** | `.git/hooks/pre-commit` | `.git/hooks/pre-push` |

### Why Both Hooks?

1. **Pre-commit**: Fix issues immediately while you're working
   - Auto-fix removes friction
   - Clean history (no messy fixes later)
   - Developer productivity

2. **Pre-push**: Catch issues before they reach remote
   - Last line of defense
   - Block pushes to prevent CI failures
   - Team code quality gate

3. **Both together**: Multi-layer protection
   - Fix early (pre-commit)
   - Validate before sharing (pre-push)

## Summary

✅ **Pre-commit ALWAYS runs** on every commit (blocks bad commits)
✅ **Pre-push ALWAYS runs** on every push (blocks bad pushes)
✅ **Auto-fix runs on commit** (not on push or CI)
✅ **Auto-fix DISABLED in CI** (`autofix_prs: false`) to prevent conflict loops
✅ **Multi-layer protection**: Commit blocked → Push blocked → CI blocked
✅ **Bypass available**: `git commit --no-verify` or `git push --no-verify` (not recommended)
✅ **Clear error messages** guide users to fix issues

This ensures code quality with three layers of protection, maintaining developer productivity while enforcing code standards.
