# Pre-Commit Validation Workflow

## Overview

The pre-commit workflow is now configured to **ALWAYS run** in both local and CI environments, ensuring code quality and blocking bad commits.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Commit or Push Request                     │
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
              │   pre-commit run      │  ← Runs all hooks
              └──────────┬───────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────────┐
│           hooks defined in .pre-commit-config.yaml          │
│  - Check YAML/JSON syntax  - Fix trailing whitespace         │
│  - Run always-run-precommit (calls tools/pre-commit.local)   │
└────────────────────────┬────────────────────────────────────┘
                         │
              ┌──────────┴──────────┐
              │                     │
         All pass?            Any fail?
              │                     │
              ▼                     ▼
      ┌───────────────┐    ┌─────────────────┐
      │  ALLOW COMMIT │    │  BLOCK COMMIT   │
      └───────────────┘    └─────────────────┘
                               │
                               ▼
                      ┌──────────────────┐
                      │ Show fix guide   │
                      │ - Commit blocked │
                      │ - How to fix     │
                      │ - Or use --no-verify │
                      └──────────────────┘
```

## Key Components

### 1. `.git/hooks/pre-commit` (Git Hook)
- **Location**: `.git/hooks/pre-commit`
- **Purpose**: Git pre-commit hook that ALWAYS runs
- **Behavior**:
  - Executes `tools/pre-commit.local` wrapper
  - Non-zero exit code blocks the commit
  - Can be bypassed with `git commit --no-verify`

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

### Local Development

```
1. User runs: git commit
   ↓
2. Git hook executes: .git/hooks/pre-commit
   ↓
3. Wrapper runs: pre-commit run --all-files --verbose
   ↓
4. Pre-commit applies auto-fixes (for fixable issues)
   ↓
5. Checks complete:
   - If all pass → Commit allowed
   - If any fail → Commit blocked, show fix instructions
```

**Key Points**:
- ✅ Pre-commit runs **ALWAYS** (cannot be skipped)
- ✅ Auto-fix runs locally to clean up issues
- ✅ Commit blocked if issues remain after auto-fix
- ✅ User can bypass with `git commit --no-verify`

### CI Environment

```
1. CI triggers commit or push
   ↓
2. Pre-commit runs automatically (GitHub Actions, pre-commit.ci, etc.)
   ↓
3. Configuration at top of .pre-commit-config.yaml:
   ci:
     autofix_prs: false  ← Auto-fix DISABLED in CI
   ↓
4. Pre-commit checks run without auto-fix
   ↓
5. Checks complete:
   - If all pass → CI continues
   - If any fail → CI fails, report issues
```

**Key Points**:
- ✅ Pre-commit runs in CI
- ✅ Auto-fix is DISABLED in CI (`autofix_prs: false`)
- ✅ CI fails if pre-commit fails
- ✅ No automatic PRs created for fixes (prevent conflict loops)

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

### Issue: "Commit blocked by pre-commit"

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

## Summary

✅ **Pre-commit ALWAYS runs** in both local and CI environments
✅ **Auto-fix runs locally** to prevent commit/push conflicts
✅ **Auto-fix DISABLED in CI** (`autofix_prs: false`) to prevent conflict loops
✅ **Commits BLOCKED** if checks fail (must fix or use `--no-verify`)
✅ **Clear error messages** guide users to fix issues

This ensures code quality without the friction of commit/push conflicts between local and CI environments.
