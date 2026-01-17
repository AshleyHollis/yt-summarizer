# Git Hooks

This directory contains Git hooks for the repository, designed to enforce code quality at multiple stages of the development workflow.

## Overview

| Hook | Stage | Purpose | Auto-Fix | Blocks | Platform |
|------|-------|---------|----------|--------|----------|
| `pre-commit` | Before commit | Clean up code immediately | ✅ Yes | Bad commits | PowerShell (cross-platform) |
| `pre-push` | Before push | Catch issues before pushing | ❌ No | Bad pushes | PowerShell (cross-platform) |

## Windows Compatibility

**Important for Windows users**: Git hooks are PowerShell scripts. On Windows, you must configure Git to use the `githooks` directory:

```powershell
# Configure per-repository (recommended)
git config core.hooksPath githooks

# Or configure globally for all repos
git config --global core.hooksPath githooks
```

This tells Git to run hooks from the `githooks/` directory directly. The hooks include batch wrappers (`pre-commit.bat`, `pre-push.bat`) that call PowerShell scripts on Windows. On Unix-like systems, Git runs `.ps1` files directly with the `#!/usr/bin/env pwsh` shebang.

## Setup

### Automatic Setup (Recommended)

Run setup script to copy hooks to `.git/hooks/`:

```powershell
# Windows (PowerShell) - works on all platforms with pwsh
pwsh -File scripts/setup-githooks.ps1
```

### Manual Setup

**Windows users**: Git needs to be configured to use PowerShell for hooks

```powershell
# Configure Git to use PowerShell for hooks
git config --global core.hooksPath githooks

# Or configure per-repository (recommended)
git config core.hooksPath githooks
```

**Linux/macOS users**:

```bash
# Copy hooks to .git/hooks/
cp githooks/pre-commit .git/hooks/pre-commit
cp githooks/pre-push .git/hooks/pre-push

# Make hooks executable
chmod +x .git/hooks/pre-commit
chmod +x .git/hooks/pre-push
```

**Important**: Git hooks are now PowerShell scripts for cross-platform compatibility. PowerShell Core (pwsh) is available on Windows, macOS, and Linux. On Windows, PowerShell 5.1+ is also available by default.

### Manual Setup

```bash
# Copy hooks to .git/hooks/
cp githooks/pre-commit .git/hooks/pre-commit
cp githooks/pre-push .git/hooks/pre-push

# Make hooks executable (Linux/macOS only)
chmod +x .git/hooks/pre-commit
chmod +x .git/hooks/pre-push
```

## Hook Behavior

### Pre-commit Hook

**Runs on**: Every `git commit` command

**Behavior**:
1. Executes `tools/pre-commit.local` wrapper
2. Pre-commit runs with auto-fix enabled
3. Auto-fixes issues where possible (trailing whitespace, YAML formatting, etc.)
4. Validates all hooks in `.pre-commit-config.yaml`

**Outcomes**:
- ✅ **All checks pass**: Commit allowed
- ❌ **Any check fails**: Commit blocked, show fix instructions

**pre-commit.ci policy**:
- Server-side auto-fix commits are disabled (`ci.autofix_prs: false`).
- Ensure the GitHub app setting "Auto-fix PRs" stays off to prevent bot commits.

**Bypass**: `git commit --no-verify ...` (not recommended)

**Example**:
```powershell
# 1. Make changes
vim my-file.yaml

# 2. Stage changes
git add .

# 3. Commit (hook runs and auto-fixes issues)
git commit -m "feat: add new feature"
# → Pre-commit runs
# → Auto-fixes issues (e.g., trailing whitespace)
# → Issue: Auto-fix not staged yet
# → Commit blocked

# 4. Review and stage fixes
git diff  # See what was auto-fixed
git add .  # Stage fixes

# 5. Commit again
git commit -m "feat: add new feature"
# → Commit succeeds ✅
```

### Pre-push Hook

**Runs on**: Every `git push` command

**Behavior**:
1. Requires `pre-commit` installed; push blocked if missing
2. Executes `tools/pre-commit.local` wrapper
3. Pre-commit runs WITHOUT auto-fix (validation only)
4. Checks all hooks in `.pre-commit-config.yaml`

**Outcomes**:
- ✅ **All checks pass**: Push allowed
- ❌ **Any check fails**: Push blocked, show fix instructions

**Bypass**: `git push --no-verify ...` (not recommended)

**Example**:
```powershell
# 1. Make changes
vim my-file.yaml

# 2. Stage and commit (auto-fix runs)
git add .
git commit -m "feat: add new feature"

# 3. Push (pre-push validates)
git push origin my-branch
# → Pre-push runs
# → Finds issues (e.g., trailing whitespace not fixed)
# → Push blocked

# 4. Run pre-commit manually to fix
pre-commit run --all-files --verbose

# 5. Stage and commit fixes
git add .
git commit -m "fix: apply pre-commit auto-fixes"

# 6. Push again
git push origin my-branch
# → Pre-push validates
# → All checks pass ✅
```

## Why Two Hooks?

### Pre-commit: Fix Issues Early

- **Purpose**: Clean up code while you're working
- **Auto-fix**: Yes - removes friction
- **Outcome**: Clean history, no messy fixes later
- **Developer Experience**: High productivity

### Pre-push: Last Line of Defense

- **Purpose**: Catch issues before they reach remote
- **Auto-fix**: No - validation only
- **Outcome**: Prevent pushing code that will fail in CI
- **Team Impact**: High code quality

### Both Together: Multi-Layer Protection

1. **Fix immediately** (pre-commit)
2. **Validate before sharing** (pre-push)
3. **CI validates deployment** (remote)

## Troubleshooting

### Issue: "Commit blocked by pre-commit"

**Cause**: Pre-commit found issues that couldn't be auto-fixed.

**Fix**:
```powershell
# See what failed
pre-commit run --all-files --verbose

# Fix issues manually
code <files-with-issues>  # or vim, nano, etc.

# Stage and commit again
git add .
git commit -m "fix: address pre-commit issues"
```

### Issue: "Push blocked by pre-push"

**Cause**: Pre-push found issues (auto-fix not run).

**Fix**:
```powershell
# Run pre-commit with auto-fix
pre-commit run --all-files --verbose

# Review fixes
git diff

# Stage and commit fixes
git add .
git commit -m "fix: apply pre-commit auto-fixes"

# Push again
git push origin my-branch
```

### Issue: Hook doesn't run

**Cause**: Hooks not executable or not in correct location.

**Fix**:
```powershell
# Check hook exists
Get-ChildItem .git/hooks/pre-commit
Get-ChildItem .git/hooks/pre-push

# Re-run setup
pwsh -File scripts/setup-githooks.ps1
```

### Issue: Need to bypass hooks

**Use case**: Emergency fixes, debugging, or quick experiments (not recommended)**

```powershell
# Bypass pre-commit
git commit --no-verify -m "fix: emergency"

# Bypass pre-push
git push --no-verify origin my-branch

# Note: This bypasses ALL hooks, including security checks
# Only use when absolutely necessary
```

## Advanced Configuration

### Configure Custom Hooks Path

```powershell
# Set custom hooks directory
git config core.hooksPath githooks

# Reset to default
git config --unset core.hooksPath
```

### Temporarily Disable Hooks

```powershell
# Disable pre-commit for one commit
git commit --no-verify -m "commit message"

# Disable pre-push for one push
git push --no-verify origin branch-name

# Note: This is not recommended for normal development
```

## Environment Detection

Both hooks support environment detection:

| Environment | Detection | Behavior |
|------------|------------|----------|
| Local Developer | `$GITHUB_ACTIONS` not set | Standard auto-fix behavior |
| GitHub Actions | `$GITHUB_ACTIONS` set | Pre-commit runs, auto-fix enabled if configured |
| Other CI | CI-specific env vars | Pre-commit runs, auto-fix controlled by config |

## Related Files

- `.pre-commit-config.yaml` - Hook definitions
- `tools/pre-commit.local` - Pre-commit wrapper script
- `.github/PRE_COMMIT_WORKFLOW.md` - Complete workflow documentation

## See Also

- [Pre-commit Documentation](https://pre-commit.com)
- [Git Hooks Documentation](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks)
- [Pre-commit Workflow](../.github/PRE_COMMIT_WORKFLOW.md)

## License

These hooks are part of the yt-summarizer project and follow the same license.
