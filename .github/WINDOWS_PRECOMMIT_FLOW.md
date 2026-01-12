# Windows Pre-commit Workflow Guide

## Summary

**You're absolutely right!** Running pre-commit locally before pushing is the best approach because:

1. **Same checks, same config** - pre-commit.ci uses the exact same `.pre-commit-config.yaml`
2. **No remote conflicts** - If you fix locally, pre-commit.ci won't need to make changes
3. **Instant feedback** - No waiting for CI runs to find issues
4. **Better DX** - Fix issues in your editor with immediate feedback

## The Problem Solved

On Windows, pre-commit hooks face two challenges:
1. **Line ending issues** - Git autocrlf defaults to CRLF, but pre-commit wants LF
2. **Encoding issues** - yamllint can't read Windows-cp1252 encoded files

Both are now fixed in this repository.

## Solution Implemented

### 1. Added `.gitattributes` ✅
Enforces Unix (LF) line endings for all text files:
```properties
* text=auto eol=lf  # All text files must use LF line endings
```

**Result**: No more "wrong new line character" errors from yamllint!

### 2. Created Windows-Friendly Scripts ✅

#### `scripts/run-precommit.ps1`
Wrapper script that handles UTF-8 encoding:
```powershell
# Run on all files
.\scripts\run-precommit.ps1

# Run on specific files
.\scripts\run-precommit.ps1 -Files .github/workflows/ci.yml

# Run as git hook (automatic on commit)
.\scripts\run-precommit.ps1 -HookStage
```

#### `scripts/pull-precommit-fixes.ps1`
Helper for when pre-commit.ci auto-fixes (should rarely happen now):
```powershell
# Pull and rebase CI fixes
.\scripts\pull-precommit-fixes.ps1
```

### 3. Updated `.git/hooks/pre-commit` ✅
Hooks installed automatically detect UTF-8 encoding via:
```bash
# Hook source sets: set PYTHONUTF8=1
```

## Daily Workflow

### Before Committing (Recommended)

```powershell
# 1. Make your changes
git add .

# 2. Run pre-commit on all files (optional but recommended)
$env:PYTHONUTF8 = "1"
C:\Python314\python.exe -m pre_commit run --all-files

# OR use the wrapper
.\scripts\run-precommit.ps1

# 3. Hook will run automatically on commit
git commit -m "your message"

# 4. Push
git push
```

### Quick Commit (Hooks Auto-Run)

```powershell
git add .
git commit -m "your message"  # Pre-commit hooks run automatically
git push
```

The hook will:
- ✅ Check YAML syntax
- ✅ Check JSON syntax
- ✅ Remove trailing whitespace (auto-fixes)
- ✅ Ensure files end with newline (auto-fixes)
- ✅ Lint GitHub Actions workflows
- ✅ Lint YAML files

If a hook fails:
- ❌ Commit is blocked
- 🔍 You'll see the error details
- 🔧 Fix the issue and try again
- 🔄 Some hooks (whitespace, end-of-file) auto-fix

## What Gets Auto-Fixed

| Hook | Auto-Fixes? | Changes Files? |
|------|-------------|----------------|
| `check-yaml` | No | ❌ Blocks commit |
| `check-json` | No | ❌ Blocks commit |
| `end-of-file-fixer` | ✅ Yes | ✅ Auto-commits fix |
| `trailing-whitespace` | ✅ Yes | ✅ Auto-commits fix |
| `actionlint` | No | ❌ Blocks commit |
| `yamllint` | No | ❌ Blocks commit |

## Why pre-commit.ci Won't Block You Anymore

If you run pre-commit locally **before pushing**, pre-commit.ci will find **zero issues** requiring fixes because:

```
Local pre-commit  = CI pre-commit  (same config, same checks)
                    ↓
               Issues found locally
                    ↓
               You fix them
                    ↓
            Commit and push
                    ↓
                CI runs
                    ↓
           Finds zero issues ✅
                    ↓
           No auto-fixes needed ✅
                    ↓
            No conflicts! ✅
```

## Troubleshooting

### "command not found: pre-commit"

Use the Python module directly:
```powershell
C:\Python314\python.exe -m pre_commit <command>
```

### PowerShell script execution blocked

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### UTF-8 Encoding Issues

Always set these environment variables:
```powershell
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
```

Or use the wrapper:
```powershell
.\scripts\run-precommit.ps1
```

### Line Ending Issues After Clone

Normalize all files to LF:
```powershell
git add --renormalize .
git status  # Review changes
git commit -m "chore: normalize line endings"
```

## One-Time Setup (Already Done) ✅

1. ✅ `.gitattributes` created and committed
2. ✅ All files normalized to LF
3. ✅ Pre-commit hooks installed in `.git/hooks/`
4. ✅ Windows-friendly wrapper scripts created
5. ✅ Pre-commit config updated

**You're all set!** Just use the daily workflows above.

## Best Practices

### Before Pushing to Remote

```powershell
# Always run full check before pushing
$env:PYTHONUTF8 = "1"
C:\Python314\python.exe -m pre_commit run --all-files

# If passes, then push
git push
```

### For Large Changes

```powershell
# Run on specific changed files only
C:\Python314\python.exe -m pre_commit run --files \
  .github/workflows/ci.yml \
  .github/workflows/preview.yml
```

### Regular Maintenance

```powershell
# Update hooks to latest versions (monthly)
C:\Python314\python.exe -m pre_commit autoupdate
```

## Summary

**The key insight you had is correct:**
- Run checks locally → pre-commit.ci makes no changes → no conflicts
- Get instant feedback → faster iteration → better developer experience
- Same checks locally and in CI → no surprises

All the Windows-specific issues (line endings, encoding) are now handled automatically. You can commit and push with confidence! 🎉
