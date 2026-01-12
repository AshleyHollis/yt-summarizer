# Pre-commit CI Troubleshooting Guide

## Problem: Push Blocked After pre-commit.ci Auto-Fixes

When you push to GitHub, pre-commit.ci may detect additional issues and automatically commit fixes to your branch. This causes Git to block subsequent pushes:

```
! [rejected] feat/your-branch -> feat/your-branch (fetch first)
hint: Updates were rejected because the remote contains work that you do
hint: not have locally. This is usually caused by another repository pushing
hint: to the same ref. You may want to first integrate the remote changes
hint: (e.g., 'git pull ...') before pushing again.
```

## Solutions

### Option 1: Quick Rebase (Recommended)

Pull and rebase the pre-commit.ci fixes on top of your commits:

```powershell
git pull --rebase
git push
```

If conflicts occur:
```powershell
# Resolve conflicts in your editor
git add .
git rebase --continue
git push
```

### Option 2: Simple Merge

Easier but creates a merge commit:

```powershell
git pull --no-rebase
git push
```

### Option 3: Use Helper Script

```powershell
# Rebase approach (default)
.\scripts\pull-pre-commit-fixes.ps1

# Merge approach
.\scripts\pull-pre-commit-fixes.ps1 -Merge

# See what would happen (dry run)
.\scripts\pull-pre-commit-fixes.ps1 -DryRun
```

### Option 4: Prevent the Issue

Run pre-commit locally before pushing to minimize CI fixes:

```powershell
# Run on all staged files
python -m pre_commit run --all-files

# Run on specific files
python -m pre_commit run --files .github/workflows/infra.yml
```

## Configuration Options

### Disable Auto-Fixes in CI

If you prefer to handle all fixes locally, add to `.pre-commit-config.yaml`:

```yaml
ci:
  autofix_prs: false  # Don't auto-create PRs with fixes
```

### Skip Specific Hooks in CI

For hooks that should only run locally:

```yaml
ci:
  skip:
    - trailing-whitespace
    - end-of-file-fixer
```

## Workflow Best Practices

### Before Pushing

```powershell
# 1. Check status
git status

# 2. Stage your changes
git add .

# 3. Run pre-commit on all files (catches issues before CI)
python -m pre_commit run --all-files

# 4. Commit
git commit -m "your message"

# 5. Push
git push
```

### After Pre-commit CI Runs

```powershell
# 1. Pull the auto-fixes
.\scripts\pull-pre-commit-fixes.ps1

# 2. Review what was changed
git diff HEAD~1

# 3. Push again
git push
```

## Understanding What Happened

### The Process:

1. **You commit locally** → pre-commit hooks run on staged files
2. **You push to GitHub** → pre-commit.ci GitHub app runs on ALL files
3. **pre-commit.ci finds issues** → Auto-applies fixes and commits them
4. **Remote changes your branch** → Your local work is now behind
5. **Your push is blocked** → Git prevents overwriting the remote fixes

### Why This Happens:

- **Local hooks** run only on files you changed
- **CI hooks** run on the entire codebase and may find unrelated issues
- **Different environments** (local vs CI) can detect different issues

## Common Issues

### "Rebase Conflicts"

When rebase encounters conflicts:

```powershell
# Conflict detected
git status  # Shows conflicted files

# Edit conflicted files (look for <<<<<<<, =======, >>>>>>> markers)

# Stage resolved files
git add <resolved-files>

# Continue rebase
git rebase --continue

# Push
git push
```

### "Merge Conflicts"

When merge encounters conflicts:

```powershell
# Conflict detected
git mergetool  # Opens diff tool, or edit manually

# Stage resolved files
git add <resolved-files>

# Complete merge
git commit  # Opens editor for merge message

# Push
git push
```

## When Pre-commit CI Fixes vs Local Hooks

### Hook Auto-Fixing Behavior:

| Hook | Auto-Fixes? | Changes Files? |
|------|-------------|----------------|
| `check-yaml` | No | No (fails only) |
| `check-json` | No | No (fails only) |
| `end-of-file-fixer` | ✅ Yes | ✅ Yes |
| `trailing-whitespace` | ✅ Yes | ✅ Yes |
| `actionlint` | No | No (fails only) |
| `yamllint` | No | No (fails only) |

**Key Insight:** Only `end-of-file-fixer` and `trailing-whitespace` automatically modify files. Since these are rare issues, running pre-commit locally should prevent most CI auto-fixes.

## Additional Resources

- [pre-commit.ci Documentation](https://pre-commit.ci/)
- [Pre-commit Framework](https://pre-commit.com/)
- [Git Rebase vs Merge](https://www.atlassian.com/git/tutorials/merging-vs-rebasing)
