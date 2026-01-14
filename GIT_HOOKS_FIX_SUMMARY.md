# Git Hooks Windows Fix - Summary

## Problem
The `.git/hooks/` directory contained bash scripts that tried to run `/bin/bash`, which doesn't exist on Windows. When trying to commit or push, Git would fail with:
```
An unexpected error has occurred: ExecutableNotFoundError: Executable `/bin/bash` not found
Check log at C:\Users\ashle\.cache\pre-commit\pre-commit.log
```

This blocked all commits and pushes on Windows unless users used `--no-verify` to bypass hooks.

## Solution
Converted git hooks from Bash to PowerShell for cross-platform compatibility:

### Files Changed

1. **githooks/pre-commit.ps1** - New PowerShell version of pre-commit hook
   - Runs `pre-commit` with auto-fix
   - Blocks commits if checks fail
   - Cross-platform (works with pwsh on Linux/macOS)

2. **githooks/pre-push.ps1** - New PowerShell version of pre-push hook
   - Runs `pre-commit` validation only (no auto-fix)
   - Blocks pushes if checks would fail
   - Cross-platform (works with pwsh on Linux/macOS)

3. **githooks/pre-commit.bat** - Windows batch wrapper
   - Calls `pre-commit.ps1` on Windows
   - Required because Git for Windows doesn't recognize `.ps1` extension

4. **githooks/pre-push.bat** - Windows batch wrapper
   - Calls `pre-push.ps1` on Windows
   - Required because Git for Windows doesn't recognize `.ps1` extension

5. **scripts/setup-githooks.ps1** - Updated setup script
   - Detects OS (Windows vs Unix-like)
   - Installs appropriate files based on OS
   - Copies `.bat` wrappers on Windows
   - Copies `.ps1` files on Unix-like systems with proper line endings and executable permissions

6. **githooks/README.md** - Updated documentation
   - Added Windows compatibility section
   - Updated all examples from Bash to PowerShell
   - Documented `core.hooksPath` configuration requirement for Windows

7. **.gitattributes** - Updated line ending configuration
   - Added `*.ps1 text eol=lf` for cross-platform compatibility

## Configuration Required

Windows users must configure Git to use the `githooks` directory:

```powershell
git config core.hooksPath githooks
```

This tells Git to:
- On Windows: Use `.bat` wrappers that call `.ps1` scripts
- On Linux/macOS: Use `.ps1` files directly (with `#!/usr/bin/env pwsh` shebang)

## How It Works

### Windows
1. Git reads `githooks/pre-commit` (actually `pre-commit.bat`)
2. Batch wrapper executes: `powershell -ExecutionPolicy Bypass -File "pre-commit.ps1"`
3. PowerShell script runs `pre-commit` with auto-fix
4. On success/failure, PowerShell returns appropriate exit code
5. Git allows/blocks operation based on exit code

### Linux/macOS
1. Git reads `githooks/pre-commit` (file without extension)
2. Git recognizes `#!/usr/bin/env pwsh` shebang
3. Git executes script with `pwsh` interpreter
4. PowerShell script runs `pre-commit` with auto-fix
5. On success/failure, PowerShell returns appropriate exit code
6. Git allows/blocks operation based on exit code

## Behavior

### Pre-commit Hook
- **Runs on**: Every `git commit` command
- **Auto-fix**: Yes - fixes issues where possible
- **Blocks**: Bad commits
- **Bypass**: `git commit --no-verify`

### Pre-push Hook
- **Runs on**: Every `git push` command
- **Auto-fix**: No - validation only
- **Blocks**: Bad pushes
- **Bypass**: `git push --no-verify`

## Benefits

1. **Cross-platform**: Works on Windows, macOS, and Linux
2. **Consistent**: Same behavior across all platforms
3. **Auto-fix on commit**: Reduces developer friction
4. **Validation on push**: Catches issues before remote CI
5. **No bash dependency**: Works even without WSL or Git Bash

## Testing

Tested on:
- Windows 11 with PowerShell 5.1
- Windows 11 with PowerShell 7 (pwsh)
- Git for Windows (latest)
- Git Bash on Windows (latest)

Verified:
- Commits work correctly with auto-fix
- Pushes work correctly with validation
- Hooks run on every operation
- Exit codes properly control Git behavior
