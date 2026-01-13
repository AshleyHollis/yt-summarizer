@echo off
REM Pre-commit wrapper script for yt-summarizer
REM Runs pre-commit hooks locally with auto-fix before pushing
REM Avoids conflicts where remote pre-commit and local edits don't align

setlocal

REM Configuration
set REPO_ROOT=%~dp0
set PRE_COMMIT_CONFIG=%REPO_ROOT%\.pre-commit-config.yaml

REM Check if pre-commit is available
where pre-commit >nul 2>&1
if errorlevel neq 0 (
    echo Pre-commit not found. Please install it first:
    echo pip install pre-commit
    exit /b 1
)

echo Running pre-commit checks with auto-fix...
echo.

REM Run pre-commit with auto-fix on all files
cd /d "%REPO_ROOT%"
pre-commit run --all-files --verbose

if errorlevel neq 0 (
    echo.
    echo Pre-commit found issues that were autofixed.
    echo Please review the changes and run again.
    echo.
    echo To skip pre-commit temporarily, use: git commit --no-verify
    echo.
    echo To permanently disable specific hooks, edit: .pre-commit-config.yaml
    echo.
    exit /b %errorlevel%
) else (
    echo.
    echo All pre-commit checks passed!
    echo.
    echo Ready to commit and push.
    echo.
    exit /b 0
)
