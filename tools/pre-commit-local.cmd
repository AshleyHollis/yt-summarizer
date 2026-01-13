@echo off
REM Pre-commit runner for yt-summarizer
REM Runs pre-commit locally with auto-fix before pushing to remote
REM This wrapper finds the repository root dynamically by locating .git directory

setlocal enabledelayedexpansion

set SCRIPT_DIR=%~dp0
set REPO_ROOT=

REM Find .git directory by walking up from current script location
cd /d "%SCRIPT_DIR%"
:find_git
if exist ".git" (
    pushd "%SCRIPT_DIR%"
    set "_GIT_ROOT=%CD%"
    popd
    set "REPO_ROOT=%_GIT_ROOT%"
    goto :found_repo
)

REM Walk up one directory level to check parent
cd /d "%SCRIPT_DIR%\.."
if exist ".git" (
    pushd "%SCRIPT_DIR%\.."
    set "_GIT_ROOT=%CD%"
    popd
    set "REPO_ROOT=%_GIT_ROOT%"
    goto :found_repo
)

REM Check if we're already at root
if "%REPO_ROOT%"=="" (
    echo ERROR: Could not find .git directory. Are you in a git repository?
    exit /b 1
)

:found_repo
set PRE_COMMIT_CONFIG=%REPO_ROOT%\.pre-commit-config.yaml

if not exist "%PRE_COMMIT_CONFIG%" (
    echo Warning: No .pre-commit-config.yaml found. Using default pre-commit hooks.
    set PRE_COMMIT_ARGS=run
) else (
    set PRE_COMMIT_ARGS=run --config %PRE_COMMIT_CONFIG% --verbose
)

echo.
echo ========================================
echo   Pre-commit Local Runner
echo ========================================
echo.
echo Repository root: %REPO_ROOT%
echo Pre-commit config: %PRE_COMMIT_CONFIG%
echo.
echo Running pre-commit with auto-fix...
echo.

where pre-commit >nul 2>&1
if errorlevel neq 0 (
    echo ERROR: Pre-commit not found. Please install it:
    echo   pip install pre-commit
    exit /b 1
)

cd /d "%REPO_ROOT%"
pre-commit %PRE_COMMIT_ARGS%

if errorlevel neq 0 (
    echo.
    echo ========================================
    echo   PRE-COMMIT FAILED
    echo ========================================
    echo.
    echo Pre-commit found issues that were auto-fixed.
    echo.
    echo Please review the changes above.
    echo.
    echo If issues persist:
    echo   1. Run: tools\pre-commit-local.cmd
    echo   2. Review and adjust: .pre-commit-config.yaml
    echo.
    echo To skip pre-commit temporarily:
    echo      git commit ^--no-verify
    echo.
    echo To run pre-commit manually with auto-fix:
    echo      pre-commit run --all-files --verbose
    echo.
    exit /b %errorlevel%
) else (
    echo.
    echo ========================================
    echo   PRE-COMMIT PASSED
    echo ========================================
    echo.
    echo All checks passed!
    echo.
    echo Your files are ready to commit:
    echo   git commit -m "your message"
    echo   git push
    echo.
)

endlocal
