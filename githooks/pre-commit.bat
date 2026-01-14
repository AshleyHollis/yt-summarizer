@echo off
REM Pre-commit hook wrapper for Windows
REM Calls PowerShell script in same directory

cd /d "%~dp0"
powershell -ExecutionPolicy Bypass -File "pre-commit.ps1" %*
