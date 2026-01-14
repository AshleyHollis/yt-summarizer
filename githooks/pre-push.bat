@echo off
REM Pre-push hook wrapper for Windows
REM Calls PowerShell script in same directory

cd /d "%~dp0"
powershell -ExecutionPolicy Bypass -File "pre-push.ps1" %*
