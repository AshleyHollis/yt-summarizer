@echo off
setlocal enabledelayedexpansion

REM Find the real aspire.exe on PATH (skip .cmd/.bat wrappers)
set "REAL_ASPIRE="
for /f "delims=" %%I in ('where aspire 2^>nul') do (
  set "CANDIDATE=%%I"
  if /I "!CANDIDATE:~-4!"==".exe" (
    set "REAL_ASPIRE=!CANDIDATE!"
    goto :found
  )
)

:found
if not defined REAL_ASPIRE (
  echo ERROR: Could not locate the real 'aspire.exe' executable on PATH. 1>&2
  exit /b 1
)

REM Workspace root is tools\..
set "WORKSPACE=%~dp0.."
if "%WORKSPACE:~-1%"=="\" set "WORKSPACE=%WORKSPACE:~0,-1%"

REM Log the launch attempt
set "LOG=%WORKSPACE%\aspire.log"
echo [%date% %time%] Launching: "!REAL_ASPIRE!" %* > "%LOG%"

REM AppHost directory (where appsettings.Development.json lives)
set "APPHOST_DIR=%WORKSPACE%\services\aspire\AppHost"

REM Create a temp script that runs aspire directly (not via PATH)
set "TEMPSCRIPT=%TEMP%\run-aspire-%RANDOM%.cmd"
echo @echo off > "%TEMPSCRIPT%"
REM Change to AppHost directory so appsettings.Development.json is picked up
echo cd /d "%APPHOST_DIR%" >> "%TEMPSCRIPT%"
REM Set environment to Development to load appsettings.Development.json (with unsecured auth)
echo set "DOTNET_ENVIRONMENT=Development" >> "%TEMPSCRIPT%"
echo set "ASPNETCORE_ENVIRONMENT=Development" >> "%TEMPSCRIPT%"
REM Enable anonymous access to the Aspire dashboard (no login token required)
echo set "ASPIRE_DASHBOARD_UNSECURED_ALLOW_ANONYMOUS=true" >> "%TEMPSCRIPT%"
echo "!REAL_ASPIRE!" %* >> "%TEMPSCRIPT%"
REM Ensure the temporary script cleans itself up after execution
echo del "%%~f0" >> "%TEMPSCRIPT%"

REM Launch the temp script minimized
start "Aspire" /MIN "%TEMPSCRIPT%"
exit /b 0
