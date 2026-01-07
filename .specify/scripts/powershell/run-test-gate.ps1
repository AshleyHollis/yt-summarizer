# Test Gate Script - MUST PASS before marking any task [X]
# This script runs all automated tests and outputs a pass/fail summary
# Usage: .\.specify\scripts\powershell\run-test-gate.ps1
#
# Options:
#   -SkipE2E     Skip E2E tests (faster, but incomplete verification)
#   -Json        Output results as JSON
#
# Output:
#   - Console summary with pass/fail
#   - test-gate-failures.log (if any failures occur)

param(
    [switch]$SkipE2E,
    [switch]$Json
)

$ErrorActionPreference = "Continue"
$script:allPassed = $true
$script:results = @()
$script:failures = @()

$repoRoot = git rev-parse --show-toplevel 2>$null
if (-not $repoRoot) {
    $repoRoot = $PSScriptRoot | Split-Path | Split-Path | Split-Path
}
$failureLogPath = Join-Path $repoRoot "test-gate-failures.log"

# Clear previous failure log
if (Test-Path $failureLogPath) {
    Remove-Item $failureLogPath -Force
}

function Add-TestResult {
    param(
        [string]$Suite,
        [int]$Passed,
        [int]$Failed,
        [int]$Skipped,
        [string]$Status,
        [string]$FailureOutput
    )
    
    $script:results += [PSCustomObject]@{
        Suite = $Suite
        Passed = $Passed
        Failed = $Failed
        Skipped = $Skipped
        Status = $Status
    }
    
    if ($Failed -gt 0) {
        $script:allPassed = $false
        $script:failures += @{
            Suite = $Suite
            Output = $FailureOutput
        }
    }
}

function Write-FailureLog {
    if ($script:failures.Count -gt 0) {
        $logContent = @()
        $logContent += "=" * 80
        $logContent += "TEST GATE FAILURE LOG"
        $logContent += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        $logContent += "=" * 80
        $logContent += ""
        
        foreach ($failure in $script:failures) {
            $logContent += "-" * 80
            $logContent += "SUITE: $($failure.Suite)"
            $logContent += "-" * 80
            $logContent += $failure.Output
            $logContent += ""
        }
        
        $logContent | Out-File -FilePath $failureLogPath -Encoding UTF8
        Write-Host "  Failure details saved to: $failureLogPath" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  TEST GATE - Pre-Completion Verification" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# 1. API Tests
Write-Host "[1/5] Running API Tests..." -ForegroundColor Yellow
Push-Location "$repoRoot\services\api"
$apiOutput = & "$repoRoot\.venv\Scripts\python.exe" -m pytest tests/ -v -m "not integration" 2>&1 | Out-String
$apiMatch = [regex]::Match($apiOutput, "(\d+) passed")
$apiPassed = if ($apiMatch.Success) { [int]$apiMatch.Groups[1].Value } else { 0 }
$apiFailMatch = [regex]::Match($apiOutput, "(\d+) failed")
$apiFailed = if ($apiFailMatch.Success) { [int]$apiFailMatch.Groups[1].Value } else { 0 }
Pop-Location

if ($apiFailed -eq 0 -and $apiPassed -gt 0) {
    Write-Host "  [PASS] API Tests: $apiPassed passed" -ForegroundColor Green
    Add-TestResult -Suite "API" -Passed $apiPassed -Failed 0 -Skipped 0 -Status "PASS" -FailureOutput ""
} else {
    Write-Host "  [FAIL] API Tests: $apiFailed failed, $apiPassed passed" -ForegroundColor Red
    Add-TestResult -Suite "API" -Passed $apiPassed -Failed $apiFailed -Skipped 0 -Status "FAIL" -FailureOutput $apiOutput
}

# 2. Worker Tests
Write-Host "[2/5] Running Worker Tests..." -ForegroundColor Yellow
Push-Location "$repoRoot\services\workers"
$workerOutput = & "$repoRoot\.venv\Scripts\python.exe" -m pytest tests/ -v 2>&1 | Out-String
$workerMatch = [regex]::Match($workerOutput, "(\d+) passed")
$workerPassed = if ($workerMatch.Success) { [int]$workerMatch.Groups[1].Value } else { 0 }
$workerFailMatch = [regex]::Match($workerOutput, "(\d+) failed")
$workerFailed = if ($workerFailMatch.Success) { [int]$workerFailMatch.Groups[1].Value } else { 0 }
Pop-Location

if ($workerFailed -eq 0 -and $workerPassed -gt 0) {
    Write-Host "  [PASS] Worker Tests: $workerPassed passed" -ForegroundColor Green
    Add-TestResult -Suite "Workers" -Passed $workerPassed -Failed 0 -Skipped 0 -Status "PASS" -FailureOutput ""
} else {
    Write-Host "  [FAIL] Worker Tests: $workerFailed failed, $workerPassed passed" -ForegroundColor Red
    Add-TestResult -Suite "Workers" -Passed $workerPassed -Failed $workerFailed -Skipped 0 -Status "FAIL" -FailureOutput $workerOutput
}

# 3. Shared Package Tests
Write-Host "[3/5] Running Shared Package Tests..." -ForegroundColor Yellow
Push-Location "$repoRoot\services\shared"
$sharedOutput = & "$repoRoot\.venv\Scripts\python.exe" -m pytest tests/ -v 2>&1 | Out-String
$sharedMatch = [regex]::Match($sharedOutput, "(\d+) passed")
$sharedPassed = if ($sharedMatch.Success) { [int]$sharedMatch.Groups[1].Value } else { 0 }
$sharedFailMatch = [regex]::Match($sharedOutput, "(\d+) failed")
$sharedFailed = if ($sharedFailMatch.Success) { [int]$sharedFailMatch.Groups[1].Value } else { 0 }
Pop-Location

if ($sharedFailed -eq 0 -and $sharedPassed -gt 0) {
    Write-Host "  [PASS] Shared Tests: $sharedPassed passed" -ForegroundColor Green
    Add-TestResult -Suite "Shared" -Passed $sharedPassed -Failed 0 -Skipped 0 -Status "PASS" -FailureOutput ""
} else {
    Write-Host "  [FAIL] Shared Tests: $sharedFailed failed, $sharedPassed passed" -ForegroundColor Red
    Add-TestResult -Suite "Shared" -Passed $sharedPassed -Failed $sharedFailed -Skipped 0 -Status "FAIL" -FailureOutput $sharedOutput
}

# 4. Frontend Tests
Write-Host "[4/5] Running Frontend Tests..." -ForegroundColor Yellow
Push-Location "$repoRoot\apps\web"
$frontendOutput = npm run test:run 2>&1 | Out-String
# Vitest outputs "Test Files  X passed" then "Tests  Y passed" - we want Y
# Match all "N passed" patterns and take the last one (which is total tests)
$allPassedMatches = [regex]::Matches($frontendOutput, "(\d+) passed")
$frontendPassed = if ($allPassedMatches.Count -ge 2) { 
    [int]$allPassedMatches[$allPassedMatches.Count - 1].Groups[1].Value 
} elseif ($allPassedMatches.Count -eq 1) {
    [int]$allPassedMatches[0].Groups[1].Value
} else { 0 }
$frontendFailMatch = [regex]::Match($frontendOutput, "(\d+) failed")
$frontendFailed = if ($frontendFailMatch.Success) { [int]$frontendFailMatch.Groups[1].Value } else { 0 }
Pop-Location

if ($frontendFailed -eq 0 -and $frontendPassed -gt 0) {
    Write-Host "  [PASS] Frontend Tests: $frontendPassed passed" -ForegroundColor Green
    Add-TestResult -Suite "Frontend" -Passed $frontendPassed -Failed 0 -Skipped 0 -Status "PASS" -FailureOutput ""
} else {
    Write-Host "  [FAIL] Frontend Tests: $frontendFailed failed, $frontendPassed passed" -ForegroundColor Red
    Add-TestResult -Suite "Frontend" -Passed $frontendPassed -Failed $frontendFailed -Skipped 0 -Status "FAIL" -FailureOutput $frontendOutput
}

# 5. E2E Tests (requires Aspire running)
if ($SkipE2E -eq $false) {
    Write-Host "[5/5] Running E2E Tests..." -ForegroundColor Yellow
    
    # Check if Aspire is running by testing the API endpoint
    $aspireRunning = $false
    try {
        $null = Invoke-RestMethod -Uri "http://localhost:8000/health" -TimeoutSec 5 -ErrorAction Stop
        $aspireRunning = $true
    } catch {
        $aspireRunning = $false
    }
    
    if ($aspireRunning -eq $false) {
        Write-Host "  [WARN] Aspire not running - starting it..." -ForegroundColor Yellow
        Push-Location "$repoRoot\services\aspire\AppHost"
        Start-Process -FilePath "dotnet" -ArgumentList "run" -WindowStyle Hidden
        Pop-Location
        Write-Host "  Waiting 45 seconds for services to start..." -ForegroundColor Yellow
        Start-Sleep -Seconds 45
    }
    
    Push-Location "$repoRoot\apps\web"
    $env:USE_EXTERNAL_SERVER = "true"
    $e2eOutput = npx playwright test 2>&1 | Out-String
    $e2eMatch = [regex]::Match($e2eOutput, "(\d+) passed")
    $e2ePassed = if ($e2eMatch.Success) { [int]$e2eMatch.Groups[1].Value } else { 0 }
    $e2eFailMatch = [regex]::Match($e2eOutput, "(\d+) failed")
    $e2eFailed = if ($e2eFailMatch.Success) { [int]$e2eFailMatch.Groups[1].Value } else { 0 }
    $e2eSkipMatch = [regex]::Match($e2eOutput, "(\d+) skipped")
    $e2eSkipped = if ($e2eSkipMatch.Success) { [int]$e2eSkipMatch.Groups[1].Value } else { 0 }
    Pop-Location
    
    if ($e2eFailed -eq 0 -and $e2ePassed -gt 0) {
        Write-Host "  [PASS] E2E Tests: $e2ePassed passed, $e2eSkipped skipped" -ForegroundColor Green
        Add-TestResult -Suite "E2E" -Passed $e2ePassed -Failed 0 -Skipped $e2eSkipped -Status "PASS" -FailureOutput ""
    } else {
        Write-Host "  [FAIL] E2E Tests: $e2eFailed failed, $e2ePassed passed" -ForegroundColor Red
        Add-TestResult -Suite "E2E" -Passed $e2ePassed -Failed $e2eFailed -Skipped $e2eSkipped -Status "FAIL" -FailureOutput $e2eOutput
    }
} else {
    Write-Host "[5/5] E2E Tests: SKIPPED (remove -SkipE2E to run)" -ForegroundColor Yellow
    Add-TestResult -Suite "E2E" -Passed 0 -Failed 0 -Skipped 0 -Status "SKIPPED" -FailureOutput ""
}

# Summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  TEST GATE SUMMARY" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$totalPassed = 0
$totalFailed = 0
foreach ($result in $script:results) {
    $totalPassed += $result.Passed
    $totalFailed += $result.Failed
}

foreach ($result in $script:results) {
    $color = switch ($result.Status) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        "SKIPPED" { "Yellow" }
    }
    $line = "  {0,-12} {1,4} passed  {2,4} failed  [{3}]" -f $result.Suite, $result.Passed, $result.Failed, $result.Status
    Write-Host $line -ForegroundColor $color
}

Write-Host ""
Write-Host "  TOTAL: $totalPassed passed, $totalFailed failed" -ForegroundColor White

# Write failure log if any failures
Write-FailureLog

if ($script:allPassed) {
    Write-Host ""
    Write-Host "  [PASS] TEST GATE: PASSED - Safe to mark task [X]" -ForegroundColor Green
    $exitCode = 0
} else {
    Write-Host ""
    Write-Host "  [FAIL] TEST GATE: FAILED - DO NOT mark task complete" -ForegroundColor Red
    Write-Host "  Review failures in: $failureLogPath" -ForegroundColor Yellow
    $exitCode = 1
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

if ($Json) {
    $jsonOutput = @{
        passed = $script:allPassed
        total_passed = $totalPassed
        total_failed = $totalFailed
        failure_log = if ($script:failures.Count -gt 0) { $failureLogPath } else { $null }
        suites = $script:results | ForEach-Object {
            @{
                suite = $_.Suite
                passed = $_.Passed
                failed = $_.Failed
                skipped = $_.Skipped
                status = $_.Status
            }
        }
    } | ConvertTo-Json -Depth 3
    Write-Host $jsonOutput
}

exit $exitCode
