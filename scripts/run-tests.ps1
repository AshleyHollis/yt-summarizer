<#
.SYNOPSIS
    Unified test runner for the YT Summarizer project.

.DESCRIPTION
    Runs tests across all components: API, Workers, Shared, Frontend, and E2E.

    By default, runs ALL tests including E2E (requires Aspire running).
    Use -SkipE2E for faster development iteration.

.PARAMETER SkipE2E
    Skip E2E tests (faster, but incomplete verification)

.PARAMETER Component
    Run tests for a specific component only: 'api', 'workers', 'shared', 'web', 'e2e'
    Default: runs all components

.PARAMETER Json
    Output results as JSON

.EXAMPLE
    # Run ALL tests (default - includes E2E)
    .\scripts\run-tests.ps1

.EXAMPLE
    # Run all unit/integration tests, skip E2E (faster for development)
    .\scripts\run-tests.ps1 -SkipE2E

.EXAMPLE
    # Run only API tests
    .\scripts\run-tests.ps1 -Component api

.EXAMPLE
    # Run only E2E tests
    .\scripts\run-tests.ps1 -Component e2e
#>

param(
    [switch]$SkipE2E,
    [ValidateSet('all','detect','api','workers','shared','web','e2e')]
    [string]$Component = 'detect',
    [switch]$Json
)

$ErrorActionPreference = "Continue"
$script:allPassed = $true
$script:results = @()
$script:failures = @()

$repoRoot = git rev-parse --show-toplevel 2>$null
if (-not $repoRoot) {
    $repoRoot = Split-Path -Parent $PSScriptRoot
}

# Auto-detect changes when Component is 'detect'
if ($Component -eq 'detect') {
    try {
        # Use local git status to include untracked files (staged/unstaged)
        $statusOutput = & git status --porcelain 2>$null
        $changedFiles = @()
        if ($statusOutput -and $statusOutput -ne "") {
            $lines = if ($statusOutput -is [array]) { $statusOutput } else { $statusOutput -split "`n" }
            foreach ($line in $lines) {
                $line = $line.Trim()
                if ($line -ne "") {
                    $parts = $line -split '\s+'
                    $filePath = $parts[-1]
                    $changedFiles += $filePath
                }
            }
        }

        # Fallback to branch diff if no local changes detected (useful in CI)
        if ($changedFiles.Count -eq 0) {
            $diffOutput = & git diff --name-only origin/main...HEAD 2>$null
            if ($diffOutput -and $diffOutput -ne "") {
                $changedFiles = $diffOutput -split "`n"
            }
        }

        # Determine affected components (ignore docs/specs/markdown/.github and pipeline scripts)
        $affectedComponents = @()
        foreach ($file in $changedFiles) {
            if ($file -and ($file -notmatch '^docs/' -and $file -notmatch '^specs/' -and $file -notmatch '\.md$' -and $file -notmatch '^\.github/' -and $file -notmatch '^scripts/')) {
                if ($file -match '^services/api/') { if (-not ('api' -in $affectedComponents)) { $affectedComponents += 'api' } }
                elseif ($file -match '^services/workers/') { if (-not ('workers' -in $affectedComponents)) { $affectedComponents += 'workers' } }
                elseif ($file -match '^services/shared/') { if (-not ('shared' -in $affectedComponents)) { $affectedComponents += 'shared' } }
                elseif ($file -match '^apps/web/') { if (-not ('web' -in $affectedComponents)) { $affectedComponents += 'web' } }
                else { $affectedComponents = @('api','workers','shared','web'); break }
            }
        }

        if ($affectedComponents.Count -eq 0) {
            Write-Host "Only docs/specs/markdown/.github/scripts changes detected - skipping all tests" -ForegroundColor Yellow
            exit 0
        } else {
            $Component = $affectedComponents -join ','
            Write-Host "Detected changes in: $Component - running selective tests" -ForegroundColor Green
        }
    } catch {
        Write-Host "Could not detect changes (git error) - running full tests" -ForegroundColor Yellow
    }
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
        $logContent += "TEST FAILURE LOG"
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

function Get-PythonExe {
    $venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
    if (Test-Path $venvPython) {
        return $venvPython
    }
    return "python"
}

function Test-Api {
    Write-Host "[API] Running API Tests..." -ForegroundColor Yellow
    Push-Location "$repoRoot\services\api"
    $pythonExe = Get-PythonExe
    $output = & $pythonExe -m pytest tests/ -v 2>&1 | Out-String
    $passMatch = [regex]::Match($output, "(\d+) passed")
    $passed = if ($passMatch.Success) { [int]$passMatch.Groups[1].Value } else { 0 }
    $failMatch = [regex]::Match($output, "(\d+) failed")
    $failed = if ($failMatch.Success) { [int]$failMatch.Groups[1].Value } else { 0 }
    Pop-Location

    return [PSCustomObject]@{
        Suite = "API"
        Passed = $passed
        Failed = $failed
        Skipped = 0
        Status = if ($failed -eq 0 -and $passed -gt 0) { "PASS" } else { "FAIL" }
        FailureOutput = if ($failed -gt 0) { $output } else { "" }
    }
}

function Test-Workers {
    Write-Host "[WORKERS] Running Worker Tests..." -ForegroundColor Yellow
    Push-Location "$repoRoot\services\workers"
    $pythonExe = Get-PythonExe
    $output = & $pythonExe -m pytest tests/ -v 2>&1 | Out-String
    $passMatch = [regex]::Match($output, "(\d+) passed")
    $passed = if ($passMatch.Success) { [int]$passMatch.Groups[1].Value } else { 0 }
    $failMatch = [regex]::Match($output, "(\d+) failed")
    $failed = if ($failMatch.Success) { [int]$failMatch.Groups[1].Value } else { 0 }
    Pop-Location

    return [PSCustomObject]@{
        Suite = "Workers"
        Passed = $passed
        Failed = $failed
        Skipped = 0
        Status = if ($failed -eq 0 -and $passed -gt 0) { "PASS" } else { "FAIL" }
        FailureOutput = if ($failed -gt 0) { $output } else { "" }
    }
}

function Test-Shared {
    Write-Host "[SHARED] Running Shared Package Tests..." -ForegroundColor Yellow
    Push-Location "$repoRoot\services\shared"
    $pythonExe = Get-PythonExe
    $output = & $pythonExe -m pytest tests/ -v 2>&1 | Out-String
    $passMatch = [regex]::Match($output, "(\d+) passed")
    $passed = if ($passMatch.Success) { [int]$passMatch.Groups[1].Value } else { 0 }
    $failMatch = [regex]::Match($output, "(\d+) failed")
    $failed = if ($failMatch.Success) { [int]$failMatch.Groups[1].Value } else { 0 }
    Pop-Location

    return [PSCustomObject]@{
        Suite = "Shared"
        Passed = $passed
        Failed = $failed
        Skipped = 0
        Status = if ($failed -eq 0 -and $passed -gt 0) { "PASS" } else { "FAIL" }
        FailureOutput = if ($failed -gt 0) { $output } else { "" }
    }
}

function Test-Web {
    Write-Host "[WEB] Running Frontend Tests (Vitest)..." -ForegroundColor Yellow
    Push-Location "$repoRoot\apps\web"
    $output = npm run test:run 2>&1 | Out-String
    # Vitest outputs "Test Files  X passed" then "Tests  Y passed" - we want Y (total tests)
    $allPassedMatches = [regex]::Matches($output, "(\d+) passed")
    $passed = if ($allPassedMatches.Count -ge 2) {
        [int]$allPassedMatches[$allPassedMatches.Count - 1].Groups[1].Value
    } elseif ($allPassedMatches.Count -eq 1) {
        [int]$allPassedMatches[0].Groups[1].Value
    } else { 0 }
    $failMatch = [regex]::Match($output, "(\d+) failed")
    $failed = if ($failMatch.Success) { [int]$failMatch.Groups[1].Value } else { 0 }
    Pop-Location

    return [PSCustomObject]@{
        Suite = "Frontend"
        Passed = $passed
        Failed = $failed
        Skipped = 0
        Status = if ($failed -eq 0 -and $passed -gt 0) { "PASS" } else { "FAIL" }
        FailureOutput = if ($failed -gt 0) { $output } else { "" }
    }
}

function Test-E2E {
    $startTime = Get-Date
    Write-Host "[E2E] Running E2E Tests (Playwright)..." -ForegroundColor Yellow

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
        # Use the wrapper script if available
        $aspireCmd = Join-Path $repoRoot "tools\aspire.cmd"
        if (Test-Path $aspireCmd) {
            & $aspireCmd run
        } else {
            Push-Location "$repoRoot\services\aspire\AppHost"
            Start-Process -FilePath "dotnet" -ArgumentList "run" -WindowStyle Hidden
            Pop-Location
        }
        Write-Host "  Waiting 45 seconds for services to start..." -ForegroundColor Yellow
        Start-Sleep -Seconds 45
    }

    Push-Location "$repoRoot\apps\web"
    $env:USE_EXTERNAL_SERVER = "true"
    $output = npx playwright test 2>&1 | Out-String
    $passMatch = [regex]::Match($output, "(\d+) passed")
    $passed = if ($passMatch.Success) { [int]$passMatch.Groups[1].Value } else { 0 }
    $failMatch = [regex]::Match($output, "(\d+) failed")
    $failed = if ($failMatch.Success) { [int]$failMatch.Groups[1].Value } else { 0 }
    $skipMatch = [regex]::Match($output, "(\d+) skipped")
    $skipped = if ($skipMatch.Success) { [int]$skipMatch.Groups[1].Value } else { 0 }
    Pop-Location

    $duration = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)
    if ($failed -eq 0 -and $passed -gt 0) {
        Write-Host "  [PASS] E2E Tests: $passed passed, $skipped skipped in ${duration}s" -ForegroundColor Green
    } else {
        Write-Host "  [FAIL] E2E Tests: $failed failed, $passed passed in ${duration}s" -ForegroundColor Red
    }

    return [PSCustomObject]@{
        Suite = "E2E"
        Passed = $passed
        Failed = $failed
        Skipped = $skipped
        Status = if ($failed -eq 0 -and $passed -gt 0) { "PASS" } else { "FAIL" }
        FailureOutput = if ($failed -gt 0) { $output } else { "" }
        Duration = $duration
    }
}

# Main execution
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  YT SUMMARIZER TEST RUNNER" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$runE2E = ($SkipE2E -eq $false) -and ($Component -eq 'all' -or $Component -eq 'e2e')

switch ($Component) {
    'all' {
        # Run unit/integration tests in parallel
        Write-Host "Running unit/integration tests in parallel..." -ForegroundColor Yellow

        # Define script blocks for parallel execution
        $sharedScript = {
            param($repoRoot)
            $startTime = Get-Date
            Write-Host "[SHARED] Running Shared Package Tests..." -ForegroundColor Yellow
            Push-Location "$repoRoot\services\shared"
            $pythonExe = if (Test-Path "$repoRoot\.venv\Scripts\python.exe") { "$repoRoot\.venv\Scripts\python.exe" } else { "python" }
            $output = & $pythonExe -m pytest tests/ -v 2>&1 | Out-String
            $passMatch = [regex]::Match($output, "(\d+) passed")
            $passed = if ($passMatch.Success) { [int]$passMatch.Groups[1].Value } else { 0 }
            $failMatch = [regex]::Match($output, "(\d+) failed")
            $failed = if ($failMatch.Success) { [int]$failMatch.Groups[1].Value } else { 0 }
            Pop-Location

            $duration = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)
            if ($failed -eq 0 -and $passed -gt 0) {
                Write-Host "  [PASS] Shared Tests: $passed passed in ${duration}s" -ForegroundColor Green
            } else {
                Write-Host "  [FAIL] Shared Tests: $failed failed, $passed passed in ${duration}s" -ForegroundColor Red
            }

            return [PSCustomObject]@{
                Suite = "Shared"
                Passed = $passed
                Failed = $failed
                Skipped = 0
                Status = if ($failed -eq 0 -and $passed -gt 0) { "PASS" } else { "FAIL" }
                FailureOutput = if ($failed -gt 0) { $output } else { "" }
                Duration = $duration
            }
        }

        $workersScript = {
            param($repoRoot)
            $startTime = Get-Date
            Write-Host "[WORKERS] Running Worker Tests..." -ForegroundColor Yellow
            Push-Location "$repoRoot\services\workers"
            $pythonExe = if (Test-Path "$repoRoot\.venv\Scripts\python.exe") { "$repoRoot\.venv\Scripts\python.exe" } else { "python" }

            # Try to use pytest-xdist if available for parallel execution
            $xdistAvailable = $false
            try {
                & $pythonExe -c "import pytest_xdist" 2>$null
                $xdistAvailable = $true
            } catch {}

            if ($xdistAvailable) {
                Write-Host "  Using pytest-xdist for parallel test execution" -ForegroundColor Cyan
                $output = & $pythonExe -m pytest -n auto tests/ -v --tb=short 2>&1 | Out-String
            } else {
                Write-Host "  Installing pytest-xdist for parallel execution..." -ForegroundColor Yellow
                & $pythonExe -m pip install pytest-xdist --quiet 2>$null
                try {
                    & $pythonExe -c "import pytest_xdist" 2>$null
                    Write-Host "  Using pytest-xdist for parallel test execution" -ForegroundColor Cyan
                    $output = & $pythonExe -m pytest -n auto tests/ -v --tb=short 2>&1 | Out-String
                } catch {
                    Write-Host "  pytest-xdist installation failed, running sequentially" -ForegroundColor Yellow
                    $output = & $pythonExe -m pytest tests/ -v 2>&1 | Out-String
                }
            }

            $passMatch = [regex]::Match($output, "(\d+) passed")
            $passed = if ($passMatch.Success) { [int]$passMatch.Groups[1].Value } else { 0 }
            $failMatch = [regex]::Match($output, "(\d+) failed")
            $failed = if ($failMatch.Success) { [int]$failMatch.Groups[1].Value } else { 0 }
            Pop-Location

            $duration = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)
            if ($failed -eq 0 -and $passed -gt 0) {
                Write-Host "  [PASS] Worker Tests: $passed passed in ${duration}s" -ForegroundColor Green
            } else {
                Write-Host "  [FAIL] Worker Tests: $failed failed, $passed passed in ${duration}s" -ForegroundColor Red
            }

            return [PSCustomObject]@{
                Suite = "Workers"
                Passed = $passed
                Failed = $failed
                Skipped = 0
                Status = if ($failed -eq 0 -and $passed -gt 0) { "PASS" } else { "FAIL" }
                FailureOutput = if ($failed -gt 0) { $output } else { "" }
                Duration = $duration
            }
        }

        $apiScript = {
            param($repoRoot)
            $startTime = Get-Date
            Write-Host "[API] Running API Tests..." -ForegroundColor Yellow
            Push-Location "$repoRoot\services\api"
            $pythonExe = if (Test-Path "$repoRoot\.venv\Scripts\python.exe") { "$repoRoot\.venv\Scripts\python.exe" } else { "python" }

            # Try to use pytest-xdist if available for parallel execution
            $xdistAvailable = $false
            try {
                & $pythonExe -c "import pytest_xdist" 2>$null
                $xdistAvailable = $true
            } catch {}

            if ($xdistAvailable) {
                Write-Host "  Using pytest-xdist for parallel test execution" -ForegroundColor Cyan
                $output = & $pythonExe -m pytest -n auto tests/ -v --tb=short 2>&1 | Out-String
            } else {
                Write-Host "  Installing pytest-xdist for parallel execution..." -ForegroundColor Yellow
                & $pythonExe -m pip install pytest-xdist --quiet 2>$null
                try {
                    & $pythonExe -c "import pytest_xdist" 2>$null
                    Write-Host "  Using pytest-xdist for parallel test execution" -ForegroundColor Cyan
                    $output = & $pythonExe -m pytest -n auto tests/ -v --tb=short 2>&1 | Out-String
                } catch {
                    Write-Host "  pytest-xdist installation failed, running sequentially" -ForegroundColor Yellow
                    $output = & $pythonExe -m pytest tests/ -v 2>&1 | Out-String
                }
            }

            $passMatch = [regex]::Match($output, "(\d+) passed")
            $passed = if ($passMatch.Success) { [int]$passMatch.Groups[1].Value } else { 0 }
            $failMatch = [regex]::Match($output, "(\d+) failed")
            $failed = if ($failMatch.Success) { [int]$failMatch.Groups[1].Value } else { 0 }
            Pop-Location

            $duration = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)
            if ($failed -eq 0 -and $passed -gt 0) {
                Write-Host "  [PASS] API Tests: $passed passed in ${duration}s" -ForegroundColor Green
            } else {
                Write-Host "  [FAIL] API Tests: $failed failed, $passed passed in ${duration}s" -ForegroundColor Red
            }

            return [PSCustomObject]@{
                Suite = "API"
                Passed = $passed
                Failed = $failed
                Skipped = 0
                Status = if ($failed -eq 0 -and $passed -gt 0) { "PASS" } else { "FAIL" }
                FailureOutput = if ($failed -gt 0) { $output } else { "" }
                Duration = $duration
            }
        }

        $webScript = {
            param($repoRoot)
            $startTime = Get-Date
            Write-Host "[WEB] Running Frontend Tests (Vitest)..." -ForegroundColor Yellow
            Push-Location "$repoRoot\apps\web"
            $output = npm run test:run 2>&1 | Out-String
            $allPassedMatches = [regex]::Matches($output, "(\d+) passed")
            $passed = if ($allPassedMatches.Count -ge 2) {
                [int]$allPassedMatches[$allPassedMatches.Count - 1].Groups[1].Value
            } elseif ($allPassedMatches.Count -eq 1) {
                [int]$allPassedMatches[0].Groups[1].Value
            } else { 0 }
            $failMatch = [regex]::Match($output, "(\d+) failed")
            $failed = if ($failMatch.Success) { [int]$failMatch.Groups[1].Value } else { 0 }
            Pop-Location

            $duration = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)
            if ($failed -eq 0 -and $passed -gt 0) {
                Write-Host "  [PASS] Frontend Tests: $passed passed in ${duration}s" -ForegroundColor Green
            } else {
                Write-Host "  [FAIL] Frontend Tests: $failed failed, $passed passed in ${duration}s" -ForegroundColor Red
            }

            return [PSCustomObject]@{
                Suite = "Frontend"
                Passed = $passed
                Failed = $failed
                Skipped = 0
                Status = if ($failed -eq 0 -and $passed -gt 0) { "PASS" } else { "FAIL" }
                FailureOutput = if ($failed -gt 0) { $output } else { "" }
                Duration = $duration
            }
        }

        $jobs = @()
        $jobs += Start-Job -ScriptBlock $sharedScript -ArgumentList $repoRoot -Name "Shared"
        $jobs += Start-Job -ScriptBlock $workersScript -ArgumentList $repoRoot -Name "Workers"
        $jobs += Start-Job -ScriptBlock $apiScript -ArgumentList $repoRoot -Name "API"
        $jobs += Start-Job -ScriptBlock $webScript -ArgumentList $repoRoot -Name "Web"

        # Wait for all jobs to complete and show results progressively
        $completedJobs = @{}
        while ($jobs.Count -gt 0) {
            $finishedJobs = $jobs | Where-Object { $_.State -eq 'Completed' }
            foreach ($job in $finishedJobs) {
                $result = Receive-Job -Job $job
                $completedJobs[$job.Name] = $result
                $jobs = $jobs | Where-Object { $_.Id -ne $job.Id }
                Remove-Job -Job $job

                # Add to results
                if ($result.Failed -gt 0) {
                    $script:allPassed = $false
                    $script:failures += @{
                        Suite = $result.Suite
                        Output = $result.FailureOutput
                    }
                }
                $script:results += $result
            }

            if ($finishedJobs.Count -eq 0) {
                Start-Sleep -Milliseconds 500  # Wait a bit before checking again
            }
        }
        # Run E2E tests sequentially after unit tests
        if ($runE2E) {
            $e2eResult = Test-E2E
            if ($e2eResult.Failed -gt 0) {
                $script:allPassed = $false
                $script:failures += @{
                    Suite = $e2eResult.Suite
                    Output = $e2eResult.FailureOutput
                }
            }
            $script:results += $e2eResult
        } else {
            $script:results += [PSCustomObject]@{
                Suite = "E2E"
                Passed = 0
                Failed = 0
                Skipped = 0
                Status = "SKIPPED"
            }
            Write-Host "[E2E] Skipped (use without -SkipE2E to include)" -ForegroundColor Yellow
        }
    }
    'api' {
        $result = Test-Api
        if ($result.Failed -gt 0) {
            $script:allPassed = $false
            $script:failures += @{ Suite = $result.Suite; Output = $result.FailureOutput }
        }
        $script:results += $result
    }
    'workers' {
        $result = Test-Workers
        if ($result.Failed -gt 0) {
            $script:allPassed = $false
            $script:failures += @{ Suite = $result.Suite; Output = $result.FailureOutput }
        }
        $script:results += $result
    }
    'shared' {
        $result = Test-Shared
        if ($result.Failed -gt 0) {
            $script:allPassed = $false
            $script:failures += @{ Suite = $result.Suite; Output = $result.FailureOutput }
        }
        $script:results += $result
    }
    'web' {
        $result = Test-Web
        if ($result.Failed -gt 0) {
            $script:allPassed = $false
            $script:failures += @{ Suite = $result.Suite; Output = $result.FailureOutput }
        }
        $script:results += $result
    }
    'e2e' {
        $result = Test-E2E
        if ($result.Failed -gt 0) {
            $script:allPassed = $false
            $script:failures += @{ Suite = $result.Suite; Output = $result.FailureOutput }
        }
        $script:results += $result
    }
}

# Summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  TEST SUMMARY" -ForegroundColor Cyan
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
    Write-Host "  [PASS] ALL TESTS PASSED" -ForegroundColor Green
    $exitCode = 0
} else {
    Write-Host ""
    Write-Host "  [FAIL] TESTS FAILED - Review: $failureLogPath" -ForegroundColor Red
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
