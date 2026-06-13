<#
.SYNOPSIS
    Unified test runner for the YT Summarizer project.

.DESCRIPTION
    Runs tests across all components: API, Workers, Shared, Frontend, and E2E.

    By default, runs ALL tests including E2E (requires Aspire running).
    WARNING: -SkipE2E is for development iteration ONLY - per Constitution VI.5, E2E tests are REQUIRED for task completion.

.PARAMETER SkipE2E
    Skip E2E tests (DEVELOPMENT ONLY - do NOT use for final verification per Constitution VI.5)

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

$swaValidationScript = Join-Path $repoRoot "scripts\validate-swa-output.ps1"
if (Test-Path $swaValidationScript) {
    Write-Host "[SWA] Validating output_location configuration..." -ForegroundColor Cyan
    try {
        & $swaValidationScript
    } catch {
        Write-Host "[SWA] Validation failed: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
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
        $Component = 'all'
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

    if ($Status -eq "FAIL") {
        $script:allPassed = $false
        $script:failures += @{
            Suite = $Suite
            Output = $FailureOutput
        }
    }
}

function Test-YtApiEndpoint {
    param(
        [string]$ApiUrl = "http://localhost:8000"
    )

    try {
        $health = Invoke-RestMethod -Uri "$($ApiUrl.TrimEnd('/'))/health" -TimeoutSec 5 -ErrorAction Stop
        return $health.checks.api -eq $true -and
            $null -ne $health.checks.database -and
            $null -ne $health.checks.blob_storage -and
            $null -ne $health.checks.queue_storage
    } catch {
        return $false
    }
}

function Test-YtWebEndpoint {
    param(
        [string]$BaseUrl = "http://localhost:3000"
    )

    try {
        $response = Invoke-WebRequest -Uri "$($BaseUrl.TrimEnd('/'))/sign-in" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
        return $response.Content -match "YT Summarizer" -or $response.Content -match "YouTube Summarizer"
    } catch {
        return $false
    }
}

function Get-UrlPort {
    param(
        [string]$Url,
        [int]$Fallback
    )

    try {
        $uri = [System.Uri]$Url
        if ($uri.Port -gt 0) {
            return $uri.Port
        }
    } catch {
        return $Fallback
    }
    return $Fallback
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
    param(
        [string]$ComponentPath = $null
    )

    if ($ComponentPath) {
        $componentPython = Join-Path $ComponentPath ".venv\Scripts\python.exe"
        if (Test-Path $componentPython) {
            return $componentPython
        }
    }

    $venvPython = Join-Path $repoRoot ".venv\Scripts\python.exe"
    if (Test-Path $venvPython) {
        return $venvPython
    }
    return "python"
}

function Get-PytestCount {
    param(
        [string]$Output,
        [string]$Label
    )

    $matches = [regex]::Matches($Output, "(\d+) $Label")
    if ($matches.Count -gt 0) {
        return [int]$matches[$matches.Count - 1].Groups[1].Value
    }
    return 0
}

function Test-Api {
    Write-Host "[API] Running API Tests..." -ForegroundColor Yellow
    $componentPath = Join-Path $repoRoot "services\api"
    Push-Location $componentPath
    $pythonExe = Get-PythonExe $componentPath

    $passed = 0
    $failed = 0
    $skipped = 0
    $failureOutput = ""
    $testFiles = Get-ChildItem -Path "tests" -Filter "test_*.py" | Sort-Object Name

    foreach ($testFile in $testFiles) {
        Write-Host "  [API] $($testFile.Name)" -ForegroundColor Cyan
        $output = & $pythonExe -m pytest $testFile.FullName -q --tb=short 2>&1 | Out-String
        $exitCode = $LASTEXITCODE
        $filePassed = Get-PytestCount -Output $output -Label "passed"
        $fileFailed = Get-PytestCount -Output $output -Label "failed"
        $fileSkipped = Get-PytestCount -Output $output -Label "skipped"

        $passed += $filePassed
        $failed += $fileFailed
        $skipped += $fileSkipped

        if ($exitCode -ne 0 -or $fileFailed -gt 0) {
            $failureOutput = $output
            break
        }
    }
    Pop-Location

    return [PSCustomObject]@{
        Suite = "API"
        Passed = $passed
        Failed = $failed
        Skipped = $skipped
        Status = if ($failed -eq 0 -and $passed -gt 0) { "PASS" } else { "FAIL" }
        FailureOutput = if ($failed -gt 0 -or $passed -eq 0) { $failureOutput } else { "" }
    }
}

function Test-Workers {
    Write-Host "[WORKERS] Running Worker Tests..." -ForegroundColor Yellow
    $componentPath = Join-Path $repoRoot "services\workers"
    Push-Location $componentPath
    $pythonExe = Get-PythonExe $componentPath
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
        FailureOutput = if ($failed -gt 0 -or $passed -eq 0) { $output } else { "" }
    }
}

function Test-Shared {
    Write-Host "[SHARED] Running Shared Package Tests..." -ForegroundColor Yellow
    $componentPath = Join-Path $repoRoot "services\shared"
    Push-Location $componentPath
    $output = & uv run --extra dev pytest tests/ -v 2>&1 | Out-String
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
        FailureOutput = if ($failed -gt 0 -or $passed -eq 0) { $output } else { "" }
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
        FailureOutput = if ($failed -gt 0 -or $passed -eq 0) { $output } else { "" }
    }
}

function Test-E2E {
    $startTime = Get-Date
    Write-Host "[E2E] Running E2E Tests (Playwright)..." -ForegroundColor Yellow
    $apiUrl = if ($env:API_URL) { $env:API_URL } else { "http://localhost:8000" }
    $baseUrl = if ($env:BASE_URL) { $env:BASE_URL } else { "http://localhost:3000" }
    $env:API_URL = $apiUrl
    $env:BASE_URL = $baseUrl
    $env:NEXT_PUBLIC_API_URL = $apiUrl
    $env:API_PORT = "$(Get-UrlPort -Url $apiUrl -Fallback 8000)"
    $env:WEB_PORT = "$(Get-UrlPort -Url $baseUrl -Fallback 3000)"
    $env:API_BASE_URL = $apiUrl

    # Check if Aspire is running by testing a YT Summarizer-specific endpoint.
    # A generic /health probe can be satisfied by another local app on port 8000.
    $aspireRunning = Test-YtApiEndpoint -ApiUrl $apiUrl

    if ($aspireRunning -eq $false) {
        Write-Host "  [WARN] Aspire not running - starting it..." -ForegroundColor Yellow
        # Use the wrapper script if available
        $aspireCmd = Join-Path $repoRoot "tools\aspire.cmd"
        if (Test-Path $aspireCmd) {
            Start-Process -FilePath $aspireCmd -ArgumentList "run" -WorkingDirectory $repoRoot -WindowStyle Hidden
        } else {
            Push-Location "$repoRoot\services\aspire\AppHost"
            Start-Process -FilePath "dotnet" -ArgumentList "run" -WindowStyle Hidden
            Pop-Location
        }
        $startupTimeoutSeconds = 180
        $deadline = (Get-Date).AddSeconds($startupTimeoutSeconds)
        Write-Host "  Waiting up to $startupTimeoutSeconds seconds for services to start..." -ForegroundColor Yellow
        do {
            $apiReady = Test-YtApiEndpoint -ApiUrl $apiUrl
            $webReady = Test-YtWebEndpoint -BaseUrl $baseUrl
            if ($apiReady -and $webReady) {
                break
            }
            Start-Sleep -Seconds 5
        } while ((Get-Date) -lt $deadline)
    }

    if (-not (Test-YtApiEndpoint -ApiUrl $apiUrl)) {
        $duration = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)
        $message = "YT Summarizer API is not available at $apiUrl. " +
            "Stop any other service using that port or start Aspire before running E2E."
        Write-Host "  [FAIL] E2E Tests: $message" -ForegroundColor Red
        return [PSCustomObject]@{
            Suite = "E2E"
            Passed = 0
            Failed = 1
            Skipped = 0
            Status = "FAIL"
            FailureOutput = $message
            Duration = $duration
        }
    }

    if (-not (Test-YtWebEndpoint -BaseUrl $baseUrl)) {
        $duration = [math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)
        $message = "YT Summarizer web app is not available at $baseUrl. " +
            "Stop any other service using that port or start Aspire before running E2E."
        Write-Host "  [FAIL] E2E Tests: $message" -ForegroundColor Red
        return [PSCustomObject]@{
            Suite = "E2E"
            Passed = 0
            Failed = 1
            Skipped = 0
            Status = "FAIL"
            FailureOutput = $message
            Duration = $duration
        }
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
        Write-Host "Running unit/integration tests sequentially with fail-fast..." -ForegroundColor Yellow

        $testSteps = @(
            @{ Name = "API"; Run = { Test-Api } },
            @{ Name = "Shared"; Run = { Test-Shared } },
            @{ Name = "Workers"; Run = { Test-Workers } },
            @{ Name = "Frontend"; Run = { Test-Web } }
        )

        foreach ($step in $testSteps) {
            if (-not $script:allPassed) {
                Write-Host "[$($step.Name)] Skipped because an earlier layer failed" -ForegroundColor Yellow
                $script:results += [PSCustomObject]@{
                    Suite = $step.Name
                    Passed = 0
                    Failed = 0
                    Skipped = 0
                    Status = "SKIPPED"
                }
                continue
            }

            $result = & $step.Run
            if ($result.Status -eq "FAIL") {
                $script:allPassed = $false
                $script:failures += @{
                    Suite = $result.Suite
                    Output = $result.FailureOutput
                }
            }
            $script:results += $result
        }

        if ($runE2E -and $script:allPassed) {
            $e2eResult = Test-E2E
            if ($e2eResult.Status -eq "FAIL") {
                $script:allPassed = $false
                $script:failures += @{
                    Suite = $e2eResult.Suite
                    Output = $e2eResult.FailureOutput
                }
            }
            $script:results += $e2eResult
        } elseif ($runE2E) {
            $script:results += [PSCustomObject]@{
                Suite = "E2E"
                Passed = 0
                Failed = 0
                Skipped = 0
                Status = "SKIPPED"
            }
            Write-Host "[E2E] Skipped because an earlier layer failed" -ForegroundColor Yellow
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
        if ($result.Status -eq "FAIL") {
            $script:allPassed = $false
            $script:failures += @{ Suite = $result.Suite; Output = $result.FailureOutput }
        }
        $script:results += $result
    }
    'workers' {
        $result = Test-Workers
        if ($result.Status -eq "FAIL") {
            $script:allPassed = $false
            $script:failures += @{ Suite = $result.Suite; Output = $result.FailureOutput }
        }
        $script:results += $result
    }
    'shared' {
        $result = Test-Shared
        if ($result.Status -eq "FAIL") {
            $script:allPassed = $false
            $script:failures += @{ Suite = $result.Suite; Output = $result.FailureOutput }
        }
        $script:results += $result
    }
    'web' {
        $result = Test-Web
        if ($result.Status -eq "FAIL") {
            $script:allPassed = $false
            $script:failures += @{ Suite = $result.Suite; Output = $result.FailureOutput }
        }
        $script:results += $result
    }
    'e2e' {
        $result = Test-E2E
        if ($result.Status -eq "FAIL") {
            $script:allPassed = $false
            $script:failures += @{ Suite = $result.Suite; Output = $result.FailureOutput }
        }
        $script:results += $result
    }
    default {
        $components = $Component -split ',' | Where-Object { $_ -in @('api','workers','shared','web','e2e') }
        foreach ($detectedComponent in $components) {
            switch ($detectedComponent) {
                'api' {
                    $result = Test-Api
                }
                'workers' {
                    $result = Test-Workers
                }
                'shared' {
                    $result = Test-Shared
                }
                'web' {
                    $result = Test-Web
                }
                'e2e' {
                    if ($script:allPassed) {
                        $result = Test-E2E
                    } else {
                        $result = [PSCustomObject]@{
                            Suite = "E2E"
                            Passed = 0
                            Failed = 0
                            Skipped = 0
                            Status = "SKIPPED"
                        }
                        Write-Host "[E2E] Skipped because earlier tests failed" -ForegroundColor Yellow
                    }
                }
            }

            if ($result.Status -eq "FAIL") {
                $script:allPassed = $false
                $script:failures += @{ Suite = $result.Suite; Output = $result.FailureOutput }
            }
            $script:results += $result
        }
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
