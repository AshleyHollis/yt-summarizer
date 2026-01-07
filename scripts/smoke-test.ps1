<#
.SYNOPSIS
    Quick smoke tests to verify core functionality after deployment.

.DESCRIPTION
    Runs a subset of critical tests to ensure the system works:
    1. API health check
    2. Video submission endpoint
    3. Job listing endpoint
    4. Frontend accessibility
    
    This is designed to run fast and give immediate feedback.

.PARAMETER ApiUrl
    The base URL for the API. Default: http://localhost:8000

.PARAMETER WebUrl
    The base URL for the web frontend. Default: http://localhost:3000

.EXAMPLE
    # Run smoke tests against local development
    .\scripts\smoke-test.ps1

.EXAMPLE
    # Run against deployed environment
    .\scripts\smoke-test.ps1 -ApiUrl https://api.example.com -WebUrl https://app.example.com
#>

param(
    [string]$ApiUrl = "http://localhost:8000",
    [string]$WebUrl = "http://localhost:3000"
)

$ErrorActionPreference = 'Stop'

Write-Host "=== YT Summarizer Smoke Tests ===" -ForegroundColor Cyan
Write-Host "API: $ApiUrl" -ForegroundColor Gray
Write-Host "Web: $WebUrl" -ForegroundColor Gray
Write-Host ""

$passed = 0
$failed = 0

function Test-Endpoint {
    param(
        [string]$Name,
        [string]$Url,
        [string]$Method = "GET",
        [object]$Body = $null,
        [int[]]$ExpectedStatus = @(200)
    )
    
    Write-Host "Testing: $Name... " -NoNewline
    
    try {
        $params = @{
            Uri = $Url
            Method = $Method
            UseBasicParsing = $true
            ErrorAction = 'Stop'
        }
        
        if ($Body) {
            $params.Body = ($Body | ConvertTo-Json)
            $params.ContentType = "application/json"
        }
        
        $response = Invoke-WebRequest @params
        
        if ($ExpectedStatus -contains $response.StatusCode) {
            Write-Host "[PASS] ($($response.StatusCode))" -ForegroundColor Green
            $script:passed++
            return $true
        } else {
            Write-Host "[FAIL] (Got $($response.StatusCode), expected $($ExpectedStatus -join '/'))" -ForegroundColor Red
            $script:failed++
            return $false
        }
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        if ($ExpectedStatus -contains $statusCode) {
            Write-Host "[PASS] ($statusCode)" -ForegroundColor Green
            $script:passed++
            return $true
        } else {
            Write-Host "[FAIL] ($_)" -ForegroundColor Red
            $script:failed++
            return $false
        }
    }
}

# =============================================================================
# API Health Checks
# =============================================================================

Write-Host "--- API Health Checks ---" -ForegroundColor Yellow

Test-Endpoint -Name "Health endpoint" -Url "$ApiUrl/health"
Test-Endpoint -Name "Liveness probe" -Url "$ApiUrl/health/live"
Test-Endpoint -Name "Readiness probe" -Url "$ApiUrl/health/ready" -ExpectedStatus @(200, 503)

# =============================================================================
# API Core Endpoints
# =============================================================================

Write-Host ""
Write-Host "--- API Core Endpoints ---" -ForegroundColor Yellow

Test-Endpoint -Name "Jobs list" -Url "$ApiUrl/api/v1/jobs"
Test-Endpoint -Name "Video submission validation" `
    -Url "$ApiUrl/api/v1/videos" `
    -Method "POST" `
    -Body @{ url = "not-valid-url" } `
    -ExpectedStatus @(422)

# =============================================================================
# Frontend
# =============================================================================

Write-Host ""
Write-Host "--- Frontend ---" -ForegroundColor Yellow

Test-Endpoint -Name "Web app accessible" -Url "$WebUrl" -ExpectedStatus @(200, 308, 307)
Test-Endpoint -Name "Submit page" -Url "$WebUrl/submit" -ExpectedStatus @(200)

# =============================================================================
# Summary
# =============================================================================

Write-Host ""
Write-Host "-------------------------------------------" -ForegroundColor DarkGray
Write-Host "Results: $passed passed, $failed failed" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
Write-Host "-------------------------------------------" -ForegroundColor DarkGray

if ($failed -gt 0) {
    exit 1
}

Write-Host "All smoke tests passed!" -ForegroundColor Green
