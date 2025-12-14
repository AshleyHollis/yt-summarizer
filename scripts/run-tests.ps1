<#
.SYNOPSIS
    Runs all tests for the YT Summarizer project.

.DESCRIPTION
    This script runs tests across all components:
    - Frontend E2E tests (Playwright)
    - API unit and integration tests (pytest)
    - Worker tests (pytest)
    
    Use flags to control which tests to run and their mode.

.PARAMETER Component
    Which component(s) to test: 'all', 'web', 'api', 'workers'
    Default: 'all'

.PARAMETER Mode
    Test mode: 'unit' (fast, mocked), 'integration' (with DB), 'e2e' (full stack)
    Default: 'unit'

.PARAMETER Coverage
    Enable coverage reporting
    Default: false

.EXAMPLE
    # Run all unit tests
    .\scripts\run-tests.ps1

.EXAMPLE
    # Run web E2E tests (requires Aspire to be running)
    .\scripts\run-tests.ps1 -Component web -Mode e2e

.EXAMPLE
    # Run API integration tests with coverage
    .\scripts\run-tests.ps1 -Component api -Mode integration -Coverage

.EXAMPLE
    # Run all E2E tests against running infrastructure
    .\scripts\run-tests.ps1 -Mode e2e
#>

param(
    [ValidateSet('all', 'web', 'api', 'workers')]
    [string]$Component = 'all',
    
    [ValidateSet('unit', 'integration', 'e2e')]
    [string]$Mode = 'unit',
    
    [switch]$Coverage
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path -Parent $PSScriptRoot

Write-Host "🧪 YT Summarizer Test Runner" -ForegroundColor Cyan
Write-Host "Component: $Component | Mode: $Mode | Coverage: $Coverage" -ForegroundColor Gray
Write-Host ""

$results = @{
    Passed = @()
    Failed = @()
}

# =============================================================================
# Helper Functions
# =============================================================================

function Write-TestHeader($name) {
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
    Write-Host "📋 $name" -ForegroundColor Yellow
    Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
}

function Write-TestResult($name, $success) {
    if ($success) {
        Write-Host "✅ $name - PASSED" -ForegroundColor Green
        $script:results.Passed += $name
    } else {
        Write-Host "❌ $name - FAILED" -ForegroundColor Red
        $script:results.Failed += $name
    }
}

# =============================================================================
# Web Tests (Playwright)
# =============================================================================

function Test-Web {
    Write-TestHeader "Web Frontend Tests"
    
    Push-Location "$RepoRoot\apps\web"
    try {
        # Install dependencies if needed
        if (-not (Test-Path "node_modules")) {
            Write-Host "Installing dependencies..." -ForegroundColor Gray
            npm install
        }
        
        switch ($Mode) {
            'unit' {
                Write-Host "Running Vitest unit tests..." -ForegroundColor Gray
                if ($Coverage) {
                    npm run test:coverage
                } else {
                    npm run test:run
                }
            }
            'e2e' {
                Write-Host "Running Playwright E2E tests..." -ForegroundColor Gray
                Write-Host "Note: Requires Aspire to be running" -ForegroundColor DarkYellow
                
                $env:USE_EXTERNAL_SERVER = "true"
                npx playwright test
            }
            'integration' {
                Write-Host "Running Vitest unit tests..." -ForegroundColor Gray
                npm run test:run
            }
        }
        
        $success = $LASTEXITCODE -eq 0
        Write-TestResult "Web Tests" $success
    }
    finally {
        Pop-Location
    }
}

# =============================================================================
# API Tests (pytest)
# =============================================================================

function Test-Api {
    Write-TestHeader "API Tests"
    
    Push-Location "$RepoRoot\services\api"
    try {
        # Activate virtual environment
        $venvPath = ".venv\Scripts\Activate.ps1"
        if (Test-Path $venvPath) {
            . $venvPath
        } else {
            Write-Host "Creating virtual environment..." -ForegroundColor Gray
            python -m venv .venv
            . $venvPath
            pip install -e ".[dev]"
            pip install -e "..\shared"
        }
        
        switch ($Mode) {
            'unit' {
                Write-Host "Running pytest unit tests..." -ForegroundColor Gray
                if ($Coverage) {
                    pytest -m "not live" --cov=api --cov-report=html
                } else {
                    pytest -m "not live"
                }
            }
            'integration' {
                Write-Host "Running pytest integration tests..." -ForegroundColor Gray
                if ($Coverage) {
                    pytest -m "integration" --cov=api --cov-report=html
                } else {
                    pytest -m "integration"
                }
            }
            'e2e' {
                Write-Host "Running live E2E tests..." -ForegroundColor Gray
                Write-Host "Note: Requires Aspire to be running" -ForegroundColor DarkYellow
                
                $env:E2E_TESTS_ENABLED = "true"
                $env:API_BASE_URL = "http://localhost:8000"
                
                if ($Coverage) {
                    pytest -m "" --cov=api --cov-report=html
                } else {
                    pytest -m ""
                }
            }
        }
        
        $success = $LASTEXITCODE -eq 0
        Write-TestResult "API Tests" $success
    }
    finally {
        Pop-Location
    }
}

# =============================================================================
# Worker Tests (pytest)
# =============================================================================

function Test-Workers {
    Write-TestHeader "Worker Tests"
    
    Push-Location "$RepoRoot\services\workers"
    try {
        # Activate virtual environment
        $venvPath = ".venv\Scripts\Activate.ps1"
        if (Test-Path $venvPath) {
            . $venvPath
        } else {
            Write-Host "Creating virtual environment..." -ForegroundColor Gray
            python -m venv .venv
            . $venvPath
            pip install -e ".[dev]"
            pip install -e "..\shared"
        }
        
        Write-Host "Running pytest worker tests..." -ForegroundColor Gray
        
        if ($Coverage) {
            pytest --cov=. --cov-report=html
        } else {
            pytest
        }
        
        $success = $LASTEXITCODE -eq 0
        Write-TestResult "Worker Tests" $success
    }
    finally {
        Pop-Location
    }
}

# =============================================================================
# Main Execution
# =============================================================================

try {
    switch ($Component) {
        'all' {
            Test-Web
            Test-Api
            Test-Workers
        }
        'web' { Test-Web }
        'api' { Test-Api }
        'workers' { Test-Workers }
    }
}
catch {
    Write-Host "Error running tests: $_" -ForegroundColor Red
    exit 1
}

# =============================================================================
# Summary
# =============================================================================

Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray
Write-Host "📊 Test Summary" -ForegroundColor Cyan
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor DarkGray

if ($results.Passed.Count -gt 0) {
    Write-Host "Passed ($($results.Passed.Count)):" -ForegroundColor Green
    $results.Passed | ForEach-Object { Write-Host "  ✅ $_" -ForegroundColor Green }
}

if ($results.Failed.Count -gt 0) {
    Write-Host "Failed ($($results.Failed.Count)):" -ForegroundColor Red
    $results.Failed | ForEach-Object { Write-Host "  ❌ $_" -ForegroundColor Red }
    exit 1
}

Write-Host ""
Write-Host "All tests passed! 🎉" -ForegroundColor Green
