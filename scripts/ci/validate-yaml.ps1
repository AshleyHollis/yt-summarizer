#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Validates YAML syntax for GitHub Actions workflows and composite actions.

.DESCRIPTION
    This script checks all workflow and composite action YAML files for syntax errors
    using Python's yaml library. It reports any parsing errors found.

.PARAMETER Path
    Path to validate (defaults to .github directory)

.EXAMPLE
    .\validate-yaml.ps1
    .\validate-yaml.ps1 -Path .github/workflows
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$Path = ".github"
)

$ErrorActionPreference = "Stop"

# Find all YAML files
$yamlFiles = Get-ChildItem -Path $Path -Recurse -Filter "*.yml" -File

if ($yamlFiles.Count -eq 0) {
    Write-Host "No YAML files found in $Path" -ForegroundColor Yellow
    exit 0
}

Write-Host "Validating $($yamlFiles.Count) YAML files..." -ForegroundColor Cyan
Write-Host ""

$errors = @()

foreach ($file in $yamlFiles) {
    $relativePath = $file.FullName.Replace("$PWD\", "")
    Write-Host "Checking: $relativePath" -ForegroundColor Gray
    
    try {
        # Use Python to validate YAML syntax
        $pythonScript = @"
import sys
import yaml

file_path = r'$($file.FullName)'

try:
    with open(file_path, 'r', encoding='utf-8') as f:
        content = f.read()
        yaml.safe_load(content)
    print('VALID')
    sys.exit(0)
except yaml.YAMLError as e:
    print(f'YAML Error: {str(e)}')
    sys.exit(1)
except Exception as e:
    print(f'Error: {str(e)}')
    sys.exit(1)
"@
        
        $output = python -c $pythonScript 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            $errors += [PSCustomObject]@{
                File = $relativePath
                Error = $output -join "`n"
            }
            Write-Host "  ❌ INVALID" -ForegroundColor Red
        } else {
            Write-Host "  ✅ VALID" -ForegroundColor Green
        }
    }
    catch {
        $errors += [PSCustomObject]@{
            File = $relativePath
            Error = $_.Exception.Message
        }
        Write-Host "  ❌ ERROR" -ForegroundColor Red
    }
}

Write-Host ""

if ($errors.Count -eq 0) {
    Write-Host "✅ All YAML files are valid!" -ForegroundColor Green
    exit 0
} else {
    Write-Host "❌ Found $($errors.Count) YAML file(s) with errors:" -ForegroundColor Red
    Write-Host ""
    
    foreach ($error in $errors) {
        Write-Host "File: $($error.File)" -ForegroundColor Yellow
        Write-Host "Error: $($error.Error)" -ForegroundColor Red
        Write-Host ""
    }
    
    exit 1
}
