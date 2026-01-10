# Validate Kubernetes manifests and Kustomize configurations
# This script runs pre-deployment validation to catch issues early

param(
    [string]$ManifestPath = "k8s",
    [switch]$Fix
)

Write-Host "🔍 Validating Kubernetes manifests..." -ForegroundColor Cyan

# Check if kubectl is available
if (!(Get-Command kubectl -ErrorAction SilentlyContinue)) {
    Write-Error "kubectl not found. Please install kubectl to validate manifests."
    exit 1
}

# Check if kustomize is available
if (!(Get-Command kustomize -ErrorAction SilentlyContinue)) {
    Write-Warning "kustomize not found. Installing..."
    # Try to install kustomize
    try {
        # Download kustomize
        $kustomizeUrl = "https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2Fv5.0.0/kustomize_v5.0.0_windows_amd64.tar.gz"
        Invoke-WebRequest -Uri $kustomizeUrl -OutFile "kustomize.tar.gz"
        tar -xzf kustomize.tar.gz
        Move-Item kustomize.exe $env:USERPROFILE\bin\kustomize.exe
        $env:PATH += ";$env:USERPROFILE\bin"
    } catch {
        Write-Warning "Could not install kustomize. Skipping kustomize validation."
    }
}

$errors = @()
$warnings = @()

# Function to validate YAML syntax
function Test-YamlSyntax {
    param([string]$FilePath)

    try {
        $content = Get-Content $FilePath -Raw
        if ($content -match '^\s*---\s*$') {
            # Multi-document YAML
            $documents = $content -split '(?m)^---\s*$' | Where-Object { $_.Trim() }
            foreach ($doc in $documents) {
                if ($doc.Trim()) {
                    $null = ConvertFrom-Yaml $doc
                }
            }
        } else {
            $null = ConvertFrom-Yaml $content
        }
        return $true
    } catch {
        $errors += "YAML syntax error in $FilePath`: $($_.Exception.Message)"
        return $false
    }
}

# Find all YAML files in the manifest path
$yamlFiles = Get-ChildItem -Path $ManifestPath -Recurse -Include "*.yaml", "*.yml" | Where-Object {
    $_.FullName -notmatch '\\\.git\\' -and
    $_.FullName -notmatch '\\node_modules\\' -and
    $_.FullName -notmatch '\\__pycache__\\'
}

Write-Host "📁 Found $($yamlFiles.Count) YAML files to validate" -ForegroundColor Blue

foreach ($file in $yamlFiles) {
    Write-Host "  Validating $($file.Name)..." -ForegroundColor Gray

    # Check YAML syntax
    if (!(Test-YamlSyntax $file.FullName)) {
        continue
    }

    # Check for common Kubernetes issues
    $content = Get-Content $file.FullName -Raw

    # Check for tabs (should use spaces)
    if ($content -match "`t") {
        $warnings += "File $file contains tabs. Use spaces for indentation."
    }

    # Check for trailing whitespace
    $lines = Get-Content $file.FullName
    for ($i = 0; $i -lt $lines.Count; $i++) {
        if ($lines[$i] -match '\s+$') {
            $warnings += "File $($file.Name) line $($i + 1) has trailing whitespace"
        }
    }
}

# Validate Kustomize configurations
$kustomizationFiles = Get-ChildItem -Path $ManifestPath -Recurse -Name "kustomization.yaml"

foreach ($kustomization in $kustomizationFiles) {
    $kustomizationPath = Join-Path $ManifestPath $kustomization
    $kustomizationDir = Split-Path $kustomizationPath -Parent

    Write-Host "🔧 Validating Kustomize in $kustomizationDir..." -ForegroundColor Blue

    if (Get-Command kustomize -ErrorAction SilentlyContinue) {
        try {
            Push-Location $kustomizationDir
            $null = kustomize build . 2>&1
            Write-Host "  ✅ Kustomize build successful" -ForegroundColor Green
        } catch {
            $errors += "Kustomize build failed in $kustomizationDir`: $($_.Exception.Message)"
        } finally {
            Pop-Location
        }
    } else {
        $warnings += "Skipping Kustomize validation for $kustomizationDir (kustomize not available)"
    }
}

# Validate Argo CD applications
$argocdApps = Get-ChildItem -Path "k8s/argocd" -Recurse -Include "*.yaml" | Where-Object {
    (Get-Content $_.FullName -Raw) -match "kind:\s*Application"
}

foreach ($app in $argocdApps) {
    Write-Host "⚙️  Validating Argo CD application $($app.Name)..." -ForegroundColor Blue

    # Check for required fields
    $content = Get-Content $app.FullName -Raw
    if ($content -notmatch "repoURL:") {
        $errors += "Argo CD application $($app.Name) missing repoURL"
    }
    if ($content -notmatch "path:") {
        $errors += "Argo CD application $($app.Name) missing path"
    }
    if ($content -notmatch "targetRevision:") {
        $warnings += "Argo CD application $($app.Name) missing explicit targetRevision"
    }
}

# Report results
if ($errors.Count -gt 0) {
    Write-Host "`n❌ Validation failed with $($errors.Count) errors:" -ForegroundColor Red
    foreach ($error in $errors) {
        Write-Host "  $error" -ForegroundColor Red
    }
    exit 1
}

if ($warnings.Count -gt 0) {
    Write-Host "`n⚠️  Validation completed with $($warnings.Count) warnings:" -ForegroundColor Yellow
    foreach ($warning in $warnings) {
        Write-Host "  $warning" -ForegroundColor Yellow
    }
}

Write-Host "`n✅ Validation completed successfully!" -ForegroundColor Green