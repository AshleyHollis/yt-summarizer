# Configure Auth0 Terraform M2M Application Permissions
# =====================================================
# This script grants the necessary permissions to an Auth0 M2M application
# so it can manage Auth0 resources via Terraform.

param(
    [Parameter(Mandatory=$false)]
    [string]$Auth0Domain = $env:AUTH0_DOMAIN,
    
    [Parameter(Mandatory=$false)]
    [string]$ClientId = $env:AUTH0_CLIENT_ID,
    
    [Parameter(Mandatory=$false)]
    [string]$ClientSecret = $env:AUTH0_CLIENT_SECRET,
    
    [switch]$ShowCurrentPermissions
)

# Validate parameters
if (-not $Auth0Domain -or -not $ClientId -or -not $ClientSecret) {
    Write-Host "❌ Missing required parameters!" -ForegroundColor Red
    Write-Host ""
    Write-Host "Usage:" -ForegroundColor Yellow
    Write-Host "  .\configure-auth0-permissions.ps1 -Auth0Domain 'your-tenant.auth0.com' -ClientId 'xxx' -ClientSecret 'yyy'"
    Write-Host ""
    Write-Host "Or set environment variables:" -ForegroundColor Yellow
    Write-Host "  `$env:AUTH0_DOMAIN = 'your-tenant.auth0.com'"
    Write-Host "  `$env:AUTH0_CLIENT_ID = 'your-client-id'"
    Write-Host "  `$env:AUTH0_CLIENT_SECRET = 'your-client-secret'"
    Write-Host ""
    exit 1
}

# Strip https:// if present
$Auth0Domain = $Auth0Domain -replace '^https?://', ''

Write-Host "🔧 Auth0 Permission Configuration Tool" -ForegroundColor Cyan
Write-Host "=======================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Domain: $Auth0Domain"
Write-Host "Client ID: $ClientId"
Write-Host ""

# Required scopes for Terraform
$requiredScopes = @(
    "read:clients",
    "create:clients",
    "update:clients",
    "delete:clients",
    "read:client_grants",
    "create:client_grants",
    "update:client_grants",
    "delete:client_grants",
    "read:resource_servers",
    "create:resource_servers",
    "update:resource_servers",
    "delete:resource_servers"
)

Write-Host "📋 Required Scopes:" -ForegroundColor Yellow
$requiredScopes | ForEach-Object { Write-Host "   - $_" }
Write-Host ""

# Step 1: Get access token
Write-Host "🔑 Step 1: Getting Management API access token..." -ForegroundColor Cyan

$tokenUrl = "https://$Auth0Domain/oauth/token"
$tokenBody = @{
    grant_type    = "client_credentials"
    client_id     = $ClientId
    client_secret = $ClientSecret
    audience      = "https://$Auth0Domain/api/v2/"
} | ConvertTo-Json

try {
    $tokenResponse = Invoke-RestMethod -Uri $tokenUrl -Method Post -Body $tokenBody -ContentType "application/json"
    $accessToken = $tokenResponse.access_token
    Write-Host "✅ Got access token" -ForegroundColor Green
    Write-Host ""
}
catch {
    Write-Host "❌ Failed to get access token!" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    Write-Host ""
    Write-Host "Please verify:" -ForegroundColor Yellow
    Write-Host "  1. AUTH0_DOMAIN is correct (without https://)" -ForegroundColor Yellow
    Write-Host "  2. AUTH0_CLIENT_ID and AUTH0_CLIENT_SECRET are correct" -ForegroundColor Yellow
    Write-Host "  3. The M2M application is enabled in Auth0" -ForegroundColor Yellow
    exit 1
}

$headers = @{
    "Authorization" = "Bearer $accessToken"
    "Content-Type"  = "application/json"
}

# Step 2: Get Management API Resource Server ID
Write-Host "🔍 Step 2: Finding Auth0 Management API..." -ForegroundColor Cyan

try {
    $resourceServers = Invoke-RestMethod -Uri "https://$Auth0Domain/api/v2/resource-servers" -Headers $headers -Method Get
    $managementApi = $resourceServers | Where-Object { $_.identifier -eq "https://$Auth0Domain/api/v2/" }
    
    if (-not $managementApi) {
        Write-Host "❌ Could not find Management API resource server!" -ForegroundColor Red
        exit 1
    }
    
    $managementApiId = $managementApi.id
    Write-Host "✅ Found Management API (ID: $managementApiId)" -ForegroundColor Green
    Write-Host ""
}
catch {
    Write-Host "❌ Failed to query resource servers!" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}

# Step 3: Check current client grants
Write-Host "🔍 Step 3: Checking current permissions..." -ForegroundColor Cyan

try {
    $clientGrants = Invoke-RestMethod -Uri "https://$Auth0Domain/api/v2/client-grants?client_id=$ClientId" -Headers $headers -Method Get
    
    $existingGrant = $clientGrants | Where-Object { $_.audience -eq "https://$Auth0Domain/api/v2/" }
    
    if ($existingGrant) {
        Write-Host "✅ Found existing client grant (ID: $($existingGrant.id))" -ForegroundColor Green
        Write-Host ""
        Write-Host "Current scopes:" -ForegroundColor Yellow
        $existingGrant.scope | ForEach-Object { Write-Host "   - $_" -ForegroundColor Gray }
        Write-Host ""
        
        if ($ShowCurrentPermissions) {
            Write-Host "✅ Current permissions displayed above" -ForegroundColor Green
            exit 0
        }
        
        # Check if all required scopes are present
        $missingScopes = $requiredScopes | Where-Object { $_ -notin $existingGrant.scope }
        
        if ($missingScopes.Count -eq 0) {
            Write-Host "✅ All required permissions are already granted!" -ForegroundColor Green
            exit 0
        }
        
        Write-Host "⚠️  Missing scopes:" -ForegroundColor Yellow
        $missingScopes | ForEach-Object { Write-Host "   - $_" -ForegroundColor Red }
        Write-Host ""
        
        # Update existing grant
        Write-Host "📝 Step 4: Updating client grant with required scopes..." -ForegroundColor Cyan
        
        $updateBody = @{
            scope = $requiredScopes
        } | ConvertTo-Json
        
        try {
            $updated = Invoke-RestMethod -Uri "https://$Auth0Domain/api/v2/client-grants/$($existingGrant.id)" -Headers $headers -Method Patch -Body $updateBody
            Write-Host "✅ Successfully updated client grant!" -ForegroundColor Green
            Write-Host ""
            Write-Host "New scopes:" -ForegroundColor Green
            $updated.scope | ForEach-Object { Write-Host "   - $_" -ForegroundColor Green }
        }
        catch {
            Write-Host "❌ Failed to update client grant!" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
            
            if ($_.Exception.Response) {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $reader.BaseStream.Position = 0
                $reader.DiscardBufferedData()
                $responseBody = $reader.ReadToEnd()
                Write-Host "Response: $responseBody" -ForegroundColor Red
            }
            exit 1
        }
    }
    else {
        Write-Host "⚠️  No existing client grant found" -ForegroundColor Yellow
        Write-Host ""
        
        # Create new client grant
        Write-Host "📝 Step 4: Creating new client grant..." -ForegroundColor Cyan
        
        $createBody = @{
            client_id = $ClientId
            audience  = "https://$Auth0Domain/api/v2/"
            scope     = $requiredScopes
        } | ConvertTo-Json
        
        try {
            $created = Invoke-RestMethod -Uri "https://$Auth0Domain/api/v2/client-grants" -Headers $headers -Method Post -Body $createBody
            Write-Host "✅ Successfully created client grant!" -ForegroundColor Green
            Write-Host ""
            Write-Host "Granted scopes:" -ForegroundColor Green
            $created.scope | ForEach-Object { Write-Host "   - $_" -ForegroundColor Green }
        }
        catch {
            Write-Host "❌ Failed to create client grant!" -ForegroundColor Red
            Write-Host $_.Exception.Message -ForegroundColor Red
            
            if ($_.Exception.Response) {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $reader.BaseStream.Position = 0
                $reader.DiscardBufferedData()
                $responseBody = $reader.ReadToEnd()
                Write-Host "Response: $responseBody" -ForegroundColor Red
            }
            exit 1
        }
    }
    
    Write-Host ""
    Write-Host "✅ Configuration complete!" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "  1. Ensure environment variables are set in your CI/CD pipeline:" -ForegroundColor Gray
    Write-Host "     - AUTH0_DOMAIN=$Auth0Domain" -ForegroundColor Gray
    Write-Host "     - AUTH0_CLIENT_ID=$ClientId" -ForegroundColor Gray
    Write-Host "     - AUTH0_CLIENT_SECRET=(your secret)" -ForegroundColor Gray
    Write-Host "  2. Set enable_auth0 = true in Terraform" -ForegroundColor Gray
    Write-Host "  3. Run terraform plan/apply" -ForegroundColor Gray
    Write-Host ""
}
catch {
    Write-Host "❌ Failed to check client grants!" -ForegroundColor Red
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
