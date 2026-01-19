# Delete Auth0 Test Users
# =======================
# Removes existing test users from Auth0 so Terraform can create them fresh
#
# Prerequisites:
#   - AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET environment variables
#   - Or pass as parameters
#
# Usage:
#   # Using environment variables:
#   $env:AUTH0_DOMAIN = "your-tenant.auth0.com"
#   $env:AUTH0_CLIENT_ID = "your-client-id"
#   $env:AUTH0_CLIENT_SECRET = "your-client-secret"
#   .\scripts\delete-auth0-test-users.ps1
#
#   # Or pass as parameters:
#   .\scripts\delete-auth0-test-users.ps1 -Domain "your-tenant.auth0.com" -ClientId "your-id" -ClientSecret "your-secret"

param(
    [string]$Domain = $env:AUTH0_DOMAIN,
    [string]$ClientId = $env:AUTH0_CLIENT_ID,
    [string]$ClientSecret = $env:AUTH0_CLIENT_SECRET
)

$ErrorActionPreference = "Stop"

Write-Host "🔧 Auth0 Test User Deletion Script" -ForegroundColor Yellow
Write-Host ""

# Check prerequisites
if (-not $Domain -or -not $ClientId -or -not $ClientSecret) {
    Write-Host "❌ Error: AUTH0_DOMAIN, AUTH0_CLIENT_ID, and AUTH0_CLIENT_SECRET must be set" -ForegroundColor Red
    Write-Host ""
    Write-Host "Set environment variables or pass as parameters:"
    Write-Host "  `$env:AUTH0_DOMAIN = 'your-tenant.auth0.com'"
    Write-Host "  `$env:AUTH0_CLIENT_ID = 'your-client-id'"
    Write-Host "  `$env:AUTH0_CLIENT_SECRET = 'your-client-secret'"
    exit 1
}

# Define test user emails
$AdminEmail = "admin@test.yt-summarizer.internal"
$UserEmail = "user@test.yt-summarizer.internal"

# Get Auth0 Management API token
Write-Host "Getting Auth0 Management API token..." -ForegroundColor Cyan

$tokenBody = @{
    client_id     = $ClientId
    client_secret = $ClientSecret
    audience      = "https://$Domain/api/v2/"
    grant_type    = "client_credentials"
} | ConvertTo-Json

try {
    $tokenResponse = Invoke-RestMethod -Method Post `
        -Uri "https://$Domain/oauth/token" `
        -ContentType "application/json" `
        -Body $tokenBody
    
    $accessToken = $tokenResponse.access_token
    Write-Host "✓ Got access token" -ForegroundColor Green
}
catch {
    Write-Host "❌ Failed to get access token" -ForegroundColor Red
    Write-Host $_.Exception.Message
    exit 1
}

# Function to get user ID by email
function Get-Auth0UserId {
    param([string]$Email)
    
    $headers = @{
        Authorization = "Bearer $accessToken"
    }
    
    try {
        $users = Invoke-RestMethod -Method Get `
            -Uri "https://$Domain/api/v2/users-by-email?email=$Email" `
            -Headers $headers
        
        if ($users.Count -gt 0) {
            return $users[0].user_id
        }
        return $null
    }
    catch {
        Write-Host "Warning: Error fetching user $Email - $_" -ForegroundColor Yellow
        return $null
    }
}

# Function to delete user
function Remove-Auth0User {
    param([string]$Email)
    
    $userId = Get-Auth0UserId -Email $Email
    
    if (-not $userId) {
        Write-Host "⚠️  User $Email not found in Auth0 (already deleted or never existed)" -ForegroundColor Yellow
        return $true
    }
    
    Write-Host "Found user: $Email (ID: $userId)" -ForegroundColor Cyan
    Write-Host "Deleting..." -ForegroundColor Cyan
    
    $headers = @{
        Authorization = "Bearer $accessToken"
    }
    
    try {
        Invoke-RestMethod -Method Delete `
            -Uri "https://$Domain/api/v2/users/$userId" `
            -Headers $headers | Out-Null
        
        Write-Host "✓ Successfully deleted $Email" -ForegroundColor Green
        return $true
    }
    catch {
        Write-Host "✗ Failed to delete $Email" -ForegroundColor Red
        Write-Host $_.Exception.Message
        return $false
    }
}

Write-Host ""
Write-Host "⚠️  WARNING: This will delete test users from Auth0" -ForegroundColor Yellow
Write-Host "Users to delete:" -ForegroundColor Yellow
Write-Host "  - $AdminEmail"
Write-Host "  - $UserEmail"
Write-Host ""
Write-Host "Press Ctrl+C to cancel, or Enter to continue..." -ForegroundColor Yellow
Read-Host

Write-Host ""
Write-Host "Deleting test users..." -ForegroundColor Cyan
Write-Host ""

$success = $true
$success = (Remove-Auth0User -Email $AdminEmail) -and $success
$success = (Remove-Auth0User -Email $UserEmail) -and $success

Write-Host ""
if ($success) {
    Write-Host "✓ Deletion complete!" -ForegroundColor Green
    Write-Host ""
    Write-Host "You can now run Terraform apply to recreate the users." -ForegroundColor Green
    exit 0
}
else {
    Write-Host "❌ Some deletions failed. Check the output above." -ForegroundColor Red
    exit 1
}
