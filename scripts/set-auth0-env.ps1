[CmdletBinding()]
param(
    [string]$Domain,
    [string]$ClientId,
    [securestring]$ClientSecret,
    [string]$Audience,
    [securestring]$SessionSecret,
    [string]$DefaultReturnTo,
    [int]$SessionTtlSeconds,
    [switch]$Clear
)

$targetScope = 'User'
$setNames = @()
$clearedNames = @()

function ConvertTo-PlainText {
    param([securestring]$SecureValue)
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureValue)
    try {
        [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    } finally {
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function Set-UserEnvVar {
    param(
        [string]$Name,
        [string]$Value
    )
    [Environment]::SetEnvironmentVariable($Name, $Value, $targetScope)
    $script:setNames += $Name
}

function Clear-UserEnvVar {
    param([string]$Name)
    [Environment]::SetEnvironmentVariable($Name, $null, $targetScope)
    $script:clearedNames += $Name
}

if ($Clear) {
    @(
        'AUTH0_DOMAIN',
        'AUTH0_CLIENT_ID',
        'AUTH0_CLIENT_SECRET',
        'AUTH0_AUDIENCE',
        'AUTH0_SESSION_SECRET',
        'AUTH0_DEFAULT_RETURN_TO',
        'AUTH0_SESSION_TTL_SECONDS'
    ) | ForEach-Object { Clear-UserEnvVar $_ }

    Write-Host "Cleared Auth0 environment variables for user scope: $($clearedNames -join ', ')"
    Write-Host 'Restart your terminal to pick up changes.'
    exit 0
}

if (-not $Domain) {
    $Domain = Read-Host 'Auth0 domain (e.g., tenant.auth0.com)'
}
if (-not $ClientId) {
    $ClientId = Read-Host 'Auth0 client ID'
}
if (-not $ClientSecret) {
    $ClientSecret = Read-Host -Prompt 'Auth0 client secret' -AsSecureString
}
if (-not $SessionSecret) {
    $SessionSecret = Read-Host -Prompt 'Auth0 session secret' -AsSecureString
}
if (-not $DefaultReturnTo) {
    $DefaultReturnTo = Read-Host 'Default return URL after login (optional)'
}
if (-not $SessionTtlSeconds -or $SessionTtlSeconds -le 0) {
    $SessionTtlInput = Read-Host 'Session TTL seconds (optional, default 86400)'
    if ($SessionTtlInput) {
        [int]$SessionTtlSeconds = $SessionTtlInput
    }
}

Set-UserEnvVar -Name 'AUTH0_DOMAIN' -Value $Domain
Set-UserEnvVar -Name 'AUTH0_CLIENT_ID' -Value $ClientId
Set-UserEnvVar -Name 'AUTH0_CLIENT_SECRET' -Value (ConvertTo-PlainText $ClientSecret)
Set-UserEnvVar -Name 'AUTH0_SESSION_SECRET' -Value (ConvertTo-PlainText $SessionSecret)

if ($Audience) {
    Set-UserEnvVar -Name 'AUTH0_AUDIENCE' -Value $Audience
}
if ($DefaultReturnTo) {
    Set-UserEnvVar -Name 'AUTH0_DEFAULT_RETURN_TO' -Value $DefaultReturnTo
}
if ($SessionTtlSeconds -gt 0) {
    Set-UserEnvVar -Name 'AUTH0_SESSION_TTL_SECONDS' -Value $SessionTtlSeconds
}

Write-Host "Set Auth0 environment variables for user scope: $($setNames -join ', ')"
Write-Host 'Restart your terminal (or sign out/in) to pick up changes.'
