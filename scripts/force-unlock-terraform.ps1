# Force Release Terraform State Lock
# ===================================
# This script forcibly releases a Terraform state lock from Azure Blob Storage.
# Only use this when you're certain no other Terraform operations are running.

param(
    [string]$StorageAccountName = "stytsummprdtfstate",
    [string]$ContainerName = "tfstate",
    [string]$BlobName = "prod.tfstate"
)

Write-Host "⚠️  WARNING: This will forcibly release the Terraform state lock!" -ForegroundColor Yellow
Write-Host "   Only proceed if you're certain no Terraform operations are running." -ForegroundColor Yellow
Write-Host ""
Write-Host "Storage Account: $StorageAccountName"
Write-Host "Container: $ContainerName"
Write-Host "Blob: $BlobName"
Write-Host ""

$confirm = Read-Host "Type 'YES' to confirm"
if ($confirm -ne "YES") {
    Write-Host "❌ Aborted" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Breaking lease on state blob..." -ForegroundColor Cyan

try {
    az storage blob lease break `
        --account-name $StorageAccountName `
        --container-name $ContainerName `
        --blob-name $BlobName `
        --break-period 0

    Write-Host "✅ Lease broken successfully" -ForegroundColor Green
    Write-Host ""
    Write-Host "You can now run Terraform commands." -ForegroundColor Green
}
catch {
    Write-Host "❌ Failed to break lease: $_" -ForegroundColor Red
    exit 1
}
