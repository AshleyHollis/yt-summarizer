#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Waits for Argo CD application to sync and become healthy

.DESCRIPTION
    Polls Argo CD application status until it's synced and healthy.
    Useful for deployment workflows that need to wait for rollout completion.

.PARAMETER AppName
    Argo CD application name

.PARAMETER Namespace
    Kubernetes namespace where the Argo CD app is deployed (default: argocd)

.PARAMETER MaxWaitSeconds
    Maximum time to wait in seconds (default: 600)

.PARAMETER IntervalSeconds
    Polling interval in seconds (default: 10)

.EXAMPLE
    ./wait-for-deployment.ps1 -AppName preview-pr-123 -MaxWaitSeconds 300
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$AppName,
    
    [string]$Namespace = "argocd",
    [int]$MaxWaitSeconds = 600,
    [int]$IntervalSeconds = 10
)

$ErrorActionPreference = "Stop"

Write-Host "Waiting for Argo CD application '$AppName' to sync and become healthy..."
Write-Host "Max wait time: $MaxWaitSeconds seconds"

$startTime = Get-Date
$endTime = $startTime.AddSeconds($MaxWaitSeconds)

$attempt = 1
while ((Get-Date) -lt $endTime) {
    Write-Host "Attempt $attempt (elapsed: $([Math]::Round(((Get-Date) - $startTime).TotalSeconds))s)..."
    
    try {
        # Get Argo CD app status
        $appJson = kubectl get application "$AppName" -n $Namespace -o json 2>$null
        
        if ($LASTEXITCODE -eq 0 -and $appJson) {
            $app = $appJson | ConvertFrom-Json
            
            $syncStatus = $app.status.sync.status
            $healthStatus = $app.status.health.status
            
            Write-Host "  Sync: $syncStatus, Health: $healthStatus"
            
            # Check if synced and healthy
            if ($syncStatus -eq "Synced" -and $healthStatus -eq "Healthy") {
                Write-Host "✅ Application is synced and healthy!"
                
                # Show deployed resources
                Write-Host ""
                Write-Host "Deployed resources:"
                $app.status.resources | ForEach-Object {
                    Write-Host "  - $($_.kind)/$($_.name) (namespace: $($_.namespace))"
                }
                
                exit 0
            }
            
            # Check for degraded state
            if ($healthStatus -eq "Degraded") {
                Write-Warning "Application is in Degraded state"
                
                # Show conditions
                if ($app.status.conditions) {
                    Write-Host "Conditions:"
                    $app.status.conditions | ForEach-Object {
                        Write-Host "  - $($_.type): $($_.message)"
                    }
                }
            }
            
            # Check for sync errors
            if ($app.status.operationState.phase -eq "Failed") {
                Write-Error "Sync operation failed"
                if ($app.status.operationState.message) {
                    Write-Host "Error: $($app.status.operationState.message)"
                }
                exit 1
            }
            
        } else {
            Write-Warning "Application '$AppName' not found in namespace '$Namespace'"
        }
        
    } catch {
        Write-Warning "Error checking application status: $_"
    }
    
    if ((Get-Date) -lt $endTime) {
        Write-Host "  Waiting $IntervalSeconds seconds..."
        Start-Sleep -Seconds $IntervalSeconds
    }
    
    $attempt++
}

Write-Error "Timeout waiting for application '$AppName' to become healthy"
Write-Host "Final status check:"
kubectl get application "$AppName" -n $Namespace -o yaml 2>$null || Write-Host "Could not retrieve application"

exit 1
