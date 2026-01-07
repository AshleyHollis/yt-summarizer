# Kill ORPHANED Next.js dev server processes (stale ones without a parent shell)
# Safe to run - won't kill actively running dev servers

# Get node processes with their command lines and parent info via WMI
$nodeProcesses = Get-CimInstance Win32_Process -Filter "Name = 'node.exe'" -ErrorAction SilentlyContinue

$nextProcesses = $nodeProcesses | Where-Object { $_.CommandLine -match "next" }

# Filter to only orphaned processes (parent no longer exists or is System)
$orphanedProcesses = $nextProcesses | Where-Object {
    $parentId = $_.ParentProcessId
    $parent = Get-Process -Id $parentId -ErrorAction SilentlyContinue
    # Orphaned if: no parent, or parent is System (PID 4), or parent is itself node (cascading orphan)
    -not $parent -or $parentId -eq 4 -or $parentId -eq 0
}

if ($orphanedProcesses) {
    Write-Host "Found $($orphanedProcesses.Count) orphaned Next.js process(es)..."
    $orphanedProcesses | ForEach-Object { 
        $mem = [math]::Round((Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue).WorkingSet64 / 1MB)
        Write-Host "  PID $($_.ProcessId) ($($mem)MB) - killing..."
        Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    }
    Write-Host "Done."
} else {
    Write-Host "No orphaned Next.js processes found."
    if ($nextProcesses) {
        Write-Host ""
        Write-Host "Active Next.js processes (not killed):"
        $nextProcesses | ForEach-Object {
            $mem = [math]::Round((Get-Process -Id $_.ProcessId -ErrorAction SilentlyContinue).WorkingSet64 / 1MB)
            Write-Host "  PID $($_.ProcessId) ($($mem)MB) - has active parent"
        }
    }
}
