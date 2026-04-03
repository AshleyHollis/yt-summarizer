# .squad/templates/new-file.ps1
# Creates a timestamped file in the specified .squad/ subdirectory.
# Agents call this instead of constructing timestamps manually (LLMs are bad at timestamps).
#
# Usage:
#   pwsh .squad/templates/new-file.ps1 -Dir "log" -Slug "milestone-1-complete"
#   pwsh .squad/templates/new-file.ps1 -Dir "decisions/inbox" -Slug "kirk-separation-of-duties" -Content "### Decision..."
#   pwsh .squad/templates/new-file.ps1 -Dir "orchestration-log" -Slug "scotty-inf-01"
#
# Output: Prints the full path to the created file on stdout.
# The caller can then write additional content to the file.

param(
    [Parameter(Mandatory)]
    [ValidateSet("log", "decisions/inbox", "orchestration-log")]
    [string]$Dir,

    [Parameter(Mandatory)]
    [string]$Slug,

    [string]$Content = ""
)

# Find repo root
$teamRoot = git rev-parse --show-toplevel 2>$null
if (-not $teamRoot) {
    Write-Error "Not in a git repository"
    exit 1
}

# Generate UTC timestamp in Squad's standard format
$ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH-mm-ssZ")
$filename = "$ts-$Slug.md"

# Ensure directory exists
$dirPath = Join-Path $teamRoot ".squad" $Dir
if (-not (Test-Path $dirPath)) {
    New-Item -ItemType Directory -Path $dirPath -Force | Out-Null
}

# Create the file
$filePath = Join-Path $dirPath $filename

if ($Content) {
    Set-Content -Path $filePath -Value $Content -Encoding utf8
} else {
    New-Item -ItemType File -Path $filePath -Force | Out-Null
}

# Return the file path so the caller knows where the file was created
Write-Output $filePath
