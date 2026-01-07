# Script to start all YT Summarizer workers
# This script sets up the environment variables and runs the workers

param(
    [int]$BlobPort = 32773,
    [int]$QueuePort = 32774,
    [int]$TablePort = 32775,
    [int]$SqlPort = 32798
)

$azurite_conn = "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://127.0.0.1:${BlobPort}/devstoreaccount1;QueueEndpoint=http://127.0.0.1:${QueuePort}/devstoreaccount1;TableEndpoint=http://127.0.0.1:${TablePort}/devstoreaccount1"
$sql_conn = "Server=localhost,${SqlPort};Database=ytsummarizer;User Id=sa;Password=YourStrong@Passw0rd;TrustServerCertificate=True"

# Set environment variables at machine level for the current session
[System.Environment]::SetEnvironmentVariable("ConnectionStrings__blobs", $azurite_conn, [System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("ConnectionStrings__queues", $azurite_conn, [System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("ConnectionStrings__sql", $sql_conn, [System.EnvironmentVariableTarget]::Process)
[System.Environment]::SetEnvironmentVariable("AZURE_HTTP_LOGGING_LEVEL", "WARNING", [System.EnvironmentVariableTarget]::Process)

$workersPath = "c:\Users\ashle\Source\GitHub\AshleyHollis\yt-summarizer\services\workers"
$pythonExe = "$workersPath\.venv\Scripts\python.exe"

Write-Host "Starting workers with ports: Blob=$BlobPort, Queue=$QueuePort, Table=$TablePort, SQL=$SqlPort"

# Start workers using cmd to preserve environment
$workers = @("transcribe", "summarize", "embed", "relationships")

foreach ($worker in $workers) {
    Write-Host "Starting $worker worker..."
    $startInfo = New-Object System.Diagnostics.ProcessStartInfo
    $startInfo.FileName = $pythonExe
    $startInfo.Arguments = "-m $worker"
    $startInfo.WorkingDirectory = $workersPath
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.EnvironmentVariables["ConnectionStrings__blobs"] = $azurite_conn
    $startInfo.EnvironmentVariables["ConnectionStrings__queues"] = $azurite_conn
    $startInfo.EnvironmentVariables["ConnectionStrings__sql"] = $sql_conn
    $startInfo.EnvironmentVariables["AZURE_HTTP_LOGGING_LEVEL"] = "WARNING"
    
    $process = New-Object System.Diagnostics.Process
    $process.StartInfo = $startInfo
    $process.Start() | Out-Null
    Write-Host "  Started $worker with PID $($process.Id)"
}

Write-Host "All workers started!"
