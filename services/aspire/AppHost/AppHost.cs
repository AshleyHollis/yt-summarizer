var builder = DistributedApplication.CreateBuilder(args);

// OpenAI API Key (required for summarize and embed workers)
var openAiApiKey = builder.AddParameter("openai-api-key", secret: true);

// Azure Storage (Azurite for local dev)
var storage = builder.AddAzureStorage("storage")
    .RunAsEmulator(azurite =>
    {
        // Keep the Azurite container between AppHost runs
        azurite.WithLifetime(ContainerLifetime.Persistent);

        // Persist the *data* (blobs/queues/tables) between runs too
        azurite.WithDataVolume();
    });

var blobs = storage.AddBlobs("blobs");
var queues = storage.AddQueues("queues");

// SQL Server Database
var sql = builder.AddSqlServer("sql")
    .AddDatabase("ytsummarizer");

// Python API (FastAPI) - using uvicorn module
var api = builder.AddPythonModule("api", "../../api", "uvicorn")
    .WithArgs("src.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload")
    .WithHttpEndpoint(port: 8000, targetPort: 8000, name: "http", isProxied: false)
    .WithExternalHttpEndpoints()
    .WithReference(blobs)
    .WithReference(queues)
    .WithReference(sql);

// Next.js Frontend
var web = builder.AddNpmApp("web", "../../../apps/web", "dev")
    .WithHttpEndpoint(port: 3000, targetPort: 3000, name: "http", isProxied: false)
    .WithExternalHttpEndpoints()
    .WithEnvironment("NEXT_PUBLIC_API_URL", "http://localhost:8000");

// Python Workers - each worker has its own directory and virtual environment
// Using AddExecutable to avoid pip install conflicts - venvs are pre-created
var transcribeWorkerPath = Path.GetFullPath(Path.Combine(builder.AppHostDirectory, "../../workers/transcribe"));
var transcribeWorker = builder.AddExecutable("transcribe-worker", 
        Path.Combine(transcribeWorkerPath, ".venv/Scripts/python.exe"),
        transcribeWorkerPath, 
        "__main__.py")
    .WithReference(blobs)
    .WithReference(queues)
    .WithReference(sql);

var summarizeWorkerPath = Path.GetFullPath(Path.Combine(builder.AppHostDirectory, "../../workers/summarize"));
var summarizeWorker = builder.AddExecutable("summarize-worker",
        Path.Combine(summarizeWorkerPath, ".venv/Scripts/python.exe"),
        summarizeWorkerPath,
        "__main__.py")
    .WithReference(blobs)
    .WithReference(queues)
    .WithReference(sql)
    .WithEnvironment("OPENAI_API_KEY", openAiApiKey);

var embedWorkerPath = Path.GetFullPath(Path.Combine(builder.AppHostDirectory, "../../workers/embed"));
var embedWorker = builder.AddExecutable("embed-worker",
        Path.Combine(embedWorkerPath, ".venv/Scripts/python.exe"),
        embedWorkerPath,
        "__main__.py")
    .WithReference(blobs)
    .WithReference(queues)
    .WithReference(sql)
    .WithEnvironment("OPENAI_API_KEY", openAiApiKey);

var relationshipsWorkerPath = Path.GetFullPath(Path.Combine(builder.AppHostDirectory, "../../workers/relationships"));
var relationshipsWorker = builder.AddExecutable("relationships-worker",
        Path.Combine(relationshipsWorkerPath, ".venv/Scripts/python.exe"),
        relationshipsWorkerPath,
        "__main__.py")
    .WithReference(blobs)
    .WithReference(queues)
    .WithReference(sql);

builder.Build().Run();
