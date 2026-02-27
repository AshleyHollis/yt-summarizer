---
name: aspire-orchestration
description: .NET Aspire orchestration patterns for microservices, including AppHost configuration, service discovery, and resource management
license: MIT
---

# Aspire Orchestration

## Purpose
Expert guidance for .NET Aspire orchestration in the YT Summarizer project, covering service configuration, resource management, and best practices for distributed systems.

## When to Use
- Configuring Aspire AppHost for new services
- Adding resources (databases, storage, messaging)
- Setting up service discovery and connection strings
- Debugging orchestration issues
- Understanding Aspire resource patterns

## Do Not Use When
- Working on application logic inside services
- Troubleshooting service-specific bugs
- Configuring CI/CD pipelines (use devops-engineer skill)

## Core Concepts

### AppHost Structure
```csharp
// AppHost.cs - Central orchestration file
var builder = DistributedApplication.CreateBuilder(args);

// Define resources
var db = builder.AddSqlServer("database")
    .AddDatabase("appdb");

var storage = builder.AddAzureStorage("storage")
    .RunAsEmulator();

var queue = builder.AddAzureQueue("queue")
    .WithReference(storage);

// Define services with references
var api = builder.AddProject<Projects.Api>("api")
    .WithReference(db)
    .WithReference(queue);

builder.Build().Run();
```

### Key Patterns

**Resource References**
- Use `WithReference()` to inject connection strings
- Aspire automatically generates connection string environment variables
- Format: `ConnectionStrings__<resource-name>`

**Environment Variables**
- Set per-service via `WithEnvironment("KEY", "value")`
- Use for configuration that varies by environment
- Queue config: `QUEUE_POLL_INTERVAL`, `QUEUE_BATCH_SIZE`

**Service Discovery**
- Services reference each other by resource name
- URLs injected automatically: `services__<name>__http__0`
- Use `WithReference(otherService)` for HTTP clients

## Common Operations

### Add a New Service
```csharp
builder.AddProject<Projects.NewService>("new-service")
    .WithReference(existingDb)
    .WithReference(existingQueue)
    .WithEnvironment("CUSTOM_SETTING", "value");
```

### Configure Queue Workers
```csharp
// In AppHost.cs
builder.AddProject<Projects.TranscribeWorker>("transcribe-worker")
    .WithReference(queue)
    .WithEnvironment("QUEUE_POLL_INTERVAL", "10")
    .WithEnvironment("QUEUE_BATCH_SIZE", "32");
```

### Database Migrations
- Migration job defined in AppHost
- Runs before dependent services start
- Uses `builder.AddExecutable()` or `builder.AddProject()`

## Debugging

**Check Resource Status**
```bash
aspire run  # Start with dashboard
# Access dashboard at http://localhost:15171
```

**View Logs**
```powershell
Get-Content aspire.log -Tail 50
```

**Common Issues**
- Connection string not injected: Check `WithReference()` calls
- Service won't start: Verify resource dependencies
- Port conflicts: Aspire auto-assigns, check dashboard

## Best Practices

1. **Always restart Aspire** after changing AppHost.cs
2. **Use resource references** instead of hardcoded connection strings
3. **Set queue config** via environment variables in AppHost
4. **One database per service** pattern for isolation
5. **Health checks** on all services for orchestration awareness
