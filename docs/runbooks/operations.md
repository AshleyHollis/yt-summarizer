# Operational Runbook

This runbook covers common operational tasks for the YT Summarizer application.

## Deployment

### Local Development with Aspire

```bash
# Start all services (API, workers, frontend, databases)
aspire run

# The wrapper in tools/aspire.cmd handles background execution
# Check logs at aspire.log in repo root
```

### Manual Deployment (Azure)

```bash
# Build and push container images
docker build -t ytsummarizer-api:latest services/api/
docker build -t ytsummarizer-workers:latest services/workers/

# Deploy to Container Apps (example)
az containerapp update --name api --resource-group yt-summarizer \
  --image ytsummarizer-api:latest

az containerapp update --name workers --resource-group yt-summarizer \
  --image ytsummarizer-workers:latest
```

### Rolling Back

1. **Identify last working version** from Azure Container Apps revisions
2. **Activate previous revision**:
   ```bash
   az containerapp revision activate --name api --revision <revision-name>
   ```
3. **Route traffic to previous revision**:
   ```bash
   az containerapp ingress traffic set --name api --revision-weight <revision-name>=100
   ```

## Scaling

### Scaling Workers

Workers scale based on queue depth. For manual scaling:

```bash
# Scale up workers
az containerapp update --name transcribe-worker --min-replicas 2 --max-replicas 10

# Scale down
az containerapp update --name transcribe-worker --min-replicas 0 --max-replicas 3
```

### Queue Depth Monitoring

Check queue lengths to identify bottlenecks:

```bash
# Using Azure CLI
az storage queue list --account-name <storage-account> --query "[].{name:name, length:approximateMessageCount}"
```

## Health Checks

### API Health

```bash
# Basic health check
curl http://localhost:8000/health

# Readiness (all dependencies)
curl http://localhost:8000/health/ready

# Liveness (simple ping)
curl http://localhost:8000/health/live
```

**Expected Response**:
```json
{
  "status": "healthy",
  "checks": {
    "api": true,
    "database": true,
    "blob_storage": true,
    "queue_storage": true
  }
}
```

### Degraded Status

If status is "degraded", the database may be waking up (serverless cold start). Wait 30-60 seconds and retry.

## Viewing Logs

### Local (Aspire)

```bash
# View Aspire console output
Get-Content aspire.log -Tail 100

# Or use Aspire dashboard at https://localhost:17139
```

### Aspire Dashboard Features

The Aspire dashboard provides rich observability:

- **Resources**: View all running services with health status
- **Traces**: Distributed traces with span links showing producer-consumer relationships
- **Structured Logs**: Searchable logs with trace correlation
- **Console Logs**: Raw stdout/stderr from each service

**Trace Features**:
- **Span Links**: Each worker span links back to its producer span for end-to-end visibility
- **Back Links**: See which downstream services consumed messages from a span
- **Span Events**: Key milestones like `message_received`, `processing_completed`, `message_dead_lettered`
- **Span Attributes**: Rich context including `video.id`, `job.id`, `processing.duration_seconds`

### Azure Log Analytics

```kusto
// All errors in last hour
ContainerAppConsoleLogs_CL
| where ContainerName_s in ("api", "transcribe-worker", "summarize-worker")
| where Log_s contains "error" or Log_s contains "ERROR"
| where TimeGenerated > ago(1h)
| order by TimeGenerated desc

// Failed jobs
ContainerAppConsoleLogs_CL
| where Log_s contains "job.failed"
| where TimeGenerated > ago(24h)
| order by TimeGenerated desc
```

### Structured Log Queries

With structured logging, you can query specific fields:

```kusto
// Videos that failed transcription
ContainerAppConsoleLogs_CL
| where Log_s contains "job.failed" and Log_s contains "transcribe"
| extend parsed = parse_json(Log_s)
| project TimeGenerated, video_id=parsed.video_id, error=parsed.error
```

## Restarting Services

### Restart a Stuck Worker

```bash
# Local (Aspire)
# Stop and restart Aspire

# Azure Container Apps
az containerapp revision restart --name transcribe-worker --revision latest
```

### Restart API

```bash
# Azure Container Apps
az containerapp revision restart --name api --revision latest
```

## Database Operations

### Check Connection

```bash
# Via API debug endpoint (development only)
curl http://localhost:8000/health/debug
```

### Run Migrations

```bash
cd services/shared
alembic upgrade head
```

### Rollback Migration

```bash
alembic downgrade -1
```

## Cost Monitoring

### Key Resources to Watch

| Resource | Metric | Expected Range |
|----------|--------|----------------|
| Azure SQL | DTU/vCore usage | < 50% average |
| Container Apps | CPU/Memory | < 70% average |
| Storage | Blob storage GB | < 10 GB |
| Storage | Queue message count | < 1000 |
| OpenAI | Token usage | Varies by ingestion volume |

### Azure Cost Analysis

```bash
# View costs by resource
az consumption usage list --start-date 2025-01-01 --end-date 2025-01-31 \
  --query "[?contains(resourceGroup, 'yt-summarizer')]"
```

### Expected Monthly Costs (Hobby Scale)

| Component | Estimated Cost |
|-----------|---------------|
| Azure SQL Serverless | $5-15 |
| Container Apps | $5-10 |
| Storage | < $1 |
| OpenAI API | $10-30 (varies by usage) |
| **Total** | **$20-55/month** |

## Common Tasks

### Retry a Failed Video

```bash
curl -X POST http://localhost:8000/api/v1/videos/{video_id}/reprocess
```

### Retry All Failed in Batch

```bash
curl -X POST http://localhost:8000/api/v1/batches/{batch_id}/retry
```

### Clear All Data (Development Only)

```bash
# Drop and recreate database
cd services/shared
alembic downgrade base
alembic upgrade head
```

### Export Video Library

```bash
# Get all videos
curl "http://localhost:8000/api/v1/library/videos?per_page=1000" > videos.json
```
