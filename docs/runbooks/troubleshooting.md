# Troubleshooting Guide

This guide covers how to diagnose and resolve issues in the YT Summarizer application using the built-in observability endpoints.

## Quick Reference: Debug Endpoints

### API Endpoints (http://localhost:8000)

| Endpoint | Purpose |
|----------|---------|
| `/health` | Overall health status with dependency checks |
| `/health/ready` | Readiness probe for load balancers |
| `/health/live` | Simple liveness check |
| `/debug` | Comprehensive debug info (version, uptime, OTEL config) |
| `/debug/env` | Environment variables (sensitive values redacted) |
| `/debug/connectivity` | Test external service connectivity with latency (includes Azure OpenAI) |
| `/debug/telemetry` | OpenTelemetry configuration status |
| `/debug/trace-test` | Generate test trace span to verify telemetry |

> **Note**: `/health/debug` is deprecated. Use `/debug` for comprehensive info or `/debug/connectivity` for service checks.

### Worker Endpoints (ports 8091-8094)

Each worker exposes the same endpoints:

| Worker | Port | Queues Monitored |
|--------|------|-----------------|
| Transcribe Worker | 8091 | transcribe-jobs |
| Summarize Worker | 8092 | summarize-jobs |
| Embed Worker | 8093 | embed-jobs |
| Relationships Worker | 8094 | relationships-jobs |

| Endpoint | Purpose |
|----------|---------|
| `/health` | Worker health with message processing stats |
| `/health/ready` | Readiness with connectivity checks |
| `/health/live` | Simple liveness check |
| `/debug` | Comprehensive debug info (Python version, OTEL config) |
| `/debug/env` | Environment variables |
| `/debug/connectivity` | External service connectivity |
| `/debug/telemetry` | OpenTelemetry configuration |
| `/debug/queue` | Queue connection status and pending messages |
| `/debug/trace-test` | Generate test trace to verify telemetry |

## Common Scenarios

### 1. Service Not Responding

**Symptoms**: API returns 502/503, workers not processing messages

**Diagnosis**:

```powershell
# Check API liveness
curl http://localhost:8000/health/live

# Check worker liveness
curl http://localhost:8091/health/live

# Check comprehensive health
curl http://localhost:8000/health
```

**Resolution**:
- If API is down: Check Aspire dashboard, restart via `aspire run`
- If workers are down: Check individual worker logs in Aspire dashboard

### 2. Database Connection Issues

**Symptoms**: Health check shows `database: false`, API returns 503

**Diagnosis**:

```powershell
# Check database debug info
curl http://localhost:8000/health/debug | ConvertFrom-Json

# Check connectivity with latency
curl http://localhost:8000/debug/connectivity | ConvertFrom-Json
```

**Resolution**:
1. **Cold start**: Wait 30-60 seconds for serverless DB to wake up
2. **Connection string**: Verify `ConnectionStrings__ytsummarizer` in `/debug/env`
3. **SQL Server container**: Check Aspire dashboard for SQL container status

### 3. Messages Not Processing

**Symptoms**: Jobs stuck in "queued" status, no progress

**Diagnosis**:

```powershell
# Check worker queue connectivity
curl http://localhost:8091/debug/queue | ConvertFrom-Json

# Check worker stats
curl http://localhost:8091/health | ConvertFrom-Json
# Look at messages_processed, messages_failed counts
```

**Resolution**:
1. **Queue connection**: Verify connection string in worker's `/debug/env`
2. **Worker stuck**: Check `last_error` in `/debug` response
3. **Queue empty**: Verify messages are being sent to correct queue

### 4. Traces Not Appearing in Dashboard

**Symptoms**: No traces in Aspire dashboard despite requests

**Diagnosis**:

```powershell
# Check API telemetry config
curl http://localhost:8000/debug/telemetry | ConvertFrom-Json

# Check worker telemetry config
curl http://localhost:8091/debug/telemetry | ConvertFrom-Json

# Generate test trace
curl http://localhost:8000/debug/trace-test | ConvertFrom-Json
```

**Look for**:
- `provider_configured: true` (not ProxyTracerProvider)
- `otlp_connectivity.status: "ok"`
- `span_exported: true` in trace-test response

**Resolution**:
1. **OTLP endpoint**: Verify `OTEL_EXPORTER_OTLP_ENDPOINT` is set
2. **SSL certificate**: Check `SSL_CERT_DIR` contains valid cert
3. **Protocol mismatch**: Ensure protocol matches (http/protobuf vs grpc)

### 5. Correlation ID Not Propagating

**Symptoms**: Can't trace request flow across services

**Diagnosis**:

```powershell
# Make request with explicit correlation ID
$headers = @{"X-Correlation-ID" = "test-123"}
Invoke-RestMethod -Uri "http://localhost:8000/health" -Headers $headers -Verbose
# Check response headers for X-Correlation-ID
```

**Resolution**:
1. **Frontend**: Ensure `X-Correlation-ID` header is set on all requests
2. **API**: Check correlation middleware is registered
3. **Logs**: Search for `correlation_id` field in structured logs

### 5a. Using Span Links and Events for Debugging

Workers emit rich telemetry with span links and events that help trace message flow:

**Span Links**: Show producer-consumer relationships
- Each worker span links back to the span that produced the message
- View in Aspire dashboard: Click on a span → "Links" section shows connected spans
- "Back Links" shows which downstream spans linked to this span

**Span Events**: Mark key milestones in message processing

| Event | What It Means |
|-------|---------------|
| `message_received` | Message was dequeued |
| `message_parsed` | Message JSON was valid |
| `processing_started` | Handler began execution |
| `processing_completed` | Handler finished (check status attribute) |
| `message_acknowledged` | Message deleted successfully |
| `message_requeued` | Message will be retried (check new_retry_count) |
| `message_dead_lettered` | Message exceeded retries (check reason) |
| `rate_limit_detected` | Worker hit rate limit (check retry_delay) |

**Diagnosis with MCP Tools**:

```powershell
# List traces with span details
mcp_aspire_list_traces --resourceName=transcribe-worker

# Look for:
# - "links": [{"trace_id": "...", "span_id": "..."}] shows parent span
# - "back_links": [...] shows child spans that linked to this one

# Get logs for a specific trace to see the full story
mcp_aspire_list_trace_structured_logs --traceId=<trace_id>
```

**Common Patterns**:
- Span has link but no back_links → Message was produced but not yet consumed
- Multiple back_links → Message triggered multiple downstream operations
- `processing_completed` event with status=failed → Check exception in logs

### 6. Dead-Lettered Jobs

**Symptoms**: Jobs fail repeatedly and stop processing

**Diagnosis**:

```powershell
# List dead-lettered jobs via API
curl "http://localhost:8000/jobs?status=dead_lettered" | ConvertFrom-Json

# Check worker's last error
curl http://localhost:8091/debug | ConvertFrom-Json
# Look at stats.last_error and stats.last_error_at
```

**Resolution**:
1. **Identify cause**: Check `error_message` on failed jobs
2. **Fix underlying issue**: Address API errors, missing resources, etc.
3. **Retry**: Use API to retry failed jobs after fixing root cause

### 7. Slow Performance

**Symptoms**: High latency, requests timing out

**Diagnosis**:

```powershell
# Check connectivity latencies
curl http://localhost:8000/debug/connectivity | ConvertFrom-Json
# Look at latency_ms for each service

# Check worker message processing rate
curl http://localhost:8091/health | ConvertFrom-Json
# Compare messages_processed vs uptime_seconds
```

**Resolution**:
1. **Database slow**: Check SQL Server container resources
2. **Queue slow**: Check storage account performance
3. **Worker slow**: Check for external API rate limits (OpenAI, YouTube)

### 8. OpenAI/Azure OpenAI Issues

**Symptoms**: Summarization or embedding fails, workers report OpenAI errors

**Diagnosis**:

```powershell
# Check API OpenAI connectivity
curl http://localhost:8000/debug/connectivity | ConvertFrom-Json
# Look for azure_openai section

# Check worker OpenAI configuration
curl http://localhost:8092/debug | ConvertFrom-Json  # Summarize worker
curl http://localhost:8093/debug | ConvertFrom-Json  # Embed worker
# Look for connectivity_checks.openai status
```

**Look for**:
- `azure_openai.status: "ok"` (API can reach Azure OpenAI endpoint)
- `azure_openai.endpoint` matches your configured endpoint
- `azure_openai.deployment` shows your deployment name
- Worker connectivity checks show `openai: true`

**Resolution**:
1. **Not configured**: Set `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_DEPLOYMENT`
2. **Endpoint unreachable**: Check network connectivity to Azure
3. **Authentication failed**: Verify API key is valid and not expired
4. **Deployment not found**: Verify deployment name matches exactly
5. **Rate limited**: Check Azure OpenAI quotas and throttling
6. **Mock mode**: If no credentials, workers generate mock summaries (check logs for "mock summary" warning)

## Aspire Dashboard Tools

The Aspire dashboard provides additional diagnostic capabilities:

### Using Aspire MCP Tools

```
# List all resources and their status
mcp_aspire_list_resources

# View distributed traces
mcp_aspire_list_traces

# View structured logs for a resource
mcp_aspire_list_structured_logs --resourceName=api

# View console logs
mcp_aspire_list_console_logs --resourceName=transcribe-worker
```

### Dashboard Navigation

1. **Resources**: Shows all running services with health status
2. **Traces**: Distributed traces across all services (filter by trace_id)
3. **Logs**: Structured logs with filtering by service/level
4. **Metrics**: Runtime metrics for .NET services

## Log Analysis

### Structured Log Fields

All logs include these fields for correlation:

| Field | Description |
|-------|-------------|
| `correlation_id` | Request-scoped ID from frontend |
| `trace_id` | OpenTelemetry trace ID (32 hex chars) |
| `span_id` | OpenTelemetry span ID (16 hex chars) |
| `service` | Service name (e.g., yt-summarizer-api) |
| `timestamp` | ISO 8601 timestamp |

### Searching Logs

```powershell
# In Aspire dashboard, filter by correlation ID
trace_id:abc123...

# Or by error level
level:error

# Or by service
service:transcribe-worker
```

## Environment Variable Reference

### Required for API

| Variable | Source | Purpose |
|----------|--------|---------|
| `ConnectionStrings__ytsummarizer` | Aspire | SQL Server connection |
| `BLOBS_CONNECTIONSTRING` | Aspire | Azure Blob Storage |
| `QUEUES_CONNECTIONSTRING` | Aspire | Azure Queue Storage |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Aspire | Telemetry endpoint |

### Required for Workers

All of the above, plus:

| Variable | Source | Purpose |
|----------|--------|---------|
| `HEALTH_PORT` | AppHost.cs | Health server port |
| `OPENAI_API_KEY` | secrets.json | OpenAI API access |
| `AZURE_OPENAI_ENDPOINT` | secrets.json | Azure OpenAI endpoint |

## Recovery Procedures

### Restart Single Service

```powershell
# Via Aspire MCP
mcp_aspire_execute_resource_command --resourceName=api --commandName=resource-restart
```

### Restart All Services

```powershell
# Stop and restart Aspire
# The detached wrapper handles cleanup automatically
aspire run
```

### Clear Stuck Messages

If messages are stuck in invisible state:

1. Wait for visibility timeout (default 30s) to expire
2. Or restart the worker to release message locks

### Reset Database (Development Only)

```powershell
# Aspire uses non-persistent SQL Server by default
# Restart Aspire to get a fresh database
aspire run
```

## Monitoring Checklist

Before deploying changes:

- [ ] All health endpoints return 200
- [ ] Database connectivity OK (`/debug/connectivity`)
- [ ] Telemetry configured (`/debug/telemetry` shows provider_configured: true)
- [ ] Test trace exports successfully (`/debug/trace-test`)
- [ ] Worker queues connected (`/debug/queue` on each worker)

## Getting Help

1. **Check this guide** for common scenarios
2. **Check Aspire dashboard** for resource status and logs
3. **Check debug endpoints** for detailed diagnostics
4. **Search traces** by correlation ID to follow request flow
5. **Review structured logs** filtered by error level
