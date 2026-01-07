# Incident Response Runbook

This runbook provides guidance for responding to incidents in the YT Summarizer application.

## Severity Levels

| Level | Description | Examples | Response Time |
|-------|-------------|----------|---------------|
| **P1** | All ingestion failing, app completely down | API unreachable, DB completely down | Immediate |
| **P2** | Specific worker down, partial functionality | One worker failing, queue backup | Within 1 hour |
| **P3** | Degraded performance, non-critical issues | Slow responses, intermittent errors | Within 4 hours |

## First Responder Checklist

When an incident is reported, follow this checklist:

### 1. Assess Impact
- [ ] Can users access the web app?
- [ ] Can users submit new videos?
- [ ] Are existing videos viewable in the library?
- [ ] Is the copilot responding?

### 2. Check Health Endpoints
```bash
# API health
curl http://localhost:8000/health

# Readiness
curl http://localhost:8000/health/ready
```

### 3. Check Aspire Dashboard
- Open http://localhost:15888 (Aspire dashboard)
- Check resource status (green = healthy, red = failing)
- Review traces for failed operations

### 4. Check Logs
```bash
# Recent errors
Get-Content aspire.log -Tail 100 | Select-String -Pattern "ERROR|error|Exception"
```

### 5. Identify Failing Component
- **API** → Check API logs, database connection
- **Workers** → Check queue depths, worker logs
- **Frontend** → Check browser console, API responses
- **Database** → Check SQL Server status, connection strings

---

## Common Incidents

### Incident: YouTube Rate Limiting

**Symptoms**:
- Transcription jobs failing
- Error messages containing "429" or "too many requests"
- Multiple videos stuck in PENDING

**Investigation**:
```bash
# Check transcribe worker logs for rate limit messages
Get-Content aspire.log | Select-String -Pattern "rate.limit|429"
```

**Resolution**:
1. Wait 5-15 minutes for rate limit to reset
2. Check if cookies/authentication needed
3. Reduce concurrent transcribe workers if needed
4. Jobs will auto-retry with exponential backoff

**Prevention**:
- Add delays between batch video submissions
- Consider using YouTube API key for higher limits

---

### Incident: OpenAI API Errors

**Symptoms**:
- Summarize or embed workers failing
- Error messages about OpenAI API
- Videos stuck at summarize or embed stage

**Investigation**:
```bash
# Check for OpenAI errors
Get-Content aspire.log | Select-String -Pattern "OpenAI|openai|429|rate_limit"
```

**Resolution**:
1. Check OpenAI API status: https://status.openai.com
2. Verify API key is valid:
   ```bash
   curl https://api.openai.com/v1/models \
     -H "Authorization: Bearer $OPENAI_API_KEY"
   ```
3. Check quota/billing at https://platform.openai.com/usage
4. Retry failed jobs after issue resolved

---

### Incident: Database Connection Failures

**Symptoms**:
- API health returns "degraded"
- "Cannot connect to database" errors
- All database-dependent operations failing

**Investigation**:
```bash
# Check database connectivity
curl http://localhost:8000/health/debug
```

**Resolution**:
1. **Serverless cold start**: Wait 30-60 seconds, database is waking up
2. **Connection string issue**: Verify `DATABASE_URL` environment variable
3. **SQL Server down**: Check SQL Server container status in Aspire
4. **Firewall rules**: Verify network connectivity to database

```bash
# Restart SQL container (local)
# Stop and restart Aspire

# Azure
az sql server show --name <server> --resource-group <rg>
```

---

### Incident: Queue Message Poison

**Symptoms**:
- Worker logs show repeated failures for same message
- Jobs stuck in processing
- Dead letter queue growing

**Investigation**:
```bash
# Check dead letter queue
az storage queue list --account-name <storage> --query "[?contains(name, 'poison')]"

# Peek at poison messages
az storage message peek --queue-name transcribe-jobs-poison --num-messages 5
```

**Resolution**:
1. Inspect failing message content
2. Identify root cause (malformed data, missing video, etc.)
3. Fix underlying issue
4. Either:
   - Delete poison messages if unrecoverable
   - Move back to main queue after fix

---

### Incident: Memory or CPU Exhaustion

**Symptoms**:
- Containers restarting frequently
- OOMKilled errors in logs
- Slow response times

**Investigation**:
```bash
# Azure Container Apps metrics
az monitor metrics list --resource <container-app-id> \
  --metric "CpuPercentage,MemoryPercentage" --interval PT1M
```

**Resolution**:
1. Scale up container resources (CPU/memory)
2. Add more replicas to distribute load
3. Identify memory leaks in application code
4. Reduce batch sizes for large operations

---

## Escalation

### When to Escalate

- P1 incident lasting > 15 minutes
- Data corruption detected
- Security breach suspected
- Unable to identify root cause

### Escalation Contacts

| Role | Contact | When |
|------|---------|------|
| On-call Engineer | See schedule | First responder |
| Tech Lead | Slack #incidents | P1 or complex issues |
| Azure Support | Portal ticket | Azure infrastructure issues |
| OpenAI Support | support@openai.com | OpenAI API issues |

## Post-Incident

### Required Actions

1. **Document incident** in incident log
2. **Timeline**: When did it start, when detected, when resolved
3. **Root cause**: What caused the incident
4. **Resolution**: How was it fixed
5. **Action items**: What changes prevent recurrence

### Incident Report Template

```markdown
## Incident Report: [Title]

**Severity**: P1/P2/P3
**Duration**: [Start time] - [End time]
**Impact**: [Description of user impact]

### Timeline
- HH:MM - Incident detected
- HH:MM - Investigation started
- HH:MM - Root cause identified
- HH:MM - Resolution applied
- HH:MM - Incident resolved

### Root Cause
[Description of what caused the incident]

### Resolution
[Description of how the incident was resolved]

### Action Items
- [ ] Item 1
- [ ] Item 2

### Lessons Learned
[What can we do differently next time]
```
