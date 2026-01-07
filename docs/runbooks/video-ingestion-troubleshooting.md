# Video Ingestion Troubleshooting Runbook

This runbook helps investigate and resolve issues with video ingestion in YT Summarizer.

## Finding Traces for a Specific Video

### Using Aspire Dashboard

1. Open Aspire dashboard: http://localhost:15888
2. Go to **Traces** tab
3. Filter by:
   - Service: `api` (for submission)
   - Or search for the video ID in trace attributes
4. Click on a trace to see the full span tree

### Using Log Queries

```bash
# Find all logs for a specific video
Get-Content aspire.log | Select-String -Pattern "video_id.*<VIDEO-ID>"

# Find job status changes
Get-Content aspire.log | Select-String -Pattern "job\.(started|completed|failed).*<VIDEO-ID>"
```

## Common Failure Patterns

### 1. Rate Limiting (YouTube)

**Symptoms**:
- Error: "HTTP Error 429: Too Many Requests"
- Transcribe jobs failing after initial success
- Pattern: works for first few videos, then fails

**Traces Show**:
- `transcribe.youtube.fetch` span has error event
- Error contains "429" or "rate_limit"

**Resolution**:
1. Wait 5-15 minutes for rate limit reset
2. Retry failed jobs:
   ```bash
   curl -X POST http://localhost:8000/api/v1/videos/{video_id}/reprocess
   ```
3. For batch ingestion, add delays between videos

**Prevention**:
- Submit videos in smaller batches (5-10 at a time)
- Use yt-dlp cookies for authenticated requests

---

### 2. Missing Transcripts

**Symptoms**:
- Error: "No captions available"
- Video has no transcript in library
- Transcribe job completes but with empty result

**Traces Show**:
- `transcribe.youtube.fetch` completes but returns no content
- Span attributes show `has_captions: false`

**Resolution**:
1. Check if video has captions on YouTube
2. Check if auto-generated captions are available
3. Consider using Whisper for audio transcription (not currently implemented)

---

### 3. OpenAI API Errors

**Symptoms**:
- Summarize or embed jobs failing
- Error: "OpenAI API error" or "rate limit exceeded"
- Videos stuck at summarize/embed stage

**Traces Show**:
- `summarize.openai.generate` or `embed.openai.batch` span has error
- Error contains OpenAI error details

**Resolution**:
1. Check OpenAI status: https://status.openai.com
2. Verify API key:
   ```bash
   curl https://api.openai.com/v1/models \
     -H "Authorization: Bearer $OPENAI_API_KEY"
   ```
3. Check usage/billing: https://platform.openai.com/usage
4. Retry after issue resolved

---

### 4. Database Write Failures

**Symptoms**:
- Jobs fail at persist step
- Error: "Database connection error" or constraint violation
- Data partially written

**Traces Show**:
- `*.persist` or `*.artifact.persist` span has error
- Database error in span events

**Resolution**:
1. Check database health:
   ```bash
   curl http://localhost:8000/health/ready
   ```
2. Check for constraint violations (duplicate video?)
3. Restart database if connection issues persist

---

### 5. Queue Message Failures

**Symptoms**:
- Job stuck between stages
- Next worker never receives message
- Message in poison queue

**Traces Show**:
- `*.queue.next` span may have error
- No child span in next worker

**Resolution**:
1. Check queue connectivity:
   ```bash
   curl http://localhost:8000/health | jq '.checks.queue_storage'
   ```
2. Check for poison messages in queue
3. Retry failed jobs after fixing underlying issue

---

## Retrying Failed Jobs

### Single Video Retry

```bash
# Via API
curl -X POST http://localhost:8000/api/v1/videos/{video_id}/reprocess

# Response shows new job ID
{
  "job_id": "new-job-id",
  "status": "PENDING"
}
```

### Retry All Failed in Batch

```bash
curl -X POST http://localhost:8000/api/v1/batches/{batch_id}/retry
```

### Retry Specific Job

```bash
curl -X POST http://localhost:8000/api/v1/jobs/{job_id}/retry
```

## Identifying Failed Worker Stage

Each worker stage creates a job record update:

| Stage | Queue | Status Values |
|-------|-------|---------------|
| Transcribe | `transcribe-jobs` | TRANSCRIBING → TRANSCRIBED |
| Summarize | `summarize-jobs` | SUMMARIZING → SUMMARIZED |
| Embed | `embed-jobs` | EMBEDDING → EMBEDDED |
| Relationships | `relationship-jobs` | EXTRACTING_RELATIONSHIPS → COMPLETED |

**Finding the failed stage**:
```bash
# Check job status in API
curl http://localhost:8000/api/v1/jobs/{job_id}

# Response shows stages with status
{
  "stages": [
    {"name": "transcribe", "status": "COMPLETED"},
    {"name": "summarize", "status": "FAILED", "error": "..."},
    {"name": "embed", "status": "PENDING"},
    {"name": "relationships", "status": "PENDING"}
  ]
}
```

## Expected Processing Times

| Stage | Expected Duration | Timeout |
|-------|------------------|---------|
| Transcribe | 5-30 seconds | 2 minutes |
| Summarize | 10-60 seconds | 3 minutes |
| Embed | 5-20 seconds | 2 minutes |
| Relationships | 2-10 seconds | 1 minute |

**Total end-to-end**: 30 seconds - 3 minutes per video

If a stage exceeds these times significantly, check:
1. External service latency (YouTube, OpenAI)
2. Database performance
3. Queue processing delays

## Diagnostic Queries

### Videos Stuck in Processing

```sql
-- Videos started more than 1 hour ago, not completed
SELECT id, youtube_video_id, status, created_at
FROM videos
WHERE status NOT IN ('COMPLETED', 'FAILED')
  AND created_at < DATEADD(hour, -1, GETUTCDATE())
ORDER BY created_at DESC;
```

### Jobs with Errors

```sql
-- Recent failed jobs with error details
SELECT j.id, j.video_id, j.job_type, j.status, j.error_message
FROM jobs j
WHERE j.status = 'FAILED'
  AND j.updated_at > DATEADD(day, -1, GETUTCDATE())
ORDER BY j.updated_at DESC;
```

### Processing Time by Stage

```sql
-- Average processing time per stage (last 24 hours)
SELECT 
  job_type,
  AVG(DATEDIFF(second, started_at, completed_at)) as avg_seconds,
  MAX(DATEDIFF(second, started_at, completed_at)) as max_seconds
FROM jobs
WHERE status = 'COMPLETED'
  AND completed_at > DATEADD(hour, -24, GETUTCDATE())
GROUP BY job_type;
```
