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

### 3. Age-Gated Videos

**Symptoms**:
- Error contains: "Age-gated video requires an age-gated transcript worker"
- YouTube asks to sign in to confirm age
- The video may have captions, but anonymous yt-dlp access cannot read metadata/subtitles

**Behavior**:
- Regular transcribe workers do not use browser cookies, even if cookie settings are present.
- Age-gated failures are marked failed and terminal in the queue so regular workers do not keep
  retrying the same message.
- A transcribe worker must declare `TRANSCRIBE_CAPABILITIES=age_gated` before yt-dlp cookie
  settings are honored.

**Local recovery with an existing signed-in browser profile**:
1. Make sure the target video is in a failed state with an age-gated error.
2. Start only one local transcribe worker with an explicit capability and cookie source:
   ```powershell
   cd services/workers
   $env:TRANSCRIBE_CAPABILITIES = "age_gated,local"
   $env:YTDLP_COOKIES_FROM_BROWSER = "edge:Default"
   uv run python -m transcribe
   ```
3. Retry the specific failed transcribe job or batch item.
4. Stop the local worker after the recovery job succeeds.
5. Clear the cookie-related environment variables from the shell.

If the browser cookie database is locked, close the browser or export a temporary Netscape cookie
file and use `YTDLP_COOKIES_FILE` instead. Treat exported cookie files as secrets and delete them
after recovery.

**Production account path**:
- Do not store a personal YouTube browser profile or personal cookies in production.
- For persistent PROD age-gated processing, create a dedicated YouTube account, document its owner
  and recovery path, export or refresh an authenticated cookie/session artifact, store that artifact
  in Azure Key Vault via Terraform, and deploy a dedicated age-gated transcribe worker that has
  `TRANSCRIBE_CAPABILITIES=age_gated`.
- Keep the regular transcribe worker pool unauthenticated so only the dedicated worker has the
  expanded blast radius.

---

### 4. OpenAI API Errors

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

### 5. Database Write Failures

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

### 6. Queue Message Failures

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
