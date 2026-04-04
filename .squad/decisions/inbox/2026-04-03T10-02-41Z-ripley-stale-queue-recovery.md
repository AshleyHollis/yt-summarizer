# Decision: Stale Queued Job Re-queue Strategy in RecoveryService

**Date:** 2026-04-03  
**Author:** Ripley (Backend Dev)  
**Status:** Accepted

## Context

17 jobs were stuck in `stage=queued` / `status=pending` since March 22. The root cause was:
1. An invalid `openai-api-key` in Azure Key Vault caused workers to fail silently.
2. Azure Storage Queue messages have a TTL — once expired, no worker can dequeue them.
3. The existing `RecoveryService` only detected orphans via `Video.processing_status == "processing"` + no active jobs, which missed jobs already in `queued`/`pending` with no active queue message.

## Decision

Added a fourth recovery strategy (`_requeue_stale_queued_jobs`) to `RecoveryService`:
- Detects jobs with `stage=queued`, `status=pending`, and `created_at < now - 30m`
- Skips jobs already succeeded or currently running (same job type + video)
- Skips jobs older than 24 hours (`MAX_REQUEUE_AGE_HOURS`) — treated as abandoned
- Caps requeues at `MAX_AUTO_RECOVERIES` (3) per sweep to prevent queue floods
- Reports count in new `queued_job_requeues` field on `RecoveryResult`

## Rationale

- 30-minute threshold aligns with typical Azure Storage Queue message visibility timeout; a job pending longer than that has almost certainly lost its queue message.
- 24-hour age cutoff prevents re-activating truly abandoned work (e.g., from a failed deployment that was rolled back).
- Reusing `MAX_AUTO_RECOVERIES` cap keeps consistent behaviour across all auto-healing strategies.
- No DB schema change required — reuses existing `Job` fields and `_queue_job()` helper.
