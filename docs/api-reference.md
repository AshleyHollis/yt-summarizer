# API Reference Guide

The YT Summarizer API is a FastAPI-based REST API that provides endpoints for video ingestion, library browsing, batch management, and copilot queries.

## Base URL

- **Local Development**: `http://localhost:8000`
- **OpenAPI Spec**: `/docs` (Swagger UI) or `/openapi.json`

## Authentication

Currently, the API uses network boundary trust and does not require authentication tokens. All requests from the frontend are trusted.

## Common Headers

| Header | Required | Description |
|--------|----------|-------------|
| `X-Correlation-ID` | No | Unique ID for request tracing. Auto-generated if not provided. |
| `Content-Type` | Yes (POST/PUT) | Must be `application/json` for request bodies. |

## Error Response Format

All error responses follow a consistent structure:

```json
{
  "error": {
    "code": 404,
    "message": "Video not found",
    "correlation_id": "abc-123-xyz",
    "details": [
      {
        "field": "video_id",
        "message": "Video with ID '...' does not exist",
        "type": "not_found"
      }
    ]
  }
}
```

## Rate Limiting

The API itself does not implement rate limiting. However, workers respect YouTube's rate limits with exponential backoff for transcript fetching.

---

## Endpoints

### Health

#### GET /health
Health check with dependency status.

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2026-01-06T12:00:00Z",
  "version": "0.1.0",
  "checks": {
    "api": true,
    "database": true,
    "database_connection": true,
    "blob_storage": true,
    "queue_storage": true
  },
  "uptime_seconds": 3600.5,
  "started_at": "2026-01-06T11:00:00Z"
}
```

#### GET /health/ready
Readiness check for load balancers.

#### GET /health/live
Simple liveness check.

---

### Videos

#### POST /api/v1/videos
Submit a YouTube video for ingestion.

**Request**:
```json
{
  "url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ"
}
```

**Response** (201 Created):
```json
{
  "video_id": "550e8400-e29b-41d4-a716-446655440000",
  "youtube_video_id": "dQw4w9WgXcQ",
  "title": "Video Title",
  "status": "PENDING",
  "job_id": "660e8400-e29b-41d4-a716-446655440001"
}
```

#### GET /api/v1/videos/{videoId}
Get video details including summary and metadata.

#### POST /api/v1/videos/{videoId}/reprocess
Re-queue a video for processing (e.g., after failed transcription).

---

### Jobs

#### GET /api/v1/jobs/{jobId}
Get job status and progress.

**Response**:
```json
{
  "job_id": "660e8400-e29b-41d4-a716-446655440001",
  "video_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "IN_PROGRESS",
  "current_stage": "summarize",
  "stages": [
    {"name": "transcribe", "status": "COMPLETED", "completed_at": "..."},
    {"name": "summarize", "status": "IN_PROGRESS", "started_at": "..."},
    {"name": "embed", "status": "PENDING"},
    {"name": "relationships", "status": "PENDING"}
  ]
}
```

#### GET /api/v1/jobs
List jobs with optional filters.

**Query Parameters**:
- `status`: Filter by status (PENDING, IN_PROGRESS, COMPLETED, FAILED)
- `video_id`: Filter by video ID
- `page`, `per_page`: Pagination

#### POST /api/v1/jobs/{jobId}/retry
Retry a failed job.

---

### Library

#### GET /api/v1/library/videos
Browse videos with filters.

**Query Parameters**:
- `channel_ids`: Comma-separated channel IDs
- `from_date`, `to_date`: Date range filter
- `facet_ids`: Comma-separated facet IDs
- `search`: Text search in title/summary
- `page`, `per_page`: Pagination

#### GET /api/v1/library/videos/{videoId}/segments
Get video segments with timestamps.

#### GET /api/v1/library/channels
List all channels in the library.

#### GET /api/v1/library/facets
List available facets with counts.

---

### Channels

#### POST /api/v1/channels
Fetch videos from a YouTube channel.

**Request**:
```json
{
  "channel_url": "https://www.youtube.com/@channelname"
}
```

---

### Batches

#### POST /api/v1/batches
Create a batch of videos to ingest.

**Request**:
```json
{
  "video_ids": ["vid1", "vid2"],
  "ingest_all": false
}
```

#### GET /api/v1/batches
List all batches.

#### GET /api/v1/batches/{batchId}
Get batch details with item statuses.

#### POST /api/v1/batches/{batchId}/retry
Retry all failed items in a batch.

#### POST /api/v1/batches/{batchId}/items/{videoId}/retry
Retry a specific failed item.

---

### Copilot

#### POST /api/v1/copilot/query
Query the copilot with scope.

**Request**:
```json
{
  "query": "What topics are covered in these videos?",
  "scope": {
    "channels": ["channel-id-1"],
    "dateRange": {
      "from": "2025-01-01",
      "to": "2025-12-31"
    }
  },
  "ai_settings": {
    "useVideoContext": true,
    "useLLMKnowledge": true,
    "useWebSearch": false
  }
}
```

**Response**:
```json
{
  "answer": "Based on your video library...",
  "video_cards": [
    {
      "video_id": "...",
      "title": "...",
      "relevance_score": 0.95,
      "primary_reason": "Directly discusses this topic",
      "explanation": {
        "summary": "This video covers...",
        "key_moments": [
          {"timestamp": "02:30", "text": "..."}
        ]
      }
    }
  ],
  "evidence": [
    {
      "video_id": "...",
      "segment_id": "...",
      "segment_text": "...",
      "start_time": 150,
      "youtube_url": "https://youtu.be/...?t=150"
    }
  ],
  "scope_echo": {
    "channels": ["channel-id-1"],
    "video_count": 42
  },
  "followups": [
    "What are the key differences between...?",
    "Can you explain more about...?"
  ]
}
```

#### POST /api/v1/copilot/search/segments
Vector search for relevant segments.

#### POST /api/v1/copilot/search/videos
Search for relevant videos.

#### POST /api/v1/copilot/topics
Get topics with counts in scope.

#### POST /api/v1/copilot/coverage
Get coverage statistics for scope.

#### GET /api/v1/copilot/neighbors/{videoId}
Get related videos for a specific video.

#### POST /api/v1/copilot/synthesize
Generate structured outputs (learning paths, watch lists).

---

### Threads (Chat Persistence)

#### POST /api/v1/threads
Create a new chat thread.

#### GET /api/v1/threads
List all threads.

#### GET /api/v1/threads/{threadId}
Get thread with messages.

#### POST /api/v1/threads/{threadId}/messages
Add message to thread.

#### DELETE /api/v1/threads/{threadId}
Delete a thread.

---

## Agent Framework (AG-UI)

The API includes a Microsoft Agent Framework endpoint for CopilotKit integration:

- **Endpoint**: `/api/copilotkit` (POST, streaming)
- **Protocol**: AG-UI JSON streaming
- **Agent Name**: `yt-summarizer`

This endpoint is used by the CopilotKit frontend for chat interactions and tool calls.
