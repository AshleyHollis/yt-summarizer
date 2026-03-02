# Ripley — History

## Project Context
- **Project**: YT Summarizer — YouTube video knowledge library
- **Stack**: Python/FastAPI, SQLAlchemy, Azure Queue Storage, yt-dlp, Auth0
- **User**: Ashley Hollis

## Key Knowledge
- DB connection: get_database_url() checks ConnectionStrings__ytsummarizer (Aspire) FIRST, then DATABASE_URL (.env fallback).
- CORS origins configured in services/shared/shared/config.py (ApiSettings.cors_origins).
- Video quota uses queue-based approach: excess jobs get quota_status='quota_queued'.
- Auth gates use require_auth dependency. Quota: free=5 videos/day + 30 copilot/hr, admin=unlimited.
- RecoveryService provides auto-healing: dead-letter retry, orphan detection, stale job cleanup.
- Login endpoint accepts 'connection' and 'login_hint' query params, forwarded to Auth0.

## Learnings
<!-- Append learnings below -->
