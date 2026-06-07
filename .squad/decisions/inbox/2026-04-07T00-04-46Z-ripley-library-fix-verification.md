# Decision: noload all lazy-selectin Video relationships in library_service

**Date:** 2026-04-07
**Author:** Ripley (Backend)
**PR:** #190 (feature/openclaw-integration)

## Context

`Video` model has three `lazy="selectin"` relationships: `segments`, `artifacts`, `jobs`.
SQLAlchemy auto-fires a SELECT for every `lazy="selectin"` relationship at load time, not at
attribute access time. The original fix in eebb47b5 only added `noload(Video.segments)` to
`_build_video_query`, leaving `artifacts` and `jobs` to auto-fire, and left `get_video_detail`
entirely unprotected.

## Decision

1. **`_build_video_query`**: explicitly noload `segments`, `artifacts`, AND `jobs`.
2. **`get_video_detail`**: explicitly noload `segments` and `jobs` (artifacts is intentionally
   loaded via `selectinload` for the detail view).
3. **`k8s/base/migration-job.yaml`**: change `argocd.argoproj.io/hook` from `Sync` to `PreSync`.
   The old `Sync` + `sync-wave: "1"` configuration ran the migration job AFTER default-wave (0)
   resources (including API pods), creating a window where the API started before migrations ran.
   `PreSync` guarantees migrations complete before any sync-phase resource is applied.

## Rule Going Forward

Any query loading a `Video` (or any model with `lazy="selectin"` relationships) MUST explicitly
noload every relationship not needed for that query. "Not accessing the attribute" does NOT
prevent the auto-fire — override loading must be explicit.

## Migration 015 Idempotency Note

Migration 015 (`op.add_column`) is not idempotent at the SQL level but is safe because Alembic's
`alembic_version` table prevents re-runs. No change needed; this is standard Alembic practice.
