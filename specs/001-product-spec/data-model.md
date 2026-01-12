# Data Model: YT Summarizer

**Feature Branch**: `001-product-spec`  
**Created**: 2025-12-13  
**Status**: Complete

---

## Overview

This document defines the SQL schema for YT Summarizer, including operational tables, content tables with vector embeddings, relationship storage, and provenance tracking.

**Database**: Azure SQL Database (Serverless)  
**Migration Tool**: DbUp  
**Naming Convention**: PascalCase for tables/columns; lowercase with underscores for indexes

---

## Entity Relationship Diagram

```text
┌─────────────┐       ┌─────────────┐
│  Channels   │──────<│   Videos    │
└─────────────┘       └──────┬──────┘
                             │
              ┌──────────────┼──────────────┐
              │              │              │
              ▼              ▼              ▼
       ┌───────────┐  ┌───────────┐  ┌───────────┐
       │  Batches  │  │ Artifacts │  │ Segments  │
       └─────┬─────┘  └───────────┘  └───────────┘
             │
             ▼
       ┌───────────┐
       │   Jobs    │
       └───────────┘

┌─────────────┐       ┌───────────────┐       ┌─────────────┐
│   Videos    │──────<│ Relationships │>──────│   Videos    │
└─────────────┘       └───────────────┘       └─────────────┘

┌─────────────┐       ┌─────────────┐       ┌─────────────┐
│   Videos    │──────<│ VideoFacets │>──────│   Facets    │
└─────────────┘       └─────────────┘       └─────────────┘
```

---

## Core Tables

### Channels

Represents a YouTube channel.

```sql
CREATE TABLE Channels (
    ChannelId UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    YouTubeChannelId NVARCHAR(50) NOT NULL UNIQUE,
    Name NVARCHAR(200) NOT NULL,
    Description NVARCHAR(MAX) NULL,
    ThumbnailUrl NVARCHAR(500) NULL,
    VideoCount INT NOT NULL DEFAULT 0,
    LastSyncedAt DATETIME2 NULL,
    CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    UpdatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
);

CREATE INDEX ix_channels_youtube_id ON Channels (YouTubeChannelId);
```

### Videos

Represents a YouTube video.

```sql
CREATE TABLE Videos (
    VideoId UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    YouTubeVideoId NVARCHAR(20) NOT NULL UNIQUE,
    ChannelId UNIQUEIDENTIFIER NOT NULL,
    Title NVARCHAR(500) NOT NULL,
    Description NVARCHAR(MAX) NULL,
    Duration INT NOT NULL, -- seconds
    PublishDate DATETIME2 NOT NULL,
    ThumbnailUrl NVARCHAR(500) NULL,
    ProcessingStatus NVARCHAR(50) NOT NULL DEFAULT 'pending',
    -- pending | processing | completed | failed
    ErrorMessage NVARCHAR(MAX) NULL,
    CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    UpdatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    CONSTRAINT FK_Videos_Channel FOREIGN KEY (ChannelId) REFERENCES Channels(ChannelId)
);

CREATE INDEX ix_videos_youtube_id ON Videos (YouTubeVideoId);
CREATE INDEX ix_videos_channel ON Videos (ChannelId);
CREATE INDEX ix_videos_publish_date ON Videos (PublishDate);
CREATE INDEX ix_videos_status ON Videos (ProcessingStatus);
```

---

## Batch & Job Tables

### Batches

Groups videos queued together for processing.

```sql
CREATE TABLE Batches (
    BatchId UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    ChannelId UNIQUEIDENTIFIER NULL, -- optional: if batch is from a specific channel
    Name NVARCHAR(200) NULL,
    TotalCount INT NOT NULL DEFAULT 0,
    PendingCount INT NOT NULL DEFAULT 0,
    RunningCount INT NOT NULL DEFAULT 0,
    SucceededCount INT NOT NULL DEFAULT 0,
    FailedCount INT NOT NULL DEFAULT 0,
    CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    CompletedAt DATETIME2 NULL,
    CONSTRAINT FK_Batches_Channel FOREIGN KEY (ChannelId) REFERENCES Channels(ChannelId)
);
```

### BatchItems

Links videos to batches.

```sql
CREATE TABLE BatchItems (
    BatchItemId UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    BatchId UNIQUEIDENTIFIER NOT NULL,
    VideoId UNIQUEIDENTIFIER NOT NULL,
    Status NVARCHAR(50) NOT NULL DEFAULT 'pending',
    -- pending | running | succeeded | failed
    CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    CONSTRAINT FK_BatchItems_Batch FOREIGN KEY (BatchId) REFERENCES Batches(BatchId),
    CONSTRAINT FK_BatchItems_Video FOREIGN KEY (VideoId) REFERENCES Videos(VideoId),
    CONSTRAINT UQ_BatchItems UNIQUE (BatchId, VideoId)
);

CREATE INDEX ix_batchitems_batch ON BatchItems (BatchId);
CREATE INDEX ix_batchitems_video ON BatchItems (VideoId);
```

### Jobs

Processing tasks for videos.

```sql
CREATE TABLE Jobs (
    JobId UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    VideoId UNIQUEIDENTIFIER NOT NULL,
    BatchId UNIQUEIDENTIFIER NULL,
    JobType NVARCHAR(50) NOT NULL,
    -- transcribe | summarize | embed | build_relationships
    Stage NVARCHAR(50) NOT NULL DEFAULT 'queued',
    -- queued | running | completed | failed | dead_lettered
    Status NVARCHAR(50) NOT NULL DEFAULT 'pending',
    -- pending | running | succeeded | failed
    Progress INT NULL, -- percentage 0-100
    ErrorMessage NVARCHAR(MAX) NULL,
    RetryCount INT NOT NULL DEFAULT 0,
    MaxRetries INT NOT NULL DEFAULT 5,
    CorrelationId NVARCHAR(50) NOT NULL,
    StartedAt DATETIME2 NULL,
    CompletedAt DATETIME2 NULL,
    CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    UpdatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    CONSTRAINT FK_Jobs_Video FOREIGN KEY (VideoId) REFERENCES Videos(VideoId),
    CONSTRAINT FK_Jobs_Batch FOREIGN KEY (BatchId) REFERENCES Batches(BatchId)
);

CREATE INDEX ix_jobs_video ON Jobs (VideoId);
CREATE INDEX ix_jobs_batch ON Jobs (BatchId);
CREATE INDEX ix_jobs_status ON Jobs (Status);
CREATE INDEX ix_jobs_correlation ON Jobs (CorrelationId);
CREATE INDEX ix_jobs_created ON Jobs (CreatedAt);
```

---

## Content Tables

### Artifacts

Derived outputs (transcripts, summaries) stored in blob with references.

```sql
CREATE TABLE Artifacts (
    ArtifactId UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    VideoId UNIQUEIDENTIFIER NOT NULL,
    ArtifactType NVARCHAR(50) NOT NULL,
    -- transcript | summary
    ContentHash NVARCHAR(64) NULL, -- SHA-256 for deduplication
    BlobUri NVARCHAR(500) NOT NULL, -- Azure Blob Storage URI
    ContentLength INT NOT NULL, -- bytes
    -- Traceability metadata
    ModelName NVARCHAR(100) NULL,
    ModelVersion NVARCHAR(50) NULL,
    Parameters NVARCHAR(MAX) NULL, -- JSON
    CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    CONSTRAINT FK_Artifacts_Video FOREIGN KEY (VideoId) REFERENCES Videos(VideoId),
    CONSTRAINT UQ_Artifacts UNIQUE (VideoId, ArtifactType)
);

CREATE INDEX ix_artifacts_video ON Artifacts (VideoId);
CREATE INDEX ix_artifacts_type ON Artifacts (ArtifactType);
```

### Segments

Chunks of transcript with embeddings for semantic search.

```sql
CREATE TABLE Segments (
    SegmentId UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    VideoId UNIQUEIDENTIFIER NOT NULL,
    SequenceNumber INT NOT NULL, -- order within video
    StartTime FLOAT NOT NULL, -- seconds
    EndTime FLOAT NOT NULL, -- seconds
    Text NVARCHAR(MAX) NOT NULL,
    ContentHash NVARCHAR(64) NOT NULL, -- SHA-256
    Embedding VECTOR(1536) NOT NULL, -- OpenAI text-embedding-3-small
    -- Traceability
    ModelName NVARCHAR(100) NULL,
    CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    CONSTRAINT FK_Segments_Video FOREIGN KEY (VideoId) REFERENCES Videos(VideoId),
    CONSTRAINT UQ_Segments UNIQUE (VideoId, SequenceNumber)
);

CREATE INDEX ix_segments_video ON Segments (VideoId);
CREATE INDEX ix_segments_times ON Segments (VideoId, StartTime, EndTime);

-- Note: Add VECTOR INDEX later if needed for ANN search
-- CREATE VECTOR INDEX ix_segments_embedding ON Segments (Embedding)
--     WITH (METRIC = 'cosine', ALGORITHM = 'hnsw');
```

---

## Relationship Tables

### Relationships

Connections between videos with evidence and rationale.

```sql
CREATE TABLE Relationships (
    RelationshipId UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    SourceVideoId UNIQUEIDENTIFIER NOT NULL,
    TargetVideoId UNIQUEIDENTIFIER NOT NULL,
    RelationshipType NVARCHAR(50) NOT NULL,
    -- series | progression | same_topic | references | related
    Confidence FLOAT NOT NULL, -- 0.0 to 1.0
    Rationale NVARCHAR(500) NULL, -- LLM-generated explanation
    EvidenceType NVARCHAR(50) NULL,
    -- segment | metadata | title | description
    EvidenceSegmentId UNIQUEIDENTIFIER NULL, -- if evidence is a segment
    EvidenceText NVARCHAR(500) NULL, -- short excerpt for display
    -- Traceability
    ModelName NVARCHAR(100) NULL,
    CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    UpdatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    CONSTRAINT FK_Relationships_Source FOREIGN KEY (SourceVideoId) REFERENCES Videos(VideoId),
    CONSTRAINT FK_Relationships_Target FOREIGN KEY (TargetVideoId) REFERENCES Videos(VideoId),
    CONSTRAINT FK_Relationships_Evidence FOREIGN KEY (EvidenceSegmentId) REFERENCES Segments(SegmentId),
    CONSTRAINT UQ_Relationships UNIQUE (SourceVideoId, TargetVideoId, RelationshipType)
);

CREATE INDEX ix_relationships_source ON Relationships (SourceVideoId);
CREATE INDEX ix_relationships_target ON Relationships (TargetVideoId);
CREATE INDEX ix_relationships_type ON Relationships (RelationshipType);
```

---

## Facets & Tags

### Facets

Generic metadata categories.

```sql
CREATE TABLE Facets (
    FacetId UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    Name NVARCHAR(200) NOT NULL,
    FacetType NVARCHAR(50) NOT NULL,
    -- topic | format | level | language | tool | concept
    Description NVARCHAR(500) NULL,
    CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    CONSTRAINT UQ_Facets UNIQUE (Name, FacetType)
);

CREATE INDEX ix_facets_type ON Facets (FacetType);
CREATE INDEX ix_facets_name ON Facets (Name);
```

### VideoFacets

Many-to-many relationship between videos and facets.

```sql
CREATE TABLE VideoFacets (
    VideoFacetId UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    VideoId UNIQUEIDENTIFIER NOT NULL,
    FacetId UNIQUEIDENTIFIER NOT NULL,
    Confidence FLOAT NULL, -- if extracted by LLM
    EvidenceSegmentId UNIQUEIDENTIFIER NULL,
    CreatedAt DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    CONSTRAINT FK_VideoFacets_Video FOREIGN KEY (VideoId) REFERENCES Videos(VideoId),
    CONSTRAINT FK_VideoFacets_Facet FOREIGN KEY (FacetId) REFERENCES Facets(FacetId),
    CONSTRAINT FK_VideoFacets_Evidence FOREIGN KEY (EvidenceSegmentId) REFERENCES Segments(SegmentId),
    CONSTRAINT UQ_VideoFacets UNIQUE (VideoId, FacetId)
);

CREATE INDEX ix_videofacets_video ON VideoFacets (VideoId);
CREATE INDEX ix_videofacets_facet ON VideoFacets (FacetId);
```

---

## Key Queries

### Semantic Search with Scope

```sql
-- Search segments within scope
SELECT TOP @limit
    s.SegmentId,
    s.VideoId,
    s.Text,
    s.StartTime,
    s.EndTime,
    v.Title AS VideoTitle,
    v.YouTubeVideoId,
    c.Name AS ChannelName,
    VECTOR_DISTANCE('cosine', s.Embedding, @queryEmbedding) AS Distance
FROM Segments s
INNER JOIN Videos v ON s.VideoId = v.VideoId
INNER JOIN Channels c ON v.ChannelId = c.ChannelId
WHERE v.ProcessingStatus = 'completed'
  AND (@channelId IS NULL OR v.ChannelId = @channelId)
  AND (@fromDate IS NULL OR v.PublishDate >= @fromDate)
  AND (@toDate IS NULL OR v.PublishDate <= @toDate)
ORDER BY Distance ASC;
```

### Related Videos (Graph Traversal)

```sql
-- Get related videos with evidence
SELECT
    r.RelationshipType,
    r.Confidence,
    r.Rationale,
    r.EvidenceText,
    v.VideoId,
    v.Title,
    v.YouTubeVideoId,
    v.ThumbnailUrl,
    c.Name AS ChannelName
FROM Relationships r
INNER JOIN Videos v ON r.TargetVideoId = v.VideoId
INNER JOIN Channels c ON v.ChannelId = c.ChannelId
WHERE r.SourceVideoId = @videoId
ORDER BY r.Confidence DESC;
```

### Topics in Scope

```sql
-- Facet counts for current scope
SELECT
    f.Name AS Topic,
    f.FacetType,
    COUNT(DISTINCT vf.VideoId) AS VideoCount
FROM Facets f
INNER JOIN VideoFacets vf ON f.FacetId = vf.FacetId
INNER JOIN Videos v ON vf.VideoId = v.VideoId
WHERE v.ProcessingStatus = 'completed'
  AND (@channelId IS NULL OR v.ChannelId = @channelId)
  AND (@fromDate IS NULL OR v.PublishDate >= @fromDate)
  AND (@toDate IS NULL OR v.PublishDate <= @toDate)
GROUP BY f.FacetId, f.Name, f.FacetType
HAVING COUNT(DISTINCT vf.VideoId) > 0
ORDER BY VideoCount DESC;
```

### Job Timeline

```sql
-- Jobs for a video with timing
SELECT
    j.JobId,
    j.JobType,
    j.Status,
    j.Stage,
    j.Progress,
    j.ErrorMessage,
    j.RetryCount,
    j.StartedAt,
    j.CompletedAt,
    DATEDIFF(SECOND, j.StartedAt, COALESCE(j.CompletedAt, SYSUTCDATETIME())) AS DurationSeconds
FROM Jobs j
WHERE j.VideoId = @videoId
ORDER BY j.CreatedAt ASC;
```

---

## Idempotency Constraints

| Entity | Uniqueness Key | Behavior |
|--------|---------------|----------|
| Channel | `YouTubeChannelId` | Update on conflict |
| Video | `YouTubeVideoId` | Update on conflict |
| Artifact | `VideoId + ArtifactType` | Replace on conflict |
| Segment | `VideoId + SequenceNumber` | Replace on conflict |
| Relationship | `SourceVideoId + TargetVideoId + RelationshipType` | Update confidence/rationale |
| Facet | `Name + FacetType` | Reuse existing |
| VideoFacet | `VideoId + FacetId` | Update confidence |

---

## Migration Strategy

### Alembic Migrations

Migrations are managed with Alembic (Python SQLAlchemy ecosystem).

```text
services/shared/alembic/
├── alembic.ini
├── env.py
└── versions/
    ├── 001_initial_schema.py      -- Channels, Videos
    ├── 002_batches_and_jobs.py    -- Batches, BatchItems, Jobs
    ├── 003_artifacts.py           -- Artifacts table
    ├── 004_segments_with_vectors.py -- Segments with VECTOR column
    ├── 005_relationships.py       -- Relationships table
    └── 006_facets.py              -- Facets, VideoFacets
```

### Migration Execution

```bash
# Development
cd services
source .venv/bin/activate
alembic upgrade head

# Generate new migration from model changes
alembic revision --autogenerate -m "add_new_table"

# Production (via CI/CD)
DATABASE_URL="..." alembic upgrade head
```

### Rollback Strategy

- Each migration has automatic `upgrade()` and `downgrade()` functions
- Alembic generates reversible migrations from SQLAlchemy model diffs
- Use transactions for multi-statement migrations
- Test migrations against production copy before deploy

---

## Storage Estimates

| Entity | Count | Storage (approx) |
|--------|-------|------------------|
| Channels | ~50 | Negligible |
| Videos | ~1,500 | ~5 MB |
| Segments | ~15,000 | ~100 MB (text + embeddings) |
| Relationships | ~5,000 | ~5 MB |
| Facets | ~500 | Negligible |
| Artifacts (SQL refs) | ~3,000 | ~1 MB |
| Blobs (transcripts) | ~1,500 | ~50 MB |

**Total SQL**: ~120 MB (well within Basic tier)
**Total Blob**: ~50 MB

---

**Phase 1 Data Model Complete**: Schema defined and ready for migration scripts.
