---
name: fastapi-patterns
description: FastAPI and Python backend patterns for the YT Summarizer API service, including async patterns, dependency injection, and testing
license: MIT
---

# FastAPI Patterns

## Purpose
FastAPI and Python backend development patterns specific to the YT Summarizer project, covering async database operations, dependency injection, structured logging, and testing.

## When to Use
- Creating new API endpoints
- Implementing database operations with SQLAlchemy
- Setting up dependency injection
- Adding structured logging
- Writing tests for API endpoints

## Do Not Use When
- Working on frontend code (use react-best-practices if available)
- Infrastructure or deployment tasks (use devops-engineer)
- Database schema design (use database migration tools)

## Project Structure

```
services/api/
├── src/api/
│   ├── main.py              # FastAPI app entry point
│   ├── routes/              # API route handlers
│   ├── models/              # Pydantic models
│   ├── services/            # Business logic
│   └── dependencies.py      # FastAPI dependencies
└── tests/                   # Test files
```

## Core Patterns

### Async Database Operations

**Database Session Dependency**
```python
from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession
from shared.db.connection import get_db

@app.get("/videos")
async def list_videos(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Video))
    return result.scalars().all()
```

**Repository Pattern**
```python
class VideoRepository:
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def get_by_id(self, video_id: str) -> Video | None:
        result = await self.db.execute(
            select(Video).where(Video.id == video_id)
        )
        return result.scalar_one_or_none()
```

### Dependency Injection

**Custom Dependencies**
```python
from fastapi import Depends, HTTPException

async def get_current_user(token: str = Header(...)) -> User:
    user = await validate_token(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    return user

@app.get("/me")
async def get_me(user: User = Depends(get_current_user)):
    return user
```

**Service Dependencies**
```python
async def get_video_service(db: AsyncSession = Depends(get_db)):
    return VideoService(db)

@app.post("/videos")
async def create_video(
    data: VideoCreate,
    service: VideoService = Depends(get_video_service)
):
    return await service.create(data)
```

### Structured Logging

**Logger Setup**
```python
from shared.logging import get_logger

logger = get_logger(__name__)

@app.post("/videos")
async def create_video(data: VideoCreate):
    logger.info("Creating video", video_id=data.id, channel=data.channel_id)
    try:
        result = await process_video(data)
        logger.info("Video created successfully", video_id=data.id)
        return result
    except Exception as e:
        logger.exception("Failed to create video", video_id=data.id, error=str(e))
        raise HTTPException(status_code=500, detail="Processing failed")
```

### Error Handling

**HTTP Exceptions**
```python
from fastapi import HTTPException

@app.get("/videos/{video_id}")
async def get_video(video_id: str, db: AsyncSession = Depends(get_db)):
    video = await repository.get_by_id(video_id)
    if not video:
        raise HTTPException(
            status_code=404,
            detail=f"Video {video_id} not found"
        )
    return video
```

**Global Exception Handler**
```python
from fastapi import Request
from fastapi.responses import JSONResponse

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled exception", path=request.url.path)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )
```

## Testing Patterns

**Endpoint Testing**
```python
import pytest
from fastapi.testclient import TestClient

@pytest.fixture
def client():
    from api.main import app
    return TestClient(app)

def test_list_videos(client):
    response = client.get("/videos")
    assert response.status_code == 200
    assert isinstance(response.json(), list)
```

**Async Testing**
```python
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

@pytest.mark.asyncio
async def test_video_repository(db: AsyncSession):
    repo = VideoRepository(db)
    video = await repo.get_by_id("test-id")
    assert video is None
```

**Mocking Dependencies**
```python
from unittest.mock import Mock, patch

def test_with_mocked_service(client):
    with patch("api.routes.videos.VideoService") as mock:
        mock.return_value.create.return_value = {"id": "123"}
        response = client.post("/videos", json={"url": "..."})
        assert response.status_code == 201
```

## Best Practices

1. **Always use async/await** for I/O operations (DB, HTTP, files)
2. **Use dependency injection** for testability and separation of concerns
3. **Structured logging** with context fields, not string concatenation
4. **Type hints everywhere** - FastAPI uses them for validation/docs
5. **Pydantic models** for request/response validation
6. **Repository pattern** for database access abstraction
7. **Handle exceptions** at appropriate levels with proper HTTP status codes
8. **Use `HTTPException`** for client errors, log unexpected server errors

## Common Commands

**Run API locally**
```bash
cd services/api
uv run uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000
```

**Run tests**
```bash
cd services/api
uv run pytest tests/test_file.py::test_name
uv run pytest tests/ -k "partial_name"
```

**Lint and format**
```bash
cd services/api
uv run ruff check .
uv run ruff format .
```
