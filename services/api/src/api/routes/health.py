"""Health check endpoint."""

from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

router = APIRouter()


class HealthStatus(BaseModel):
    """Health check response model."""
    
    status: Literal["healthy", "degraded", "unhealthy"] = Field(
        description="Overall health status"
    )
    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="Current server timestamp (UTC)"
    )
    version: str = Field(
        description="Service version"
    )
    checks: dict[str, bool] = Field(
        default_factory=dict,
        description="Individual component health checks"
    )


class ReadinessStatus(BaseModel):
    """Readiness check response model."""
    
    ready: bool = Field(
        description="Whether the service is ready to accept requests"
    )
    timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="Current server timestamp (UTC)"
    )
    checks: dict[str, bool] = Field(
        default_factory=dict,
        description="Individual readiness checks"
    )


@router.get(
    "/health",
    response_model=HealthStatus,
    summary="Health Check",
    description="Check if the service is running and get version info with dependency status",
)
async def health_check(request: Request) -> HealthStatus:
    """Health check endpoint for liveness probes.
    
    Returns health status including dependency checks for database, 
    blob storage, and queue services.
    Used by container orchestrators and monitoring systems.
    """
    # Get version from app or settings
    version = getattr(request.app, "version", "0.1.0")
    
    checks = {"api": True}
    overall_status = "healthy"
    
    # Check database status from app state (set during startup)
    db_initialized = getattr(request.app.state, "db_initialized", False)
    checks["database"] = db_initialized
    
    # Try to verify database connection is still alive
    if db_initialized:
        try:
            from shared.db.connection import get_db
            db = get_db()
            await db.connect()
            checks["database_connection"] = True
        except Exception:
            checks["database_connection"] = False
            overall_status = "degraded"
    else:
        overall_status = "degraded"
    
    # Check blob storage connectivity
    try:
        from shared.blob.client import get_connection_string as get_blob_conn
        get_blob_conn()  # Verify connection string is available
        checks["blob_storage"] = True
    except Exception:
        checks["blob_storage"] = False
        # Blob storage is optional for basic health, don't degrade
    
    # Check queue storage connectivity
    try:
        from shared.queue.client import get_connection_string as get_queue_conn
        get_queue_conn()  # Verify connection string is available
        checks["queue_storage"] = True
    except Exception:
        checks["queue_storage"] = False
        # Queue storage is optional for basic health, don't degrade
    
    return HealthStatus(
        status=overall_status,
        version=version,
        checks=checks,
    )


@router.get(
    "/health/ready",
    response_model=ReadinessStatus,
    summary="Readiness Check",
    description="Check if the service is ready to accept requests",
)
async def readiness_check(request: Request) -> ReadinessStatus:
    """Readiness check endpoint for readiness probes.
    
    Checks that all dependencies (database, storage, etc.) are available.
    Used by load balancers to determine if traffic should be sent to this instance.
    """
    checks = {}
    all_ready = True
    
    # Check if API is running
    checks["api"] = True
    
    # Check database initialization status from startup
    db_initialized = getattr(request.app.state, "db_initialized", False)
    checks["database_init"] = db_initialized
    if not db_initialized:
        all_ready = False
    
    # Also verify we can actually connect to the database
    if db_initialized:
        try:
            from shared.db.connection import get_db
            db = get_db()
            await db.connect()
            checks["database_connection"] = True
        except Exception as e:
            checks["database_connection"] = False
            checks["database_error"] = str(e)[:100]  # Truncate error message
            all_ready = False
    
    return ReadinessStatus(
        ready=all_ready,
        checks=checks,
    )


@router.get(
    "/health/live",
    summary="Liveness Check",
    description="Simple liveness check - returns 200 if service is alive",
)
async def liveness_check() -> dict[str, str]:
    """Simple liveness check endpoint.
    
    Returns a minimal response to indicate the service is running.
    """
    return {"status": "ok"}


@router.get(
    "/health/debug",
    summary="Debug Check",
    description="Debug endpoint to check database connection and environment",
)
async def debug_check() -> dict:
    """Debug endpoint to check database and environment."""
    import os
    
    result = {
        "connection_strings": {},
        "database": {"status": "unknown", "error": None, "url": None},
    }
    
    # Check for connection strings
    for key in ["DATABASE_URL", "ConnectionStrings__ytsummarizer", "ConnectionStrings__sql"]:
        val = os.environ.get(key)
        if val:
            # Mask password
            result["connection_strings"][key] = val[:30] + "..." if len(val) > 30 else val
    
    # Try to get database URL and connect
    try:
        from shared.db.connection import get_database_url, get_db
        url = get_database_url()
        # Mask password in URL
        if "@" in url:
            parts = url.split("@")
            masked_url = parts[0][:20] + "...@" + parts[1]
        else:
            masked_url = url[:50] + "..."
        result["database"]["url"] = masked_url
        
        # Try to connect
        db = get_db()
        await db.connect()
        result["database"]["status"] = "connected"
        
        # Try to create tables
        try:
            await db.create_tables()
            result["database"]["tables_created"] = True
        except Exception as te:
            result["database"]["tables_created"] = False
            result["database"]["tables_error"] = str(te)
    except Exception as e:
        result["database"]["status"] = "error"
        result["database"]["error"] = str(e)
    
    return result
