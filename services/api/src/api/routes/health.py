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
    description="Check if the service is running and get version info",
)
async def health_check(request: Request) -> HealthStatus:
    """Health check endpoint for liveness probes.
    
    Returns basic health status without checking dependencies.
    Used by container orchestrators to verify the service is running.
    """
    # Get version from app or settings
    version = getattr(request.app, "version", "0.1.0")
    
    return HealthStatus(
        status="healthy",
        version=version,
        checks={
            "api": True,
        },
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
    
    # TODO: Add actual dependency checks
    # Example:
    # try:
    #     db = get_db()
    #     await db.connect()
    #     checks["database"] = True
    # except Exception:
    #     checks["database"] = False
    #     all_ready = False
    
    # For now, just check that the API is running
    checks["api"] = True
    
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
