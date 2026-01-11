"""Health check and debug endpoints.

Provides comprehensive observability endpoints for monitoring, debugging,
and troubleshooting the API service.

Endpoints:
- /health: Overall health status with dependency checks
- /health/ready: Readiness probe for load balancers
- /health/live: Liveness probe for container orchestrators
- /health/debug: Database connection diagnostics

Debug endpoints (mirrors worker debug endpoints for consistency):
- /debug: Comprehensive debug information
- /debug/env: Environment variables (sanitized)
- /debug/connectivity: External service connectivity tests
- /debug/telemetry: OpenTelemetry configuration status
- /debug/trace-test: Generate a test trace span
"""

import os
import sys
import time
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field

router = APIRouter()


class HealthStatus(BaseModel):
    """Health check response model."""

    status: Literal["healthy", "degraded", "unhealthy"] = Field(description="Overall health status")
    timestamp: datetime = Field(
        default_factory=datetime.utcnow, description="Current server timestamp (UTC)"
    )
    version: str = Field(description="Service version")
    checks: dict[str, bool] = Field(
        default_factory=dict, description="Individual component health checks"
    )
    uptime_seconds: float | None = Field(default=None, description="Seconds since the API started")
    started_at: datetime | None = Field(
        default=None, description="Timestamp when the API started (UTC)"
    )


class ReadinessStatus(BaseModel):
    """Readiness check response model."""

    ready: bool = Field(description="Whether the service is ready to accept requests")
    timestamp: datetime = Field(
        default_factory=datetime.utcnow, description="Current server timestamp (UTC)"
    )
    checks: dict[str, bool] = Field(default_factory=dict, description="Individual readiness checks")


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

    # Calculate uptime from stored startup timestamp
    started_at = getattr(request.app.state, "started_at", None)
    uptime_seconds = None
    if started_at:
        uptime_seconds = (datetime.utcnow() - started_at).total_seconds()

    return HealthStatus(
        status=overall_status,
        version=version,
        checks=checks,
        uptime_seconds=uptime_seconds,
        started_at=started_at,
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
    "/healthz",
    summary="Load Balancer Health Check",
    description="Simple health check endpoint for Azure Load Balancer probes",
    include_in_schema=False,  # Don't show in API docs
)
async def load_balancer_health() -> dict[str, str]:
    """Health check endpoint specifically for Azure Load Balancer.

    Azure LB health probes expect a 200 OK response on /healthz.
    This is separate from Kubernetes readiness/liveness probes.
    """
    return {"status": "ok"}


@router.get(
    "/health/debug",
    summary="Database Debug (Deprecated)",
    description="Database diagnostics. Prefer /debug for comprehensive info or /debug/connectivity for all service checks.",
    deprecated=True,
)
async def debug_check() -> dict:
    """Debug endpoint to check database and environment.

    DEPRECATED: Use /debug for comprehensive debug info or
    /debug/connectivity for all service connectivity checks.
    """
    import os

    result = {
        "note": "This endpoint is deprecated. Use /debug or /debug/connectivity instead.",
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


# =============================================================================
# DEBUG ENDPOINTS - Match worker debug endpoints for consistency
# =============================================================================

# Store API startup time for uptime calculation
_api_started_at = datetime.now(UTC)


@router.get(
    "/debug",
    summary="Debug Information",
    description="Comprehensive debug information including version, uptime, OTEL config, and available endpoints",
)
async def debug_info(request: Request) -> dict[str, Any]:
    """Return detailed debug information for troubleshooting.

    Mirrors the worker /debug endpoint for consistency across services.
    """
    # Calculate uptime
    started_at = getattr(request.app.state, "started_at", _api_started_at)
    uptime = (
        (
            datetime.now(UTC) - started_at.replace(tzinfo=UTC)
            if started_at.tzinfo is None
            else started_at
        ).total_seconds()
        if started_at
        else 0
    )

    # Get OTEL-related env vars (redact sensitive values)
    otel_vars = {}
    for key, value in os.environ.items():
        if key.startswith("OTEL_"):
            if "HEADER" in key or "KEY" in key:
                otel_vars[key] = "[REDACTED]" if value else "(not set)"
            else:
                otel_vars[key] = value

    # Get version from app
    version = getattr(request.app, "version", "0.1.0")

    return {
        "service": "yt-summarizer-api",
        "version": version,
        "uptime_seconds": round(uptime, 2) if uptime else None,
        "started_at": started_at.isoformat() if started_at else None,
        "python_version": sys.version,
        "database_initialized": getattr(request.app.state, "db_initialized", False),
        "database_error": getattr(request.app.state, "db_error", None),
        "otel_environment": otel_vars,
        "endpoints": {
            "health": "/health",
            "ready": "/health/ready",
            "live": "/health/live",
            "debug": "/debug",
            "debug_env": "/debug/env",
            "debug_connectivity": "/debug/connectivity",
            "debug_telemetry": "/debug/telemetry",
            "debug_trace_test": "/debug/trace-test",
        },
    }


@router.get(
    "/debug/env",
    summary="Environment Variables",
    description="Display relevant environment variables (sensitive values redacted)",
)
async def debug_env() -> dict[str, Any]:
    """Return relevant environment variables for debugging.

    Includes OTEL, connection strings, and service-related vars.
    Sensitive values are redacted.
    """
    relevant_prefixes = (
        "OTEL_",
        "SSL_",
        "BLOBS_",
        "QUEUES_",
        "YTSUMMARIZER_",
        "ConnectionStrings__",
        "API_",
        "AZURE_OPENAI_",
        "SERVICE_",
    )

    env_vars = {}
    for key, value in sorted(os.environ.items()):
        if any(key.startswith(prefix) for prefix in relevant_prefixes):
            # Redact sensitive values
            if any(
                sensitive in key.upper()
                for sensitive in ("PASSWORD", "KEY", "SECRET", "HEADER", "AUTH")
            ):
                env_vars[key] = "[REDACTED]" if value else "(not set)"
            else:
                env_vars[key] = value

    return {
        "service": "yt-summarizer-api",
        "environment_variables": env_vars,
        "count": len(env_vars),
    }


@router.get(
    "/debug/connectivity",
    summary="Connectivity Tests",
    description="Test connectivity to external services (database, blob storage, queue storage)",
)
async def debug_connectivity() -> dict[str, Any]:
    """Test connectivity to external services with latency measurements."""
    results = {}

    # Test database connectivity
    try:
        from shared.db.connection import get_db

        start = time.time()
        db = get_db()
        await db.connect()
        elapsed = time.time() - start
        results["database"] = {
            "status": "ok",
            "latency_ms": round(elapsed * 1000, 2),
        }
    except Exception as e:
        results["database"] = {
            "status": "error",
            "error": str(e),
        }

    # Test blob storage connectivity
    try:
        from shared.blob.client import get_container_client

        start = time.time()
        client = get_container_client()
        # Check if container exists (creates it if not)
        if hasattr(client, "exists"):
            await client.exists() if hasattr(client.exists(), "__await__") else client.exists()
        elapsed = time.time() - start
        results["blob_storage"] = {
            "status": "ok",
            "latency_ms": round(elapsed * 1000, 2),
        }
    except Exception as e:
        results["blob_storage"] = {
            "status": "error",
            "error": str(e),
        }

    # Test queue storage connectivity
    try:
        from shared.queue.client import get_queue_client

        start = time.time()
        client = get_queue_client()
        # Try to ensure queue exists
        if hasattr(client, "ensure_queue"):
            client.ensure_queue("test-connectivity")
        elapsed = time.time() - start
        results["queue_storage"] = {
            "status": "ok",
            "latency_ms": round(elapsed * 1000, 2),
        }
    except Exception as e:
        results["queue_storage"] = {
            "status": "error",
            "error": str(e),
        }

    # Test Azure OpenAI connectivity (for copilot/agent features)
    try:
        from shared.config import get_settings

        settings = get_settings()
        openai_settings = settings.openai

        if openai_settings.is_azure_configured:
            import httpx

            start = time.time()
            endpoint = openai_settings.azure_endpoint
            # Make a simple HTTP HEAD request to check endpoint reachability
            # We don't call the API directly to avoid auth issues - just check network connectivity
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.head(endpoint)
            elapsed = time.time() - start
            results["azure_openai"] = {
                "status": "ok",
                "endpoint": endpoint,
                "deployment": openai_settings.azure_deployment,
                "embedding_deployment": openai_settings.azure_embedding_deployment,
                "latency_ms": round(elapsed * 1000, 2),
            }
        else:
            # Check if standard OpenAI is configured
            if openai_settings.api_key and openai_settings.api_key != "not-configured":
                results["azure_openai"] = {
                    "status": "not_configured",
                    "note": "Using standard OpenAI (not Azure)",
                    "model": openai_settings.model,
                }
            else:
                results["azure_openai"] = {
                    "status": "not_configured",
                    "note": "No OpenAI credentials configured",
                }
    except Exception as e:
        results["azure_openai"] = {
            "status": "error",
            "error": str(e),
        }

    all_ok = all(r.get("status") in ("ok", "not_configured") for r in results.values())

    return {
        "service": "yt-summarizer-api",
        "overall_status": "healthy" if all_ok else "degraded",
        "checks": results,
    }


@router.get(
    "/debug/telemetry",
    summary="Telemetry Configuration",
    description="Display OpenTelemetry configuration status and connectivity",
)
async def debug_telemetry() -> dict[str, Any]:
    """Return telemetry configuration status.

    Shows OTLP endpoint, protocol, tracer provider status, and connectivity.
    """
    otel_endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "")
    otel_protocol = os.environ.get("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")
    otel_service = os.environ.get("OTEL_SERVICE_NAME", "yt-summarizer-api")
    ssl_cert_dir = os.environ.get("SSL_CERT_DIR", "")

    # Check if OpenTelemetry packages are available
    otel_packages = {}
    for pkg in ["opentelemetry-api", "opentelemetry-sdk", "opentelemetry-exporter-otlp"]:
        try:
            module_name = pkg.replace("-", "_")
            if pkg == "opentelemetry-api":
                from opentelemetry import trace

                otel_packages[pkg] = "installed"
            elif pkg == "opentelemetry-sdk":
                from opentelemetry.sdk import trace as sdk_trace

                otel_packages[pkg] = "installed"
            elif pkg == "opentelemetry-exporter-otlp":
                from opentelemetry.exporter.otlp.proto.http import trace_exporter

                otel_packages[pkg] = "installed"
        except ImportError:
            otel_packages[pkg] = "not installed"

    # Check tracer provider
    tracer_info = {}
    try:
        from opentelemetry import trace

        provider = trace.get_tracer_provider()
        tracer_info["provider_class"] = type(provider).__name__
        tracer_info["provider_configured"] = type(provider).__name__ != "ProxyTracerProvider"
    except Exception as e:
        tracer_info["error"] = str(e)

    # Test OTLP endpoint connectivity
    otlp_connectivity = {"status": "not tested"}
    if otel_endpoint:
        try:
            import ssl
            import urllib.request

            ctx = ssl.create_default_context()
            if ssl_cert_dir:
                for cert_file in os.listdir(ssl_cert_dir):
                    if cert_file.endswith((".crt", ".pem")):
                        try:
                            ctx.load_verify_locations(os.path.join(ssl_cert_dir, cert_file))
                        except Exception:
                            pass

            req = urllib.request.Request(otel_endpoint, method="HEAD")
            start = time.time()
            try:
                urllib.request.urlopen(req, timeout=5, context=ctx)
                otlp_connectivity = {
                    "status": "ok",
                    "latency_ms": round((time.time() - start) * 1000, 2),
                }
            except urllib.error.HTTPError as e:
                otlp_connectivity = {
                    "status": "ok",
                    "http_code": e.code,
                    "latency_ms": round((time.time() - start) * 1000, 2),
                }
            except urllib.error.URLError as e:
                otlp_connectivity = {"status": "error", "error": str(e.reason)}
        except Exception as e:
            otlp_connectivity = {"status": "error", "error": str(e)}

    return {
        "service": "yt-summarizer-api",
        "configuration": {
            "endpoint": otel_endpoint or "(not set)",
            "protocol": otel_protocol,
            "service_name": otel_service,
            "ssl_cert_dir": ssl_cert_dir or "(not set)",
        },
        "packages": otel_packages,
        "tracer": tracer_info,
        "otlp_connectivity": otlp_connectivity,
    }


@router.get(
    "/debug/trace-test",
    summary="Trace Test",
    description="Generate a test trace span to verify telemetry pipeline",
)
async def debug_trace_test() -> dict[str, Any]:
    """Generate a test trace span to verify telemetry is working.

    Creates a span with the name 'debug_trace_test' and attempts to
    flush it to the OTLP endpoint.
    """
    result = {
        "test_id": f"trace-test-{int(time.time())}",
        "span_created": False,
        "span_exported": False,
        "tracer_info": {},
        "errors": [],
    }

    try:
        from opentelemetry import trace
        from opentelemetry.trace import Status, StatusCode

        # Get tracer info
        provider = trace.get_tracer_provider()
        result["tracer_info"]["provider_class"] = type(provider).__name__

        if type(provider).__name__ == "ProxyTracerProvider":
            result["errors"].append(
                "TracerProvider is ProxyTracerProvider - telemetry may not be configured"
            )

        # Create a test span
        tracer = trace.get_tracer("api-debug-test")
        with tracer.start_as_current_span(
            "debug_trace_test",
            attributes={
                "test.id": result["test_id"],
                "service.name": "yt-summarizer-api",
                "test.type": "api_diagnostic",
            },
        ) as span:
            result["span_created"] = True
            result["span_info"] = {
                "trace_id": format(span.get_span_context().trace_id, "032x"),
                "span_id": format(span.get_span_context().span_id, "016x"),
                "is_recording": span.is_recording(),
            }

            span.add_event("test_event", {"message": "Debug trace test completed"})
            span.set_status(Status(StatusCode.OK))

        # Try to force flush
        try:
            if hasattr(provider, "force_flush"):
                provider.force_flush(timeout_millis=5000)
                result["span_exported"] = True
                result["flush_status"] = "force_flush called successfully"
            else:
                result["flush_status"] = "provider does not support force_flush"
        except Exception as e:
            result["flush_status"] = f"flush error: {e}"
            result["errors"].append(f"Force flush failed: {e}")

    except ImportError as e:
        result["errors"].append(f"OpenTelemetry not available: {e}")
    except Exception as e:
        result["errors"].append(f"Error creating test span: {e}")

    return result
