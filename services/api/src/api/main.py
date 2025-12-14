"""FastAPI application factory and main entry point."""

from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .middleware import CorrelationIdMiddleware
from .routes import health, jobs, library, videos

# Import shared modules (path will be configured via PYTHONPATH)
try:
    from shared.config import get_settings
    from shared.db.connection import get_db
    from shared.logging.config import configure_logging, get_logger
except ImportError:
    # Fallback for development without shared package installed
    def get_settings():
        class MockSettings:
            service_name = "yt-summarizer-api"
            service_version = "0.1.0"
            environment = "development"
            class api:
                cors_origins = ["http://localhost:3000"]
                debug = True
            class logging:
                level = "INFO"
                json_format = False
        return MockSettings()
    
    def configure_logging(*args, **kwargs):
        pass
    
    def get_logger(name):
        import logging
        return logging.getLogger(name)
    
    def get_db():
        raise NotImplementedError("Database not available in fallback mode")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler for startup/shutdown events."""
    import asyncio
    logger = get_logger(__name__)
    settings = get_settings()
    
    # Startup
    logger.info(
        "Starting application",
        service=settings.service_name,
        version=settings.service_version,
        environment=settings.environment,
    )
    
    # Initialize database connection and create tables with retry
    max_retries = 30
    retry_delay = 2  # seconds
    for attempt in range(max_retries):
        try:
            db = get_db()
            await db.connect()
            await db.create_tables()
            logger.info("Database connection established and tables created")
            break
        except Exception as e:
            if attempt < max_retries - 1:
                logger.warning(f"Database initialization attempt {attempt + 1}/{max_retries} failed: {e}. Retrying in {retry_delay}s...")
                await asyncio.sleep(retry_delay)
            else:
                logger.error(f"Failed to initialize database after {max_retries} attempts: {e}")
                # Continue anyway - let individual requests fail with better error messages
    
    yield
    
    # Shutdown
    logger.info("Shutting down application")
    
    # Close database connections
    try:
        db = get_db()
        await db.close()
    except Exception:
        pass


def create_app() -> FastAPI:
    """Create and configure the FastAPI application.
    
    Returns:
        Configured FastAPI application instance.
    """
    settings = get_settings()
    
    # Configure logging
    configure_logging(
        level=settings.logging.level,
        json_format=settings.logging.json_format,
        service_name=settings.service_name,
    )
    
    # Create app
    app = FastAPI(
        title="YT Summarizer API",
        description="AI-powered YouTube video summarization service",
        version=settings.service_version,
        docs_url="/docs" if settings.api.debug else None,
        redoc_url="/redoc" if settings.api.debug else None,
        openapi_url="/openapi.json" if settings.api.debug else None,
        lifespan=lifespan,
    )
    
    # Add middleware (order matters - first added = last executed)
    
    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.api.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Correlation-ID"],
    )
    
    # Correlation ID middleware
    app.add_middleware(CorrelationIdMiddleware)
    
    # Register exception handlers
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(RequestValidationError, validation_exception_handler)
    app.add_exception_handler(Exception, general_exception_handler)
    
    # Register routes
    app.include_router(health.router, tags=["Health"])
    app.include_router(videos.router)
    app.include_router(jobs.router)
    app.include_router(library.router)
    
    return app


async def http_exception_handler(
    request: Request,
    exc: StarletteHTTPException,
) -> JSONResponse:
    """Handle HTTP exceptions."""
    correlation_id = getattr(request.state, "correlation_id", None)
    
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": exc.status_code,
                "message": exc.detail,
                "correlation_id": correlation_id,
            }
        },
        headers={"X-Correlation-ID": correlation_id} if correlation_id else {},
    )


async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """Handle request validation errors."""
    correlation_id = getattr(request.state, "correlation_id", None)
    
    # Format validation errors
    errors = []
    for error in exc.errors():
        errors.append({
            "field": ".".join(str(loc) for loc in error["loc"]),
            "message": error["msg"],
            "type": error["type"],
        })
    
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": 422,
                "message": "Validation Error",
                "details": errors,
                "correlation_id": correlation_id,
            }
        },
        headers={"X-Correlation-ID": correlation_id} if correlation_id else {},
    )


async def general_exception_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    """Handle unexpected exceptions."""
    import traceback
    logger = get_logger(__name__)
    correlation_id = getattr(request.state, "correlation_id", None)
    
    # Log the exception
    logger.exception(
        "Unhandled exception",
        correlation_id=correlation_id,
        path=request.url.path,
        method=request.method,
    )
    
    # Include detailed error info in development
    error_detail = f"{type(exc).__name__}: {str(exc)}"
    
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": 500,
                "message": "Internal Server Error",
                "detail": error_detail,
                "traceback": traceback.format_exc(),
                "correlation_id": correlation_id,
            }
        },
        headers={"X-Correlation-ID": correlation_id} if correlation_id else {},
    )


# Create the app instance
app = create_app()
