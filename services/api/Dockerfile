# Python API Dockerfile
# Multi-stage build for smaller production image
# Supports multi-platform builds (amd64, arm64) via Docker buildx

# syntax=docker/dockerfile:1

# ================================
# Stage 1: Build dependencies
# ================================
FROM --platform=$BUILDPLATFORM python:3.11-slim AS builder

# Build arguments for multi-platform support
ARG TARGETPLATFORM
ARG BUILDPLATFORM

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv for fast dependency management
RUN pip install uv

# Copy shared package first (for layer caching)
COPY services/shared/pyproject.toml /app/shared/
COPY services/shared/README.md /app/shared/
COPY services/shared/shared/ /app/shared/shared/

# Copy API dependency files
COPY services/api/pyproject.toml ./
COPY services/api/README.md ./

# Create virtual environment and install dependencies
RUN uv venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"

# Install shared package and API dependencies
RUN cd /app/shared && uv pip install --system --prerelease=allow -e .
RUN uv pip install --system --prerelease=allow -e .

# ================================
# Stage 2: Production image
# ================================
FROM python:3.11-slim AS production

# Labels for container registry
LABEL org.opencontainers.image.source="https://github.com/AshleyHollis/yt-summarizer"
LABEL org.opencontainers.image.description="YT Summarizer API"

WORKDIR /app

# Install runtime dependencies (ODBC driver for SQL Server)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gnupg2 \
    unixodbc \
    && curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg \
    && echo "deb [arch=amd64,arm64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/debian/12/prod bookworm main" > /etc/apt/sources.list.d/mssql-release.list \
    && apt-get update \
    && ACCEPT_EULA=Y apt-get install -y --no-install-recommends msodbcsql18 \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY services/shared/shared/ /app/shared/shared/
COPY services/api/src/ ./src/

# Set Python path
ENV PYTHONPATH="/app/src:/app/shared"

# Create non-root user
RUN useradd --create-home --shell /bin/bash appuser
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health/live || exit 1

# Run the application
CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]
