# Python Workers Dockerfile
# Multi-stage build for smaller production image
# Supports multiple worker types via environment variable

# ================================
# Stage 1: Build dependencies
# ================================
FROM python:3.11-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    ffmpeg \
    && rm -rf /var/lib/apt/lists/*

# Install uv for fast dependency management
RUN pip install uv

# Copy dependency files
COPY pyproject.toml ./
COPY ../shared/pyproject.toml ../shared/

# Create virtual environment and install dependencies
RUN uv venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"
RUN uv pip install -e . -e ../shared

# ================================
# Stage 2: Production image
# ================================
FROM python:3.11-slim as production

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ffmpeg \
    gnupg2 \
    unixodbc \
    && curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add - \
    && curl https://packages.microsoft.com/config/debian/11/prod.list > /etc/apt/sources.list.d/mssql-release.list \
    && apt-get update \
    && ACCEPT_EULA=Y apt-get install -y --no-install-recommends msodbcsql18 \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /app/.venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"

# Copy application code
COPY . ./
COPY ../shared/ ../shared/

# Set Python path
ENV PYTHONPATH="/app:/app/../shared"

# Create non-root user
RUN useradd --create-home --shell /bin/bash appuser
USER appuser

# Worker type is set via environment variable
# WORKER_TYPE: transcribe | summarize | embed | relationships
ENV WORKER_TYPE=transcribe

# Health check - worker-specific health endpoint would be needed
# For now, just check if the process is running
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD pgrep -f "python -m ${WORKER_TYPE}" || exit 1

# Run the worker
# The entrypoint script selects the worker based on WORKER_TYPE
CMD ["sh", "-c", "python -m ${WORKER_TYPE}.main"]
