# Python Workers Dockerfile
# Multi-stage build for smaller production image
# Supports multi-platform builds (amd64, arm64) via Docker buildx
# Supports multiple worker types via WORKER_TYPE environment variable

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
    ffmpeg \
    && rm -rf /var/lib/apt/lists/*

# Install uv for fast dependency management
RUN pip install uv

# Copy shared package first (for layer caching)
COPY services/shared/pyproject.toml /app/shared/
COPY services/shared/README.md /app/shared/
COPY services/shared/shared/ /app/shared/shared/

# Copy workers dependency files
COPY services/workers/pyproject.toml ./
COPY services/workers/README.md ./

# Create virtual environment and install dependencies
RUN uv venv /app/.venv
ENV PATH="/app/.venv/bin:$PATH"

# Install shared package and workers dependencies
RUN cd /app/shared && uv pip install --system -e .
RUN uv pip install --system -e .

# ================================
# Stage 2: Production image
# ================================
FROM python:3.11-slim AS production

# Labels for container registry
LABEL org.opencontainers.image.source="https://github.com/AshleyHollis/yt-summarizer"
LABEL org.opencontainers.image.description="YT Summarizer Workers"

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ffmpeg \
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
COPY services/shared/pyproject.toml /app/shared/
COPY services/shared/README.md /app/shared/
COPY services/shared/shared/ /app/shared/shared/
COPY services/workers/transcribe/ ./transcribe/
COPY services/workers/summarize/ ./summarize/
COPY services/workers/embed/ ./embed/
COPY services/workers/relationships/ ./relationships/
COPY services/workers/worker_utils/ ./worker_utils/
COPY services/workers/run_all.py ./

# Set Python path
ENV PYTHONPATH="/app:/app/shared"

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

# Run the worker - selects worker based on WORKER_TYPE
CMD ["sh", "-c", "python -m ${WORKER_TYPE}.main"]
