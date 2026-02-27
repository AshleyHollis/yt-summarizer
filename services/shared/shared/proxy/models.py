"""Data models for the proxy service."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime


class ProxyConfigurationError(Exception):
    """Raised when the proxy service is misconfigured.

    This is raised at construction time when PROXY_ENABLED=true but required
    credentials (PROXY_USERNAME / PROXY_PASSWORD) are missing.
    """


@dataclass
class ProxyRequestEntry:
    """Record of a single proxied yt-dlp request.

    Created by ProxyService.log_request() and persisted to the
    proxy_request_logs table via an async DB session.
    """

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    job_id: str | None = None
    """FK to the Job that triggered this request (nullable for API-originated calls)."""

    service: str = "unknown"
    """Originating service name, e.g. 'transcribe-worker', 'api'."""

    operation: str = "unknown"
    """High-level operation label, e.g. 'fetch_transcript', 'fetch_channel_videos'."""

    proxy_url_masked: str = ""
    """Proxy URL with password replaced by '***' for safe logging."""

    success: bool = False
    duration_ms: int = 0
    error_type: str | None = None
    """Exception class name on failure, e.g. 'DownloadError'."""

    bytes_used: int = 0
    """Approximate bytes consumed (populated when known, otherwise 0)."""

    created_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ProxyUsageSummary:
    """Aggregated proxy usage statistics returned by ProxyService.get_usage_summary()."""

    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    total_bytes_used: int = 0
    total_duration_ms: int = 0

    @property
    def success_rate(self) -> float:
        """Return success rate as a fraction in [0.0, 1.0]."""
        if self.total_requests == 0:
            return 1.0
        return self.successful_requests / self.total_requests

    @property
    def average_duration_ms(self) -> float:
        """Return average request duration in milliseconds."""
        if self.total_requests == 0:
            return 0.0
        return self.total_duration_ms / self.total_requests
