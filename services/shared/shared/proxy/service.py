"""Proxy service for routing yt-dlp requests through Webshare rotating residential proxies."""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

import httpx
import structlog

from shared.proxy.models import ProxyConfigurationError, ProxyRequestEntry, ProxyUsageSummary

if TYPE_CHECKING:
    from shared.config import ProxySettings

logger = structlog.get_logger(__name__)

# Webshare rotating residential gateway
WEBSHARE_GATEWAY_HOST = "p.webshare.io"
WEBSHARE_GATEWAY_PORT = 80


class ProxyService:
    """Manages Webshare rotating residential proxy access for yt-dlp calls.

    When PROXY_ENABLED=false (default), all methods are no-ops and get_ydl_opts()
    returns an empty dict. This allows callers to unconditionally merge the result
    into their yt-dlp opts dict without any conditional branching.

    The proxy URL format used by Webshare rotating residential:
        http://{username}-backbone:{password}@p.webshare.io:80

    Usage::

        proxy_service = ProxyService(settings.proxy)

        # Get opts to merge into yt-dlp ydl_opts
        ydl_opts = {
            "quiet": True,
            **proxy_service.get_ydl_opts(),
        }

        # Log the outcome of a proxied request
        async with proxy_service.log_request(job_id="...", service="transcribe-worker",
                                              operation="fetch_transcript") as entry:
            # entry.success and entry.error_type are set automatically on exit
            ...
    """

    def __init__(self, settings: ProxySettings) -> None:
        self._settings = settings
        self._lock = asyncio.Lock()

        # In-memory usage counters (reset on restart; DB is the durable store)
        self._total_requests: int = 0
        self._successful_requests: int = 0
        self._failed_requests: int = 0
        self._total_bytes_used: int = 0
        self._total_duration_ms: int = 0

        if settings.enabled:
            if not settings.username or not settings.password:
                raise ProxyConfigurationError(
                    "PROXY_ENABLED=true but PROXY_USERNAME and/or PROXY_PASSWORD are not set. "
                    "All Webshare secrets must be provisioned via Azure Key Vault."
                )
            logger.info(
                "proxy_service.initialized",
                gateway=f"{WEBSHARE_GATEWAY_HOST}:{WEBSHARE_GATEWAY_PORT}",
                username_masked=f"{settings.username[:4]}***",
            )
        else:
            logger.info("proxy_service.disabled", reason="PROXY_ENABLED=false")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        """Return True if the proxy is currently enabled."""
        return self._settings.enabled

    def get_proxy_url(self) -> str | None:
        """Return the full proxy URL, or None if disabled.

        The password is included so this value must NOT be logged.
        Use proxy_url_masked for logging.
        """
        if not self._settings.enabled:
            return None
        return (
            f"http://{self._settings.username}-backbone:{self._settings.password}"
            f"@{WEBSHARE_GATEWAY_HOST}:{WEBSHARE_GATEWAY_PORT}"
        )

    def get_proxy_url_masked(self) -> str | None:
        """Return the proxy URL with the password replaced by '***', or None if disabled."""
        if not self._settings.enabled:
            return None
        return (
            f"http://{self._settings.username}-backbone:***"
            f"@{WEBSHARE_GATEWAY_HOST}:{WEBSHARE_GATEWAY_PORT}"
        )

    def get_ydl_opts(self) -> dict:
        """Return a dict of yt-dlp options to enable proxy routing.

        Returns an empty dict when the proxy is disabled, so callers can
        unconditionally spread this into their ydl_opts::

            ydl_opts = {"quiet": True, **proxy_service.get_ydl_opts()}
        """
        proxy_url = self.get_proxy_url()
        if proxy_url is None:
            return {}
        return {"proxy": proxy_url}

    @asynccontextmanager
    async def log_request(
        self,
        *,
        job_id: str | None = None,
        service: str = "unknown",
        operation: str = "unknown",
    ) -> AsyncGenerator[ProxyRequestEntry, None]:
        """Async context manager that records a single proxied yt-dlp request.

        Sets entry.success=True on clean exit, or entry.success=False and
        entry.error_type=<ExceptionClassName> on exception. Updates in-memory
        counters. The caller is responsible for persisting the entry to the DB
        if desired.

        Example::

            async with proxy_service.log_request(
                job_id=job.id, service="transcribe-worker", operation="fetch_transcript"
            ) as entry:
                result = yt_dlp_call(...)

            # After the block: entry.success, entry.duration_ms, entry.error_type are set
        """
        entry = ProxyRequestEntry(
            job_id=job_id,
            service=service,
            operation=operation,
            proxy_url_masked=self.get_proxy_url_masked() or "",
        )

        start = time.monotonic()
        try:
            yield entry
            entry.success = True
        except Exception as exc:
            entry.success = False
            entry.error_type = type(exc).__name__
            raise
        finally:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            entry.duration_ms = elapsed_ms

            async with self._lock:
                self._total_requests += 1
                if entry.success:
                    self._successful_requests += 1
                else:
                    self._failed_requests += 1
                self._total_duration_ms += elapsed_ms
                self._total_bytes_used += entry.bytes_used

            log = logger.bind(
                job_id=job_id,
                service=service,
                operation=operation,
                success=entry.success,
                duration_ms=elapsed_ms,
                error_type=entry.error_type,
                proxy=self.get_proxy_url_masked(),
            )
            if entry.success:
                log.info("proxy_request.completed")
            else:
                log.warning("proxy_request.failed")

    async def get_usage_summary(self) -> ProxyUsageSummary:
        """Return in-memory aggregated usage statistics."""
        async with self._lock:
            return ProxyUsageSummary(
                total_requests=self._total_requests,
                successful_requests=self._successful_requests,
                failed_requests=self._failed_requests,
                total_bytes_used=self._total_bytes_used,
                total_duration_ms=self._total_duration_ms,
            )

    async def check_connectivity(self) -> bool:
        """Probe the Webshare gateway to verify proxy reachability.

        Returns True if a HEAD request to http://httpbin.org/ip through the proxy
        succeeds with a 2xx response within the configured timeout.
        Returns False (never raises) so it can be used as a health check callback.
        """
        if not self._settings.enabled:
            return True  # No proxy = no connectivity requirement

        proxy_url = self.get_proxy_url()
        timeout = self._settings.health_check_timeout_seconds

        try:
            async with httpx.AsyncClient(
                proxy=proxy_url,
                timeout=timeout,
            ) as client:
                resp = await client.head("http://httpbin.org/ip")
                ok = resp.status_code < 400
                logger.debug(
                    "proxy.connectivity_check",
                    status_code=resp.status_code,
                    ok=ok,
                    proxy=self.get_proxy_url_masked(),
                )
                return ok
        except Exception as exc:
            logger.warning(
                "proxy.connectivity_check_failed",
                error=str(exc),
                proxy=self.get_proxy_url_masked(),
            )
            return False
