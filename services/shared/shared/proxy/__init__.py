"""Webshare rotating residential proxy service for yt-dlp call routing.

Public API::

    from shared.proxy import ProxyService, ProxyConfigurationError
    from shared.proxy import ProxyRequestEntry, ProxyUsageSummary

Usage::

    from shared.config import get_settings
    from shared.proxy import ProxyService

    proxy_service = ProxyService(get_settings().proxy)

    ydl_opts = {
        "quiet": True,
        **proxy_service.get_ydl_opts(),   # adds "proxy": "http://..." when enabled
    }

    async with proxy_service.log_request(
        job_id=job.id, service="transcribe-worker", operation="fetch_transcript"
    ) as entry:
        info = yt_dlp.YoutubeDL(ydl_opts).extract_info(url)

    ok = await proxy_service.check_connectivity()  # for health checks
"""

from .models import ProxyConfigurationError, ProxyRequestEntry, ProxyUsageSummary
from .service import ProxyService

__all__ = [
    "ProxyConfigurationError",
    "ProxyRequestEntry",
    "ProxyService",
    "ProxyUsageSummary",
]
