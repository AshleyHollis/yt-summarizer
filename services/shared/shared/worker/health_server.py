"""HTTP health and debug server for workers.

Provides endpoints for monitoring and debugging worker processes.
"""

import json
import os
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

from shared.logging.config import get_logger

logger = get_logger(__name__)


@dataclass
class WorkerStats:
    """Statistics about worker processing."""

    messages_processed: int = 0
    messages_succeeded: int = 0
    messages_failed: int = 0
    last_message_at: datetime | None = None
    last_error: str | None = None
    last_error_at: datetime | None = None


@dataclass
class HealthServerConfig:
    """Configuration for the health server."""

    port: int
    worker_name: str
    queue_name: str
    stats: WorkerStats = field(default_factory=WorkerStats)
    connectivity_checks: dict[str, Callable[[], bool]] = field(default_factory=dict)
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    proxy_summary_fn: Callable[[], dict] | None = None


class HealthRequestHandler(BaseHTTPRequestHandler):
    """HTTP request handler for health and debug endpoints."""

    config: HealthServerConfig  # Set by server

    def log_message(self, format: str, *args) -> None:
        """Suppress default HTTP logging."""
        pass

    def _send_json(self, data: dict, status: int = 200) -> None:
        """Send JSON response."""
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data, indent=2, default=str).encode())

    def do_GET(self) -> None:
        """Handle GET requests."""
        if self.path == "/health":
            self._handle_health()
        elif self.path == "/health/ready":
            self._handle_ready()
        elif self.path == "/health/live":
            self._handle_live()
        elif self.path == "/debug":
            self._handle_debug()
        elif self.path == "/debug/env":
            self._handle_env()
        elif self.path == "/debug/connectivity":
            self._handle_connectivity()
        elif self.path == "/debug/telemetry":
            self._handle_telemetry()
        elif self.path == "/debug/queue":
            self._handle_queue()
        elif self.path == "/debug/trace-test":
            self._handle_trace_test()
        elif self.path == "/debug/proxy":
            self._handle_proxy()
        else:
            self._send_json({"error": "Not found"}, 404)

    def _handle_health(self) -> None:
        """Return health status based on connectivity checks."""
        uptime = (datetime.now(UTC) - self.config.started_at).total_seconds()

        # Determine health based on connectivity checks
        overall_status = "healthy"
        check_results = {}

        for name, check_fn in self.config.connectivity_checks.items():
            try:
                success = check_fn()
                check_results[name] = success
                if not success:
                    overall_status = "degraded"
            except Exception:
                check_results[name] = False
                overall_status = "degraded"

        # Also check for high failure rate
        stats = self.config.stats
        if stats.messages_processed > 0:
            failure_rate = stats.messages_failed / stats.messages_processed
            if failure_rate > 0.5:  # More than 50% failures
                overall_status = "degraded"

        self._send_json(
            {
                "status": overall_status,
                "worker": self.config.worker_name,
                "queue": self.config.queue_name,
                "uptime_seconds": round(uptime, 2),
                "started_at": self.config.started_at.isoformat(),
                "stats": {
                    "messages_processed": self.config.stats.messages_processed,
                    "messages_succeeded": self.config.stats.messages_succeeded,
                    "messages_failed": self.config.stats.messages_failed,
                    "last_message_at": self.config.stats.last_message_at,
                },
                "checks": check_results if check_results else None,
            }
        )

    def _handle_ready(self) -> None:
        """Return readiness status for orchestrator probes.

        A worker is ready when:
        1. It has started successfully
        2. It can connect to external services (if checks are configured)
        """
        checks = {}
        all_ready = True

        # Worker is running
        checks["worker_started"] = True

        # Check external service connectivity if configured
        for name, check_fn in self.config.connectivity_checks.items():
            try:
                success = check_fn()
                checks[name] = success
                if not success:
                    all_ready = False
            except Exception as e:
                checks[name] = False
                checks[f"{name}_error"] = str(e)[:100]
                all_ready = False

        status_code = 200 if all_ready else 503
        self._send_json(
            {
                "ready": all_ready,
                "worker": self.config.worker_name,
                "checks": checks,
            },
            status_code,
        )

    def _handle_live(self) -> None:
        """Return simple liveness status.

        Just confirms the worker process is running and responding.
        """
        self._send_json({"status": "ok"})

    def _handle_debug(self) -> None:
        """Return detailed debug information."""
        uptime = (datetime.now(UTC) - self.config.started_at).total_seconds()

        # Get OTEL-related env vars (redact sensitive values)
        otel_vars = {}
        for key, value in os.environ.items():
            if key.startswith("OTEL_"):
                # Redact headers which may contain auth tokens
                if "HEADER" in key or "KEY" in key:
                    otel_vars[key] = "[REDACTED]" if value else "(not set)"
                else:
                    otel_vars[key] = value

        self._send_json(
            {
                "worker": self.config.worker_name,
                "queue": self.config.queue_name,
                "uptime_seconds": round(uptime, 2),
                "started_at": self.config.started_at.isoformat(),
                "python_version": sys.version,
                "stats": {
                    "messages_processed": self.config.stats.messages_processed,
                    "messages_succeeded": self.config.stats.messages_succeeded,
                    "messages_failed": self.config.stats.messages_failed,
                    "last_message_at": self.config.stats.last_message_at,
                    "last_error": self.config.stats.last_error,
                    "last_error_at": self.config.stats.last_error_at,
                },
                "otel_environment": otel_vars,
                "endpoints": {
                    "health": "/health",
                    "ready": "/health/ready",
                    "live": "/health/live",
                    "debug": "/debug",
                    "env": "/debug/env",
                    "connectivity": "/debug/connectivity",
                    "telemetry": "/debug/telemetry",
                    "queue": "/debug/queue",
                    "trace_test": "/debug/trace-test",
                    "proxy": "/debug/proxy",
                },
            }
        )

    def _handle_env(self) -> None:
        """Return relevant environment variables."""
        # Include OTEL, connection strings, and worker-related vars
        relevant_prefixes = (
            "OTEL_",
            "SSL_",
            "BLOBS_",
            "QUEUES_",
            "YTSUMMARIZER_",
            "ConnectionStrings__",
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

        self._send_json(
            {
                "worker": self.config.worker_name,
                "environment_variables": env_vars,
                "count": len(env_vars),
            }
        )

    def _handle_connectivity(self) -> None:
        """Test connectivity to external services."""
        results = {}

        for name, check_fn in self.config.connectivity_checks.items():
            try:
                start = time.time()
                success = check_fn()
                elapsed = time.time() - start
                results[name] = {
                    "status": "ok" if success else "failed",
                    "latency_ms": round(elapsed * 1000, 2),
                }
            except Exception as e:
                results[name] = {
                    "status": "error",
                    "error": str(e),
                }

        all_ok = all(r.get("status") == "ok" for r in results.values())

        self._send_json(
            {
                "worker": self.config.worker_name,
                "overall_status": "healthy" if all_ok else "degraded",
                "checks": results,
            }
        )

    def _handle_telemetry(self) -> None:
        """Return telemetry configuration status."""
        otel_endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "")
        otel_protocol = os.environ.get("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
        otel_service = os.environ.get("OTEL_SERVICE_NAME", "")
        ssl_cert_dir = os.environ.get("SSL_CERT_DIR", "")

        # Check if OpenTelemetry packages are available
        otel_packages = {}
        for pkg in ["opentelemetry.api", "opentelemetry.sdk", "opentelemetry.exporter.otlp"]:
            try:
                __import__(pkg.replace(".", "_"), fromlist=[""])
                otel_packages[pkg] = "installed"
            except ImportError:
                # Try alternate import
                try:
                    parts = pkg.split(".")
                    if len(parts) >= 2:
                        __import__(parts[0])
                        otel_packages[pkg] = "installed"
                    else:
                        otel_packages[pkg] = "not installed"
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

                # Create SSL context that trusts system certs
                ctx = ssl.create_default_context()
                if ssl_cert_dir:
                    # Add custom cert directory if specified
                    for cert_file in os.listdir(ssl_cert_dir):
                        if cert_file.endswith((".crt", ".pem")):
                            ctx.load_verify_locations(os.path.join(ssl_cert_dir, cert_file))

                # Try to connect (just check if endpoint responds)
                req = urllib.request.Request(otel_endpoint, method="HEAD")
                start = time.time()
                try:
                    urllib.request.urlopen(req, timeout=5, context=ctx)
                    otlp_connectivity = {
                        "status": "ok",
                        "latency_ms": round((time.time() - start) * 1000, 2),
                    }
                except urllib.error.HTTPError as e:
                    # HTTP errors mean we connected successfully
                    otlp_connectivity = {
                        "status": "ok",
                        "http_code": e.code,
                        "latency_ms": round((time.time() - start) * 1000, 2),
                    }
                except urllib.error.URLError as e:
                    otlp_connectivity = {"status": "error", "error": str(e.reason)}
            except Exception as e:
                otlp_connectivity = {"status": "error", "error": str(e)}

        self._send_json(
            {
                "worker": self.config.worker_name,
                "configuration": {
                    "endpoint": otel_endpoint or "(not set)",
                    "protocol": otel_protocol,
                    "service_name": otel_service or "(not set)",
                    "ssl_cert_dir": ssl_cert_dir or "(not set)",
                },
                "packages": otel_packages,
                "tracer": tracer_info,
                "otlp_connectivity": otlp_connectivity,
            }
        )

    def _handle_queue(self) -> None:
        """Test queue connectivity and show queue status."""
        import time

        queue_info = {
            "queue_name": self.config.queue_name,
            "connection": {"status": "not tested"},
            "messages": {"status": "not tested"},
            "environment": {},
        }

        # Show queue-related environment variables
        for key in [
            "QUEUES_CONNECTIONSTRING",
            "BLOBS_CONNECTIONSTRING",
            "ConnectionStrings__queues",
            "ConnectionStrings__blobs",
            "AZURE_STORAGE_CONNECTION_STRING",
        ]:
            value = os.environ.get(key)
            if value:
                # Mask the account key but show the endpoint
                if "AccountKey=" in value:
                    masked = value.split("AccountKey=")[0] + "AccountKey=[REDACTED]"
                    if "Endpoint=" in value:
                        masked += ";" + ";".join(p for p in value.split(";") if "Endpoint=" in p)
                    queue_info["environment"][key] = masked
                else:
                    queue_info["environment"][key] = (
                        value[:100] + "..." if len(value) > 100 else value
                    )

        # Try to connect to queue service
        try:
            from shared.queue.client import get_connection_string, get_queue_client

            # Show which connection string is being used
            try:
                conn_str = get_connection_string()
                if "QueueEndpoint=" in conn_str:
                    endpoint = [p for p in conn_str.split(";") if "QueueEndpoint=" in p]
                    queue_info["connection"]["endpoint"] = endpoint[0] if endpoint else "unknown"
                queue_info["connection"]["status"] = "connection_string_found"
            except Exception as e:
                queue_info["connection"]["status"] = "error"
                queue_info["connection"]["error"] = str(e)
                self._send_json(queue_info)
                return

            # Try to get queue client and list messages
            start = time.time()
            try:
                client = get_queue_client()
                client.ensure_queue(self.config.queue_name)
                queue_info["connection"]["status"] = "ok"
                queue_info["connection"]["latency_ms"] = round((time.time() - start) * 1000, 2)

                # Try to peek at messages
                start = time.time()
                messages = client.receive_messages(
                    self.config.queue_name, max_messages=1, visibility_timeout=1
                )
                queue_info["messages"]["status"] = "ok"
                queue_info["messages"]["latency_ms"] = round((time.time() - start) * 1000, 2)
                queue_info["messages"]["pending_count"] = len(messages)

                # Put message back if we got one (by not deleting it, visibility will expire)

            except Exception as e:
                queue_info["connection"]["status"] = "error"
                queue_info["connection"]["error"] = str(e)

        except ImportError as e:
            queue_info["connection"]["status"] = "import_error"
            queue_info["connection"]["error"] = str(e)
        except Exception as e:
            queue_info["connection"]["status"] = "error"
            queue_info["connection"]["error"] = str(e)

        self._send_json(queue_info)

    def _handle_trace_test(self) -> None:
        """Generate a test trace span to verify telemetry is working."""
        import time

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

            # Check if we have a real provider (not ProxyTracerProvider)
            if type(provider).__name__ == "ProxyTracerProvider":
                result["errors"].append(
                    "TracerProvider is ProxyTracerProvider - telemetry may not be configured"
                )

            # Create a test span
            tracer = trace.get_tracer("health-server-test")
            with tracer.start_as_current_span(
                "debug_trace_test",
                attributes={
                    "test.id": result["test_id"],
                    "worker.name": self.config.worker_name,
                    "test.type": "health_server_diagnostic",
                },
            ) as span:
                result["span_created"] = True
                result["span_info"] = {
                    "trace_id": format(span.get_span_context().trace_id, "032x"),
                    "span_id": format(span.get_span_context().span_id, "016x"),
                    "is_recording": span.is_recording(),
                }

                # Add an event
                span.add_event("test_event", {"message": "Debug trace test completed"})
                span.set_status(Status(StatusCode.OK))

            # Try to force flush the span
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

        self._send_json(result)

    def _handle_proxy(self) -> None:
        """Return proxy usage summary."""
        if self.config.proxy_summary_fn is None:
            self._send_json({"enabled": False, "message": "Proxy not configured"})
            return
        try:
            summary = self.config.proxy_summary_fn()
            self._send_json({"enabled": True, **summary})
        except Exception as e:
            self._send_json({"enabled": True, "error": str(e)}, 500)


class WorkerHealthServer:
    """HTTP server for worker health and debug endpoints.

    Runs in a background thread so it doesn't block worker processing.
    """

    def __init__(
        self,
        port: int,
        worker_name: str,
        queue_name: str,
    ):
        self.config = HealthServerConfig(
            port=port,
            worker_name=worker_name,
            queue_name=queue_name,
        )
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def stats(self) -> WorkerStats:
        """Get worker stats for updating."""
        return self.config.stats

    def add_connectivity_check(self, name: str, check_fn: Callable[[], bool]) -> None:
        """Add a connectivity check function."""
        self.config.connectivity_checks[name] = check_fn

    def set_proxy_summary_fn(self, fn: Callable[[], dict]) -> None:
        """Set a callable that returns proxy usage summary for /debug/proxy."""
        self.config.proxy_summary_fn = fn

    def start(self) -> None:
        """Start the health server in a background thread."""
        if self._server is not None:
            return

        # Create handler class with config reference
        handler = type("ConfiguredHealthHandler", (HealthRequestHandler,), {"config": self.config})

        try:
            self._server = HTTPServer(("0.0.0.0", self.config.port), handler)
            self._thread = threading.Thread(
                target=self._server.serve_forever,
                daemon=True,
                name=f"{self.config.worker_name}-health",
            )
            self._thread.start()
            logger.info(
                "Health server started",
                port=self.config.port,
                worker=self.config.worker_name,
            )
        except OSError as e:
            logger.warning(
                "Failed to start health server",
                port=self.config.port,
                error=str(e),
            )

    def stop(self) -> None:
        """Stop the health server."""
        if self._server is not None:
            self._server.shutdown()
            self._server = None
            self._thread = None
            logger.info("Health server stopped", worker=self.config.worker_name)

    def record_message_processed(self, success: bool, error: str | None = None) -> None:
        """Record that a message was processed."""
        self.stats.messages_processed += 1
        self.stats.last_message_at = datetime.now(UTC)

        if success:
            self.stats.messages_succeeded += 1
        else:
            self.stats.messages_failed += 1
            if error:
                self.stats.last_error = error
                self.stats.last_error_at = datetime.now(UTC)
