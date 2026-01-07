"""
Shared OpenTelemetry configuration for API and workers.

Provides centralized telemetry setup that can be reused across services.
Auto-detects Aspire OTLP endpoint from environment variables.

Configures all three pillars of observability:
- Traces: Distributed tracing with span context propagation
- Logs: Structured logging exported via OTLP
- Metrics: (Optional, configured separately)

Environment variables used by Aspire:
- OTEL_EXPORTER_OTLP_ENDPOINT: Base OTLP endpoint (e.g., http://localhost:4318)
- OTEL_EXPORTER_OTLP_PROTOCOL: Protocol (http/protobuf or grpc)
- OTEL_EXPORTER_OTLP_HEADERS: Authentication headers (e.g., x-otlp-api-key=xxx)
- OTEL_SERVICE_NAME: Service name (set by Aspire)
- SSL_CERT_DIR: Directory containing SSL certificates for HTTPS endpoints
"""

import logging as stdlib_logging
import os
import sys
from typing import Optional

# Flag to track if telemetry has been configured
_telemetry_configured = False
_log_handler_configured = False


def _parse_headers(headers_str: Optional[str]) -> dict[str, str]:
    """Parse OTEL_EXPORTER_OTLP_HEADERS format (key=value,key2=value2)."""
    if not headers_str:
        return {}
    headers = {}
    for pair in headers_str.split(","):
        if "=" in pair:
            key, value = pair.split("=", 1)
            headers[key.strip()] = value.strip()
    return headers


def _find_ssl_cert() -> Optional[str]:
    """Find SSL certificate from environment or SSL_CERT_DIR.
    
    Sets OTEL_EXPORTER_OTLP_CERTIFICATE environment variable if found,
    since the OTLP exporters read this directly in addition to constructor args.
    
    IMPORTANT: We only set OTEL-specific certificate variables here.
    We do NOT set SSL_CERT_FILE or REQUESTS_CA_BUNDLE because:
    - The Aspire dev certificate is only valid for local OTLP collector
    - Other libraries (openai, httpx, requests) need the system/certifi CA bundle
    - Setting these globally would break Azure OpenAI and other external HTTPS calls
    """
    ssl_cert = os.environ.get("OTEL_EXPORTER_OTLP_CERTIFICATE")
    if ssl_cert:
        return ssl_cert
    
    ssl_cert_dir = os.environ.get("SSL_CERT_DIR")
    if ssl_cert_dir:
        import pathlib
        cert_dir = pathlib.Path(ssl_cert_dir)
        if cert_dir.exists():
            # Look for aspire-dev-cert.pem or any .pem/.crt file
            for pattern in ["aspire*.pem", "*.pem", "*.crt"]:
                certs = list(cert_dir.glob(pattern))
                if certs:
                    cert_path = str(certs[0])
                    # Set the env var so OTLP exporters can find it
                    os.environ["OTEL_EXPORTER_OTLP_CERTIFICATE"] = cert_path
                    # NOTE: Do NOT set SSL_CERT_FILE or REQUESTS_CA_BUNDLE here!
                    # The Aspire dev cert is only for OTLP, not for Azure/external APIs.
                    return cert_path
    return None


def configure_telemetry(
    service_name: str,
    service_version: str = "0.1.0",
    environment: Optional[str] = None,
) -> bool:
    """
    Configure OpenTelemetry for the service (traces, logs, and metrics).
    
    This function configures all three pillars of observability for Aspire:
    - Traces: Distributed tracing with BatchSpanProcessor
    - Logs: Structured log export via OTLP using LoggingHandler
    - Metrics: Basic metrics exporter (if available)
    
    Args:
        service_name: Name of the service (e.g., 'yt-summarizer-api')
        service_version: Version of the service
        environment: Deployment environment (e.g., 'development', 'production')
    
    Returns:
        True if telemetry was configured, False if skipped or unavailable
    """
    global _telemetry_configured, _log_handler_configured
    
    # Use service name from environment if set by Aspire (takes precedence)
    service_name = os.environ.get("OTEL_SERVICE_NAME", service_name)
    
    print(f"[TELEMETRY] Configuring telemetry for {service_name}", file=sys.stderr, flush=True)
    
    # Skip if already configured
    if _telemetry_configured:
        print(f"[TELEMETRY] Already configured, skipping", file=sys.stderr, flush=True)
        return True
    
    # Get OTLP endpoint from environment (Aspire sets this automatically)
    otlp_endpoint = os.environ.get(
        "OTEL_EXPORTER_OTLP_ENDPOINT",
        os.environ.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
    )
    otlp_protocol = os.environ.get("OTEL_EXPORTER_OTLP_PROTOCOL", "http/protobuf")
    otlp_headers_str = os.environ.get("OTEL_EXPORTER_OTLP_HEADERS")
    otlp_headers = _parse_headers(otlp_headers_str)
    
    print(f"[TELEMETRY] OTLP endpoint: {otlp_endpoint}, protocol: {otlp_protocol}", file=sys.stderr, flush=True)
    if otlp_headers:
        print(f"[TELEMETRY] OTLP headers configured: {list(otlp_headers.keys())}", file=sys.stderr, flush=True)
    
    # Skip telemetry if no endpoint configured
    if not otlp_endpoint:
        print(f"[TELEMETRY] No OTLP endpoint configured, telemetry disabled", file=sys.stderr, flush=True)
        return False
    
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_VERSION
        
        # Find SSL certificate for HTTPS endpoints
        ssl_cert = _find_ssl_cert()
        if ssl_cert:
            print(f"[TELEMETRY] Using SSL certificate: {ssl_cert}", file=sys.stderr, flush=True)
        
        # Create resource with service info
        resource = Resource.create({
            SERVICE_NAME: service_name,
            SERVICE_VERSION: service_version,
            "deployment.environment": environment or os.environ.get("ENVIRONMENT", "development"),
        })
        
        # ==================== CONFIGURE TRACES ====================
        provider = TracerProvider(resource=resource)
        
        if otlp_protocol == "http/protobuf":
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
            import requests
            
            # HTTP exporter needs /v1/traces appended if not present
            traces_endpoint = otlp_endpoint
            if not traces_endpoint.endswith("/v1/traces"):
                traces_endpoint = f"{otlp_endpoint.rstrip('/')}/v1/traces"
            
            print(f"[TELEMETRY] Traces endpoint: {traces_endpoint}", file=sys.stderr, flush=True)
            
            exporter_kwargs = {"endpoint": traces_endpoint}
            if otlp_headers:
                exporter_kwargs["headers"] = otlp_headers
            
            # For HTTPS endpoints, create a custom session with SSL cert
            if traces_endpoint.startswith("https://"):
                session = requests.Session()
                if ssl_cert:
                    session.verify = ssl_cert
                    print(f"[TELEMETRY] Using SSL cert for session: {ssl_cert}", file=sys.stderr, flush=True)
                else:
                    # For local development with self-signed certs, disable SSL verification
                    session.verify = False
                    print(f"[TELEMETRY] WARNING: Disabling SSL verification (no cert found)", file=sys.stderr, flush=True)
                    # Suppress SSL warnings for local dev
                    import urllib3
                    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                exporter_kwargs["session"] = session
            
            trace_exporter = OTLPSpanExporter(**exporter_kwargs)
        else:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
            
            print(f"[TELEMETRY] Using gRPC exporter: {otlp_endpoint}", file=sys.stderr, flush=True)
            
            if otlp_endpoint.startswith("https://"):
                if ssl_cert:
                    os.environ["GRPC_DEFAULT_SSL_ROOTS_FILE_PATH"] = ssl_cert
                    trace_exporter = OTLPSpanExporter(
                        endpoint=otlp_endpoint,
                        headers=otlp_headers if otlp_headers else None,
                        insecure=False,
                    )
                else:
                    trace_exporter = OTLPSpanExporter(
                        endpoint=otlp_endpoint,
                        headers=otlp_headers if otlp_headers else None,
                        insecure=True,
                    )
            else:
                trace_exporter = OTLPSpanExporter(
                    endpoint=otlp_endpoint,
                    headers=otlp_headers if otlp_headers else None,
                    insecure=True,
                )
        
        provider.add_span_processor(BatchSpanProcessor(trace_exporter))
        trace.set_tracer_provider(provider)
        print(f"[TELEMETRY] Trace exporter configured", file=sys.stderr, flush=True)
        
        # ==================== INSTRUMENT LIBRARIES ====================
        # OpenAI - Gen AI semantic conventions for LLM calls
        try:
            from opentelemetry.instrumentation.openai_v2 import OpenAIInstrumentor
            OpenAIInstrumentor().instrument()
            print(f"[TELEMETRY] OpenAI instrumentation enabled (Gen AI traces)", file=sys.stderr, flush=True)
        except ImportError:
            print(f"[TELEMETRY] OpenAI instrumentation not available", file=sys.stderr, flush=True)
        except Exception as e:
            print(f"[TELEMETRY] OpenAI instrumentation failed: {e}", file=sys.stderr, flush=True)
        
        # SQLAlchemy - Database query traces
        try:
            from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
            SQLAlchemyInstrumentor().instrument()
            print(f"[TELEMETRY] SQLAlchemy instrumentation enabled (DB traces)", file=sys.stderr, flush=True)
        except ImportError:
            print(f"[TELEMETRY] SQLAlchemy instrumentation not available", file=sys.stderr, flush=True)
        except Exception as e:
            print(f"[TELEMETRY] SQLAlchemy instrumentation failed: {e}", file=sys.stderr, flush=True)
        
        # HTTPX - Async HTTP client traces (used by OpenAI SDK)
        try:
            from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
            HTTPXClientInstrumentor().instrument()
            print(f"[TELEMETRY] HTTPX instrumentation enabled (HTTP client traces)", file=sys.stderr, flush=True)
        except ImportError:
            print(f"[TELEMETRY] HTTPX instrumentation not available", file=sys.stderr, flush=True)
        except Exception as e:
            print(f"[TELEMETRY] HTTPX instrumentation failed: {e}", file=sys.stderr, flush=True)
        
        # Logging - Correlate Python logs with trace context
        try:
            from opentelemetry.instrumentation.logging import LoggingInstrumentor
            LoggingInstrumentor().instrument(set_logging_format=True)
            print(f"[TELEMETRY] Logging instrumentation enabled (log-trace correlation)", file=sys.stderr, flush=True)
        except ImportError:
            print(f"[TELEMETRY] Logging instrumentation not available", file=sys.stderr, flush=True)
        except Exception as e:
            print(f"[TELEMETRY] Logging instrumentation failed: {e}", file=sys.stderr, flush=True)
        
        # ==================== ENABLE AZURE SDK TRACING ====================
        # This enables tracing for Azure Storage (Queues, Blobs) and other Azure services
        try:
            from azure.core.settings import settings
            from azure.core.tracing.ext.opentelemetry_span import OpenTelemetrySpan
            settings.tracing_implementation = OpenTelemetrySpan
            print(f"[TELEMETRY] Azure SDK tracing enabled (Storage Queue/Blob traces)", file=sys.stderr, flush=True)
        except ImportError:
            print(f"[TELEMETRY] Azure SDK tracing not available (install azure-core-tracing-opentelemetry)", file=sys.stderr, flush=True)
        except Exception as e:
            print(f"[TELEMETRY] Azure SDK tracing failed: {e}", file=sys.stderr, flush=True)
        
        # ==================== CONFIGURE METRICS ====================
        _configure_metrics_exporter(otlp_endpoint, otlp_protocol, otlp_headers, ssl_cert, resource)
        
        # Enable system/process metrics (CPU, memory, GC, etc.)
        try:
            from opentelemetry.instrumentation.system_metrics import SystemMetricsInstrumentor
            SystemMetricsInstrumentor().instrument()
            print(f"[TELEMETRY] System metrics instrumentation enabled (CPU, memory, runtime)", file=sys.stderr, flush=True)
        except ImportError:
            print(f"[TELEMETRY] System metrics not available (install opentelemetry-instrumentation-system-metrics)", file=sys.stderr, flush=True)
        except Exception as e:
            print(f"[TELEMETRY] System metrics instrumentation failed: {e}", file=sys.stderr, flush=True)
        
        # ==================== CONFIGURE LOGS ====================
        _configure_log_exporter(otlp_endpoint, otlp_protocol, otlp_headers, ssl_cert, resource)
        
        _telemetry_configured = True
        print(f"[TELEMETRY] OpenTelemetry configured successfully for {service_name}", file=sys.stderr, flush=True)
        
        return True
        
    except ImportError as e:
        print(f"[TELEMETRY] ImportError: {e}", file=sys.stderr, flush=True)
        return False
    except Exception as e:
        print(f"[TELEMETRY] Exception: {type(e).__name__}: {e}", file=sys.stderr, flush=True)
        import traceback
        traceback.print_exc()
        return False


def _configure_log_exporter(
    otlp_endpoint: str,
    otlp_protocol: str,
    otlp_headers: dict[str, str],
    ssl_cert: Optional[str],
    resource,
) -> bool:
    """Configure OTLP log exporter for structured logging."""
    global _log_handler_configured
    
    if _log_handler_configured:
        return True
    
    try:
        from opentelemetry._logs import set_logger_provider
        from opentelemetry.sdk._logs import LoggerProvider, LoggingHandler
        from opentelemetry.sdk._logs.export import BatchLogRecordProcessor
        
        if otlp_protocol == "http/protobuf":
            from opentelemetry.exporter.otlp.proto.http._log_exporter import OTLPLogExporter
            
            logs_endpoint = otlp_endpoint
            if not logs_endpoint.endswith("/v1/logs"):
                logs_endpoint = f"{otlp_endpoint.rstrip('/')}/v1/logs"
            
            print(f"[TELEMETRY] Logs endpoint: {logs_endpoint}", file=sys.stderr, flush=True)
            
            exporter_kwargs = {"endpoint": logs_endpoint}
            if otlp_headers:
                exporter_kwargs["headers"] = otlp_headers
            if logs_endpoint.startswith("https://") and ssl_cert:
                exporter_kwargs["certificate_file"] = ssl_cert
            
            log_exporter = OTLPLogExporter(**exporter_kwargs)
        else:
            from opentelemetry.exporter.otlp.proto.grpc._log_exporter import OTLPLogExporter
            
            if otlp_endpoint.startswith("https://"):
                log_exporter = OTLPLogExporter(
                    endpoint=otlp_endpoint,
                    headers=otlp_headers if otlp_headers else None,
                    insecure=not ssl_cert,
                )
            else:
                log_exporter = OTLPLogExporter(
                    endpoint=otlp_endpoint,
                    headers=otlp_headers if otlp_headers else None,
                    insecure=True,
                )
        
        # Create logger provider with batch processor
        logger_provider = LoggerProvider(resource=resource)
        logger_provider.add_log_record_processor(BatchLogRecordProcessor(log_exporter))
        set_logger_provider(logger_provider)
        
        # Add OTLP handler to the root logger so all logs are exported
        handler = LoggingHandler(level=stdlib_logging.NOTSET, logger_provider=logger_provider)
        stdlib_logging.getLogger().addHandler(handler)
        
        _log_handler_configured = True
        print(f"[TELEMETRY] Log exporter configured", file=sys.stderr, flush=True)
        return True
        
    except ImportError as e:
        # Log exporter packages may not be installed
        print(f"[TELEMETRY] Log exporter not available: {e}", file=sys.stderr, flush=True)
        return False
    except Exception as e:
        print(f"[TELEMETRY] Failed to configure log exporter: {e}", file=sys.stderr, flush=True)
        return False


def _configure_metrics_exporter(
    otlp_endpoint: str,
    otlp_protocol: str,
    otlp_headers: dict[str, str],
    ssl_cert: Optional[str],
    resource,
) -> bool:
    """Configure OTLP metrics exporter for application metrics."""
    try:
        from opentelemetry import metrics
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
        
        if otlp_protocol == "http/protobuf":
            from opentelemetry.exporter.otlp.proto.http.metric_exporter import OTLPMetricExporter
            
            metrics_endpoint = otlp_endpoint
            if not metrics_endpoint.endswith("/v1/metrics"):
                metrics_endpoint = f"{otlp_endpoint.rstrip('/')}/v1/metrics"
            
            print(f"[TELEMETRY] Metrics endpoint: {metrics_endpoint}", file=sys.stderr, flush=True)
            
            exporter_kwargs = {"endpoint": metrics_endpoint}
            if otlp_headers:
                exporter_kwargs["headers"] = otlp_headers
            if metrics_endpoint.startswith("https://") and ssl_cert:
                exporter_kwargs["certificate_file"] = ssl_cert
            
            metric_exporter = OTLPMetricExporter(**exporter_kwargs)
        else:
            from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
            
            if otlp_endpoint.startswith("https://"):
                metric_exporter = OTLPMetricExporter(
                    endpoint=otlp_endpoint,
                    headers=otlp_headers if otlp_headers else None,
                    insecure=not ssl_cert,
                )
            else:
                metric_exporter = OTLPMetricExporter(
                    endpoint=otlp_endpoint,
                    headers=otlp_headers if otlp_headers else None,
                    insecure=True,
                )
        
        # Create metric reader with 60 second export interval (configurable via OTEL_METRIC_EXPORT_INTERVAL)
        export_interval_ms = int(os.environ.get("OTEL_METRIC_EXPORT_INTERVAL", "60000"))
        metric_reader = PeriodicExportingMetricReader(
            metric_exporter,
            export_interval_millis=export_interval_ms,
        )
        
        # Create meter provider
        meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
        metrics.set_meter_provider(meter_provider)
        
        print(f"[TELEMETRY] Metrics exporter configured (interval: {export_interval_ms}ms)", file=sys.stderr, flush=True)
        return True
        
    except ImportError as e:
        print(f"[TELEMETRY] Metrics exporter not available: {e}", file=sys.stderr, flush=True)
        return False
    except Exception as e:
        print(f"[TELEMETRY] Failed to configure metrics exporter: {e}", file=sys.stderr, flush=True)
        return False


def get_tracer(name: str):
    """
    Get a tracer for the given component name.
    
    Args:
        name: Name of the component (e.g., 'video_service')
    
    Returns:
        OpenTelemetry tracer, or a no-op tracer if telemetry is not configured
    """
    try:
        from opentelemetry import trace
        return trace.get_tracer(name)
    except ImportError:
        # Return a no-op tracer if OpenTelemetry is not available
        return NoOpTracer()


class NoOpSpanContext:
    """No-op span context for when telemetry is not available."""
    trace_id = 0
    span_id = 0
    is_remote = False
    trace_flags = 0
    is_valid = False


class NoOpSpan:
    """No-op span for when telemetry is not available."""
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        pass
    
    def set_attribute(self, key, value):
        pass
    
    def set_attributes(self, attributes):
        pass
    
    def add_event(self, name, attributes=None, timestamp=None):
        pass
    
    def record_exception(self, exception, attributes=None):
        pass
    
    def set_status(self, status, description=None):
        pass
    
    def get_span_context(self):
        return NoOpSpanContext()
    
    def is_recording(self):
        return False
    
    def end(self, end_time=None):
        pass


class NoOpTracer:
    """No-op tracer for when telemetry is not available."""
    
    def start_as_current_span(self, name, **kwargs):
        return NoOpSpan()
    
    def start_span(self, name, **kwargs):
        return NoOpSpan()


def inject_trace_context(message: dict) -> dict:
    """
    Inject current trace context into a message for propagation.
    
    Args:
        message: The message dict to inject trace context into
    
    Returns:
        The message with trace context fields added
    """
    try:
        from opentelemetry import trace
        from opentelemetry.propagate import inject
        
        # Get current span context
        span = trace.get_current_span()
        context = span.get_span_context()
        
        if context.is_valid:
            # Use W3C Trace Context format
            carrier = {}
            inject(carrier)
            
            # Add trace context to message
            message = {
                **message,
                "traceparent": carrier.get("traceparent"),
                "tracestate": carrier.get("tracestate"),
            }
    except ImportError:
        pass  # OpenTelemetry not available
    except Exception:
        pass  # Ignore propagation errors
    
    return message


def extract_trace_context(message: dict):
    """
    Extract trace context from a message for continuing a trace.
    
    Args:
        message: The message dict containing trace context
    
    Returns:
        OpenTelemetry Context object, or None if not available
    """
    try:
        from opentelemetry.propagate import extract
        
        # Create carrier from message fields
        carrier = {
            "traceparent": message.get("traceparent"),
            "tracestate": message.get("tracestate"),
        }
        
        # Only extract if we have a traceparent
        if carrier.get("traceparent"):
            return extract(carrier)
        
    except ImportError:
        pass  # OpenTelemetry not available
    except Exception:
        pass  # Ignore extraction errors
    
    return None


def create_span_link_from_message(message: dict):
    """
    Create a span link from a message's trace context.
    
    This allows linking the consumer span back to the producer span
    when messages are passed through a queue. This is useful when you
    want to create a NEW trace but still show the relationship to the
    producer span.
    
    Args:
        message: The message dict containing traceparent field
    
    Returns:
        A Link object, or None if trace context is not available
    """
    try:
        from opentelemetry.trace import Link
        
        traceparent = message.get("traceparent")
        if not traceparent:
            return None
        
        # Parse traceparent: version-trace_id-parent_id-flags
        # Example: 00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01
        parts = traceparent.split("-")
        if len(parts) != 4:
            return None
        
        version, trace_id_hex, span_id_hex, flags_hex = parts
        
        from opentelemetry.trace import SpanContext, TraceFlags
        
        span_context = SpanContext(
            trace_id=int(trace_id_hex, 16),
            span_id=int(span_id_hex, 16),
            is_remote=True,
            trace_flags=TraceFlags(int(flags_hex, 16)),
        )
        
        return Link(
            context=span_context,
            attributes={
                "link.type": "producer",
                "messaging.operation": "receive",
            },
        )
        
    except ImportError:
        pass  # OpenTelemetry not available
    except Exception:
        pass  # Ignore parsing errors
    
    return None


def add_span_event(
    span,
    name: str,
    attributes: dict | None = None,
):
    """
    Add an event to a span with optional attributes.
    
    Events are used to record significant moments within a span,
    such as "message_received", "processing_started", "rate_limit_hit", etc.
    
    Args:
        span: The span to add the event to
        name: Name of the event (e.g., "rate_limit_detected")
        attributes: Optional dict of event attributes
    """
    try:
        if span and hasattr(span, "add_event"):
            span.add_event(name, attributes=attributes)
    except Exception:
        pass  # Ignore errors


def record_exception_on_span(span, exception: Exception, attributes: dict | None = None):
    """
    Record an exception on a span with full context.
    
    This creates a span event with the exception details and sets
    the span status to ERROR.
    
    Args:
        span: The span to record the exception on
        exception: The exception that occurred
        attributes: Optional additional attributes
    """
    try:
        if span and hasattr(span, "record_exception"):
            span.record_exception(exception, attributes=attributes)
        if span and hasattr(span, "set_status"):
            from opentelemetry.trace import Status, StatusCode
            span.set_status(Status(StatusCode.ERROR, str(exception)))
    except Exception:
        pass  # Ignore errors
