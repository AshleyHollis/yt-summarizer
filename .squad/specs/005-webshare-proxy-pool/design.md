# Design: Webshare Rotating Proxy Pool

**Feature ID**: F005
**Imported**: 2026-04-04 from `specs/005-webshare-proxy-pool/plan.md` + `data-model.md` + `contracts/proxy-service.md`

---

## Overview

A shared Python proxy service module (`services/shared/shared/proxy/`) is added to the common library. It wraps the Webshare rotating residential gateway (`p.webshare.io:80`), providing a `get_ydl_proxy_opts()` method that returns the dict needed to inject proxy support into any yt-dlp `ydl_opts`. All five yt-dlp call sites across the transcribe worker and API service are patched to merge these opts. Concurrency is upgraded in `BaseWorker` to use `asyncio.gather(return_exceptions=True)` with an `asyncio.Semaphore`. Feature flags are Pydantic Settings env vars; credentials live in Azure Key Vault.

---

## Architecture

```mermaid
graph TD
    subgraph "services/shared"
        PS[ProxyService<br/>proxy/service.py]
        PM[ProxySettings<br/>config.py]
        PRL[ProxyRequestLog<br/>db/models.py]
        BW[BaseWorker<br/>worker/base_worker.py]
        HS[WorkerHealthServer<br/>worker/health_server.py]
    end

    subgraph "services/workers/transcribe"
        TW[TranscribeWorker<br/>worker.py]
    end

    subgraph "services/api"
        YS[youtube_service.py]
        VS[video_service.py]
        BS[batch_service.py]
    end

    subgraph "infra"
        KV[Azure Key Vault<br/>Terraform]
        AH[Aspire AppHost<br/>AppHost.cs]
    end

    subgraph "external"
        WS[Webshare Gateway<br/>p.webshare.io:80]
        YT[YouTube / yt-dlp]
    end

    PM --> PS
    PS --> TW
    PS --> YS
    PS --> VS
    PS --> BS
    PS --> PRL
    PS --> HS
    BW --> TW
    TW -->|proxy URL| WS
    YS -->|proxy URL| WS
    VS -->|proxy URL| WS
    BS -->|proxy URL| WS
    WS --> YT
    KV -->|PROXY_USERNAME, PROXY_PASSWORD| AH
    AH -->|env vars| TW
    AH -->|env vars| YS
```

### Component Responsibilities

| Component | Responsibility |
|-----------|---------------|
| `ProxyService` | Gateway URL construction, feature flag check, request logging, usage summary, health check via httpx |
| `ProxySettings` | Pydantic Settings fields for `PROXY_*` env vars; nested in main `Settings` |
| `ProxyRequestLog` | SQLAlchemy model for `proxy_request_logs` table; write-only from proxy service |
| `BaseWorker` | Concurrent message processing via `asyncio.gather` + `asyncio.Semaphore`; graceful shutdown drain |
| `WorkerHealthServer` | `/debug/connectivity` extended with proxy section; new `/debug/proxy` endpoint |
| `TranscribeWorker` | Injects `ProxyService`; merges proxy opts into yt-dlp; wraps download with `log_request` |
| `youtube_service.py` | Merges proxy opts into yt-dlp for channel browsing / video listing |
| `video_service.py` | Merges proxy opts into yt-dlp for video metadata + transcript availability |
| `batch_service.py` | Merges proxy opts into yt-dlp for batch video metadata |
| Terraform (Key Vault) | Provisions `webshare-proxy-username` and `webshare-proxy-password` secrets |
| Aspire AppHost | Wires `PROXY_*` env vars from Key Vault to worker + API service resources |

---

## Data Flow

```mermaid
sequenceDiagram
    participant Q as Azure Queue
    participant BW as BaseWorker
    participant TW as TranscribeWorker
    participant PS as ProxyService
    participant WS as Webshare Gateway
    participant YT as YouTube

    Q->>BW: poll_once() → batch of messages
    BW->>BW: asyncio.gather(semaphore-bounded)
    loop each message (concurrent)
        BW->>TW: _process_single_message(msg)
        TW->>PS: get_ydl_proxy_opts()
        PS-->>TW: {"proxy": "http://user-backbone:pass@p.webshare.io:80"}
        TW->>WS: yt-dlp download (via proxy)
        WS->>YT: request (residential IP)
        YT-->>WS: response
        WS-->>TW: response
        TW->>PS: log_request(entry)
        PS->>DB: INSERT proxy_request_logs
    end
```

---

## Technical Decisions

| Decision | Options Considered | Choice | Rationale |
|----------|-------------------|--------|-----------|
| Concurrency primitive | asyncio.TaskGroup, asyncio.gather, horizontal scaling | `asyncio.gather(return_exceptions=True)` + `asyncio.Semaphore` | Error isolation — sibling tasks survive individual failure; TaskGroup cancels all siblings |
| Feature flag mechanism | LaunchDarkly, DB-backed, env vars | Pydantic Settings env vars | Consistent with existing config pattern; hot-reload per poll cycle; no new dependencies |
| Credentials storage | Config files, .env files, Key Vault | Azure Key Vault via Terraform | Security requirement; consistent with project secrets management |
| Proxy type | Datacenter static, residential static, rotating residential | Rotating residential (Webshare gateway) | Auto IP rotation per connection; no lease management; residential IPs harder for YouTube to detect |
| Bandwidth tracking | Webshare API only, no tracking, local DB | Local DB logging + Webshare API reconciliation | Immediate visibility; not dependent on external API availability |
| Thread pool sizing | Single shared executor, per-worker executor | Dedicated `ThreadPoolExecutor` per worker sized to `max_concurrency` | Prevents thread starvation across concurrent yt-dlp calls |

---

## File Structure

| File | Action | Purpose |
|------|--------|---------|
| `services/shared/shared/proxy/__init__.py` | Create | Public exports: ProxyService, ProxySettings, ProxyRequestEntry, ProxyUsageSummary, ProxyConfigurationError |
| `services/shared/shared/proxy/service.py` | Create | `ProxyService` class — `is_enabled`, `get_proxy_url`, `get_ydl_proxy_opts`, `log_request`, `get_usage_summary` |
| `services/shared/shared/proxy/models.py` | Create | `ProxyRequestEntry` dataclass, `ProxyUsageSummary` dataclass, `ProxyConfigurationError` exception |
| `services/shared/shared/config.py` | Modify | Add `ProxySettings` and `FeatureFlagSettings` with `PROXY_*` env vars |
| `services/shared/shared/db/models.py` | Modify | Add `ProxyRequestLog` SQLAlchemy model |
| `services/shared/alembic/versions/` | Create | Alembic migration: `add proxy_request_logs table` |
| `services/shared/shared/worker/base_worker.py` | Modify | `_semaphore`, `_in_flight`, `_process_with_semaphore`, concurrent `poll_once`, graceful shutdown |
| `services/shared/shared/worker/health_server.py` | Modify | `/debug/proxy` endpoint returning usage summary |
| `services/workers/transcribe/worker.py` | Modify | Inject `ProxyService`; merge proxy opts; `log_request`; instance vars for rate-limit tracking |
| `services/api/src/api/services/youtube_service.py` | Modify | Inject `ProxyService`; merge proxy opts for channel browsing |
| `services/api/src/api/services/video_service.py` | Modify | Inject `ProxyService`; merge proxy opts for video metadata |
| `services/api/src/api/services/batch_service.py` | Modify | Inject `ProxyService`; merge proxy opts for batch metadata |
| `services/aspire/AppHost/AppHost.cs` | Modify | Wire `PROXY_*` env vars to transcribe worker + API service resources |
| `infra/terraform/` | Modify | Add `webshare-proxy-username` and `webshare-proxy-password` to Key Vault |
| `services/workers/.env.example` | Modify | Document `PROXY_*` env var templates |
| `services/api/.env.example` | Modify | Document `PROXY_*` env var templates |

---

## Interfaces

```python
# ProxyService public API (services/shared/shared/proxy/service.py)
class ProxyService:
    def __init__(self, settings: ProxySettings, db: DatabaseConnection | None): ...
    def is_enabled(self) -> bool: ...
    def get_proxy_url(self) -> str | None: ...
        # Returns: "http://{user}-backbone:{pass}@p.webshare.io:80" or None
        # Raises: ProxyConfigurationError if enabled with missing credentials
    def get_ydl_proxy_opts(self) -> dict[str, str]: ...
        # Returns: {"proxy": "<url>"} when enabled, {} when disabled
    async def log_request(self, entry: ProxyRequestEntry) -> None: ...
        # Fire-and-forget — errors logged, not propagated
    async def get_usage_summary(self, since: datetime) -> ProxyUsageSummary: ...

# ProxySettings (services/shared/shared/config.py)
class ProxySettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PROXY_")
    enabled: bool = False
    gateway_host: str = "p.webshare.io"
    gateway_port: int = 80
    username: str = ""
    password: SecretStr = SecretStr("")
    use_backbone: bool = True
    max_concurrency: int = 0  # 0 = unlimited

# ProxyRequestLog SQLAlchemy model (services/shared/shared/db/models.py)
class ProxyRequestLog(Base):
    __tablename__ = "proxy_request_logs"
    id: UUID (PK, auto)
    timestamp: DateTime (NOT NULL, indexed)
    component: String(50) (NOT NULL, indexed)
    operation: String(50) (NOT NULL)
    video_id: String(20) (NULLABLE)
    channel_name: String(100) (NULLABLE)
    job_id: UUID (NULLABLE, FK → jobs.id)
    correlation_id: String(50) (NULLABLE)
    success: Boolean (NOT NULL)
    error_type: String(50) (NULLABLE)
    estimated_bytes: BigInteger (NULLABLE)
    duration_ms: Integer (NULLABLE)
    created_at: DateTime (NOT NULL, default=now)
    # Indexes: timestamp, component, (component, timestamp)
    # Retention: 90 days (configurable)
```

---

## Error Handling

| Scenario | Strategy | User Impact |
|----------|----------|-------------|
| Proxy disabled | `get_ydl_proxy_opts()` returns `{}`; no proxy routing | None — identical to pre-proxy behaviour |
| Proxy enabled, credentials missing | `ProxyConfigurationError` raised; consumer falls back or fails explicitly | Job may fail and retry; health endpoint reports config error |
| Proxy enabled, gateway unreachable | yt-dlp raises connection error; existing tenacity retry handles it | Job retried with backoff; after exhaustion → DLQ |
| YouTube 429 through proxy | Retry with backoff; next retry auto-gets a new residential IP | Transparent to operator; visible in request logs |
| Request logging fails (DB error) | Warning logged; request continues — logging is non-blocking | None — logging failure never blocks business logic |
| Webshare credentials expire | All proxied requests fail with auth errors; health endpoint surfaces credential failure | Operator alerted; jobs retry; eventually DLQ |
| Bandwidth budget exhausted | Gateway throttles/blocks; treated identically to gateway unreachable | Operator alerted via bandwidth metrics |
| Worker crash mid-request | No proxy state to clean up (stateless gateway); job message re-enqueued after visibility timeout | Job retried by next available worker |

---

## Edge Cases

- **Flag toggle during active batch**: Worker checks flag on each `poll_once()`. In-flight messages complete with their original proxy state; new batch uses updated flag.
- **Module-level globals in concurrent context**: `_last_youtube_request_time` and `_youtube_request_count` must be instance variables with `asyncio.Lock` to prevent data races across concurrent tasks.
- **Semaphore sizing**: `max_concurrency=0` means unlimited. Semaphore is created with `sys.maxsize` in this case.
- **ThreadPoolExecutor sizing**: Must match `max_concurrency` to prevent thread starvation when all semaphore slots are occupied.
- **Partial batch failure**: `asyncio.gather(return_exceptions=True)` returns a list where each element is a result or exception. Failed tasks are logged and handled individually without affecting siblings.

---

## Security Considerations

- Webshare credentials (`PROXY_USERNAME`, `PROXY_PASSWORD`) stored exclusively in Azure Key Vault; injected via Aspire/Terraform at runtime
- Credentials never logged (Pydantic `SecretStr` prevents accidental logging)
- Proxy URL is logged as a warning on config errors, with credentials masked
- `proxy_request_logs` table contains no PII — only YouTube video/channel IDs, component names, and metrics

---

## Performance Considerations

- yt-dlp sleep intervals preserved (`sleep_interval_subtitles=60+random(0,10)`) — each job still takes 60-70 s minimum; concurrency is the primary throughput lever
- Queue batch size (32 messages) caps practical concurrency per poll cycle
- `ThreadPoolExecutor` sized to `max_concurrency` prevents thread starvation
- `proxy_request_logs` table: indexes on `timestamp`, `component`, `(component, timestamp)` support time-range and per-component aggregation queries efficiently
- At 10,000 transcriptions/day + 90-day retention: ~198 MB — well within SQL Server capacity

---

## Test Strategy

### Unit Tests
- `ProxyService.is_enabled()` with flag enabled/disabled
- `ProxyService.get_proxy_url()` with valid credentials, missing credentials, disabled
- `ProxyService.get_ydl_proxy_opts()` returns correct dict shape
- `ProxyConfigurationError` raised when enabled with missing credentials
- `BaseWorker` concurrent processing: semaphore, task isolation, graceful shutdown

### Integration Tests
- Transcribe worker with `PROXY_ENABLED=true` → yt-dlp opts contain proxy URL
- Transcribe worker with `PROXY_ENABLED=false` → yt-dlp opts contain no proxy key
- API service (youtube_service, video_service, batch_service) proxy injection
- `proxy_request_logs` rows written after proxied requests
- `/debug/connectivity` includes `proxy` section
- `/debug/proxy` returns `ProxyUsageSummary`

### E2E Tests
- Submit 5 jobs with proxy enabled → verify all start concurrently (no sequential blocking)
- Simulate gateway unavailable → verify all jobs reach DLQ, none silently lost
- Toggle `PROXY_ENABLED` → verify behaviour changes within one poll cycle

---

## Existing Patterns to Follow

- **Pydantic Settings with env prefix**: Follow pattern of existing `Settings` nested classes in `services/shared/shared/config.py`
- **SQLAlchemy async model**: Follow pattern of existing models in `services/shared/shared/db/models.py`
- **Worker health server extension**: Follow pattern of existing connectivity checks in `health_server.py`
- **structlog context**: Use `structlog.contextvars.bind_contextvars()` for per-task log context under `asyncio.gather`
- **tenacity retry**: Proxy failures feed into existing `@retry` decorators — no new retry wrappers needed
