# Agent Instructions (YT Summarizer)

> This file is the single source of truth for agentic coding guidance. It merges the original
> Aspire notes with repository rules from `.github/copilot-instructions.md`.

## Critical Rules (Read First)
1. **Before marking ANY task complete, run** `./scripts/run-tests.ps1`.
2. **Run pre-commit locally before pushing**: `python -m pre_commit run --all-files --verbose`.
3. **E2E tests are mandatory** for completion; do not use `-SkipE2E` for final verification.
4. If Aspire is not running, start it with the wrapper (see below) before E2E tests.
5. Prefer official Aspire docs: https://aspire.dev and https://learn.microsoft.com/dotnet/aspire.
6. **ALL secrets and credentials MUST be stored in Azure Key Vault** and managed via Terraform. Never ask the user to manually store secrets unless Terraform cannot support it. This includes:
   - API keys (OpenAI, Cloudflare, etc.)
   - Database passwords
   - Auth0 credentials (both service account and BFF application)
   - Session secrets
   - Storage connection strings
   - Any other sensitive configuration values

## Repository Map
- `apps/web`: Next.js frontend (TypeScript, Tailwind).
- `services/api`: FastAPI backend.
- `services/workers`: Python background workers.
- `services/shared`: Shared Python libraries (DB, logging, queue).
- `services/aspire`: Aspire AppHost + defaults.
- `scripts`: PowerShell automation for tests, migrations, deploys.
- `infra`: Terraform and deployment manifests.

## Aspire Workflow
- The app is orchestrated via Aspire; resources are defined in `services/aspire/AppHost/AppHost.cs`.
- Changes to `AppHost.cs` require restarting Aspire.
- Use the Aspire MCP tools to inspect resources and logs when debugging.
- The repo includes a wrapper: `tools/aspire.cmd`.
  - Running `aspire run` uses the wrapper automatically and detaches the process.
  - Check logs via `Get-Content aspire.log -Tail 50`.
  - Stop Aspire by closing the detached window or using Task Manager.

## Dependency Setup
- **Frontend**: `cd apps/web && npm install`
- **API**: `cd services/api && uv sync`
- **Workers**: `cd services/workers && uv sync`
- **Shared**: `cd services/shared && uv sync`

## Build / Run Commands
- **Aspire (full stack)**: `aspire run`
- **Frontend dev server**: `cd apps/web && npm run dev`
- **API dev server**: `cd services/api && uv run uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000`
- **Workers (example)**: `cd services/workers && uv run python -m transcribe`
- **Migrations (shared)**:
  - `cd services/shared && uv run alembic revision --autogenerate -m "description"`
  - `cd services/shared && uv run alembic upgrade head`

## Test Commands
### Unified (Required)
- **All tests (includes E2E)**: `./scripts/run-tests.ps1`
- **Specific component**: `./scripts/run-tests.ps1 -Component api|workers|shared|web|e2e`
- **Integration-only**: `./scripts/run-tests.ps1 -Mode integration`
- **E2E-only**: `./scripts/run-tests.ps1 -Mode e2e`
- **Smoke test**: `./scripts/smoke-test.ps1` (run after Aspire starts)

### Single-test examples
- **API/Workers/Shared (pytest)**:
  - `cd services/api && uv run pytest tests/test_file.py::test_name`
  - `cd services/workers && uv run pytest tests/test_file.py -k "partial_name"`
  - `cd services/shared && uv run pytest tests/test_file.py -k "partial_name"`
- **Frontend (Vitest)**:
  - `cd apps/web && npm run test:run -- src/__tests__/components/SubmitVideoForm.test.tsx`
  - `cd apps/web && npx vitest run src/__tests__/hooks/useHealthCheck.test.tsx`
- **E2E (Playwright)**:
  - `cd apps/web && npx playwright test e2e/smoke.spec.ts`
  - `cd apps/web && npx playwright test e2e/video-flow.spec.ts --headed`

### Test Notes
- E2E requires Aspire; the runner will start it if needed.
- Playwright uses `USE_EXTERNAL_SERVER=true` when running against Aspire.
- API live E2E tests require `E2E_TESTS_ENABLED=true` and `pytest -m ""`.
- `./scripts/run-tests.ps1` defaults to `-Component detect` to auto-scope changes.
- Use `-Component` for quicker iteration, but final run must include E2E.

## Environment Variables
- `DATABASE_URL`: SQL Server connection string for API/workers.
- `AZURE_STORAGE_CONNECTION_STRING`: Azure/Azurite storage for queues/blobs.
- `OPENAI_API_KEY`: Required for summarization workers.
- `NEXT_PUBLIC_API_URL`: Public API URL for browser clients.
- `API_URL`: Internal API URL for SSR calls.
- `QUEUE_POLL_INTERVAL`: Seconds between queue polls when empty (default: 10.0). Configured per-worker in Aspire.
- `QUEUE_BATCH_SIZE`: Number of messages to fetch per poll, range 1-32 (default: 32). Configured per-worker in Aspire.

## Lint / Format
- **Frontend lint**: `cd apps/web && npm run lint`
- **Frontend format**: `cd apps/web && npx prettier --write .`
- **Python lint**: `cd services/api && uv run ruff check .`
- **Python format**: `cd services/api && uv run ruff format .`
- `ruff.toml` defines import sorting (isort) and line length = 100.

## Code Style Guidelines
### General
- Prefer small, focused changes; avoid unrelated refactors.
- Use `get_logger(__name__)` for Python logging and include context fields.
- Keep line length to **100** (Python + TS/JS).
- Preserve existing module boundaries (`api`, `workers`, `shared`, `apps/web`).

### Python (API/Workers/Shared)
- Use type hints everywhere; prefer `list[str]`, `dict[str, Any]`, and union types (`str | None`).
- Use `dataclass` for message payloads and small value objects.
- Follow Ruff import ordering; first-party modules are `api`, `shared`, `workers`.
- Favor explicit error handling with `try/except` and structured logs (`logger.warning`, `logger.exception`).
- Raise FastAPI `HTTPException` with clear status + detail when handling routes.
- Prefer async DB/session patterns from `shared.db.connection` and `AsyncSession`.
- Use SQLAlchemy models from `shared.db.models` and shared helpers for storage/queues.

### TypeScript / React (Frontend)
- Use named exports for utilities and types; default exports are rare.
- Components are `PascalCase` file names and functions (`MarkdownRenderer`).
- Hooks use `useX` naming and live in `src/hooks`.
- Keep API types in `src/services/api.ts` and shared types in `src/types`.
- Prefer `type` or `interface` with explicit field docs for API contracts.
- Use `async/await` for API calls; wrap errors in custom error classes where needed.
- Keep UI logic in components and data access in `src/services`.

### Formatting
- Prettier config in `apps/web/.prettierrc`:
  - `singleQuote: true`, `semi: true`, `printWidth: 100`, `tabWidth: 2`.
- ESLint config: `apps/web/eslint.config.mjs` (Next.js core-web-vitals + TS).
- Ruff config: `services/ruff.toml` (imports + lint rules).

### Naming
- Python: `snake_case` for modules/functions, `PascalCase` for classes.
- TypeScript: `camelCase` variables/functions, `PascalCase` components/types.
- Environment variables use `SCREAMING_SNAKE_CASE`.

### Error Handling & Logging
- Prefer structured log fields over string concatenation.
- Use `logger.exception` for unexpected failures to capture stack traces.
- Preserve correlation IDs across HTTP and queue messages.
- Use retry/backoff patterns for transient failures (see workers).

## Infrastructure & Ops Scripts
- **Run migrations**: `./scripts/run-migrations.ps1`
- **Start workers**: `./scripts/start-workers.ps1`
- **Deploy infra**: `./scripts/deploy-infra.ps1`
- CI helpers live under `scripts/ci/`.

## Validation Framework
All infrastructure validation is centralized in the `.github/actions/validate` composite action for consistency and maintainability.

### Available Validators
The validate action supports these validators (use comma-separated list):

- **yaml-syntax**: Validates YAML syntax for all K8s manifests
- **kustomize-build**: Validates kustomize overlays and bases build successfully
- **argocd-paths**: Validates Argo CD Application paths exist
- **argocd-manifest**: Validates Argo CD manifests against server state
- **terraform-config**: Validates Terraform configuration (fmt, validate, init)
- **swa-config**: Validates Static Web Apps configuration (output_location, token, build script)
- **kustomize-resources**: Validates resource requests/limits against AKS quotas
- **all**: Runs all validators

### Usage Examples

```yaml
# K8s validation
- uses: ./.github/actions/validate
  with:
    validators: yaml-syntax,kustomize-build
    overlay-paths: k8s/overlays/preview,k8s/overlays/prod

# Terraform validation
- uses: ./.github/actions/validate
  with:
    validators: terraform-config
    terraform-directory: infra/terraform
    terraform-backend-config: 'true'

# Resource quota validation with AKS query
- uses: ./.github/actions/validate
  with:
    validators: kustomize-resources
    overlay-paths: k8s/overlays/prod
    query-aks: 'true'
    aks-resource-group: rg-yt-summarizer-prod
    aks-cluster-name: aks-yt-summarizer-prod
    aks-namespace: default

# Manual limits (if not querying AKS)
- uses: ./.github/actions/validate
  with:
    validators: kustomize-resources
    overlay-paths: k8s/overlays/prod
    max-cpu-millicores: '4000'
    max-memory-mi: '8192'
```

### Validator Details

**swa-config**: Validates Static Web Apps configuration consistency across workflow files. Checks: (1) `output_location: ""` in deploy workflows, (2) SWA token is `SWA_DEPLOYMENT_TOKEN`, (3) build script starts with `next build --webpack`, (4) no root package.json/package-lock.json.

**kustomize-resources**: Validates total CPU/memory requests don't exceed AKS cluster quotas. Can query AKS for actual quotas (`query-aks: 'true'`) or use manual limits. Sums container requests across all Deployment/StatefulSet/DaemonSet resources (scaled by replicas).

### Deprecated Scripts (Removed)
These scripts have been migrated to the centralized validate action:
- ~~`scripts/validate_workflows.py`~~ - Now covered by yaml-syntax validator + actionlint
- ~~`scripts/validate-swa-output.ps1`~~ - Now `swa-config` validator
- ~~`scripts/ci/validate_kustomize.py`~~ - Now `kustomize-resources` validator

## Queue Polling & Cost Optimization
Workers poll Azure Storage queues at configurable intervals to balance latency vs. transaction costs:

- **Poll Interval**: 10 seconds (default) - Time to wait between queue polls when empty
- **Batch Size**: 32 messages (default, Azure max) - Messages fetched per poll
- **Cost Impact**: ~98% reduction in queue transactions vs. 1-second polling with batch_size=1

Configuration is set in `services/aspire/AppHost/AppHost.cs` via environment variables:
- `QUEUE_POLL_INTERVAL`: Adjust for latency vs. cost tradeoff (default: 10.0 seconds)
- `QUEUE_BATCH_SIZE`: Increase for high-volume workloads, decrease for memory-constrained workers (default: 32)

**Latency Trade-off**: Messages may wait up to 10 seconds before processing starts (avg: 5 seconds). For video processing workflows that take minutes to hours, this is negligible.

**Per-Worker Overrides**: Workers can override defaults in their `__init__` method if needed. For example, the transcribe worker already has rate limiting (5-10s delays) due to YouTube API constraints.

## K8s Preview Patch Placeholders
Preview environment K8s patches use placeholders that are substituted during deployment to ensure each PR gets unique resources:

**Required Placeholders**:
- `__PR_NUMBER__`: PR number (e.g., 109)
- `__PREVIEW_HOST__`: Full preview hostname (e.g., api-pr-109.yt-summarizer.apps.ashleyhollis.com)
- `__TLS_SECRET__`: TLS secret name for the preview
- `__SWA_URL__`: Static Web App URL for CORS configuration

**Validation**: The CI runs `scripts/ci/validate-k8s-placeholders.sh` to ensure patch files in `k8s/overlays/preview/patches/` don't contain hardcoded PR numbers or URLs. This prevents deployment issues where patches reference wrong resources.

**Substitution**: During deployment, `scripts/ci/generate_preview_kustomization.py` replaces placeholders with actual values for the current PR.

## Tooling & Automation Rules (Copilot Instructions)
- Use **PowerShell** for scripts on Windows.
- Use `gh` (GitHub CLI) for any GitHub operations (PRs, issues, runs).
- Playwright MCP server is configured; use it for UI checks when needed.
- Available tooling: .NET CLI, uv/pip, npm/pnpm, pytest, Vitest, Ruff, ESLint, Prettier.

## Cursor Rules
- No `.cursor/rules` or `.cursorrules` files are present in this repository.
