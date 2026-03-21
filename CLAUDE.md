# yt-summarizer — Claude Code Project Instructions

## Project Location
/home/openclaw/dev/yt-summarizer

> Note: Repo lives at /home/openclaw/dev/ (NOT OneDriveOpenClaw/projects/) because OneDrive's
> FUSE mount does not support symlinks, which Python venvs require.

## Architecture
- Frontend: Next.js in apps/web (port 3000)
- Backend API: FastAPI in services/api (port 8000)
- Workers: Python workers in services/workers/{transcribe,summarize,embed,relationships}
- Shared: DB models, Alembic migrations in services/shared
- Orchestration: .NET Aspire via services/aspire/AppHost/AppHost.cs
- Infrastructure: SQL Server 2025 + Azurite in Docker containers (managed by Aspire)

## How to Start the App
```bash
cd /home/openclaw/dev/yt-summarizer/services/aspire/AppHost
export DOTNET_ROOT=$HOME/.dotnet
export PATH=$PATH:$HOME/.dotnet:$HOME/.dotnet/tools
dotnet run --no-dashboard
```
This starts everything (containers, API, workers, frontend). Run inside tmux for persistence.

## How to Stop / Restart
```bash
# Stop: Ctrl+C in the tmux session
tmux attach -t yt-summarizer
# Then Ctrl+C

# Restart
tmux send-keys -t yt-summarizer "dotnet run --no-dashboard" Enter
```

## Health Checks (headless)
```bash
curl -s http://localhost:8000/health/live
curl -s http://localhost:8000/health/ready
curl -s http://localhost:8091/health   # transcribe
curl -s http://localhost:8092/health   # summarize
curl -s http://localhost:8093/health   # embed
curl -s http://localhost:8094/health   # relationships
```

## Python Deps (when adding packages)
```bash
export PATH=$PATH:$HOME/.local/bin
cd services/api && uv add <package> && uv sync --prerelease=allow
cd services/workers/transcribe && uv add <package> && uv sync --prerelease=allow
# etc. Always use --prerelease=allow (azure-ai-agents is a prerelease dep)
```

## Database Migrations
```bash
cd services/api
uv run alembic revision --autogenerate -m "describe change"
uv run alembic upgrade head
# OR from services/shared (Alembic is configured there)
cd services/shared
uv run alembic upgrade head
```

## Aspire Secrets
Secrets are in dotnet user-secrets (not committed). To update:
```bash
export DOTNET_ROOT=$HOME/.dotnet
export PATH=$PATH:$HOME/.dotnet:$HOME/.dotnet/tools
cd services/aspire/AppHost
dotnet user-secrets set "Parameters:<name>" "<value>"
dotnet user-secrets list   # see all configured
```

### Missing Secrets (Peter must fill in)
These are set to "PLACEHOLDER_FILL_IN" and must be updated before full functionality:
- `Parameters:azure-openai-embedding-deployment` — embedding model name (check Azure AI Studio)
- `Parameters:openai-api-key` — standard OpenAI key (check GitHub Secrets or OpenAI dashboard)
- `Parameters:auth0-domain` — Auth0 tenant domain
- `Parameters:auth0-client-id` — Auth0 application client ID
- `Parameters:auth0-client-secret` — Auth0 application client secret
- `Parameters:auth0-session-secret` — random secret for session encryption

## AppHost Modification
- Main orchestration file: services/aspire/AppHost/AppHost.cs
- After any AppHost.cs change: restart Aspire (Ctrl+C then dotnet run --no-dashboard)
- NOTE: Worker paths use Linux format: .venv/bin/python (NOT .venv/Scripts/python.exe)

## Worker venvs — Linux Path Notes
Each worker's pyproject.toml has a `[tool.uv.sources]` block pointing to shared:
```toml
[tool.uv.sources]
yt-summarizer-shared = { path = "../../shared", editable = true }
```
This was added at setup time because workers depend on the local shared package.
Recreate venvs with: `uv sync --prerelease=allow` in each worker dir.

Workers are launched from `services/workers/` (parent dir) with `-m <name>` so relative
imports in `__main__.py` work. AppHost.cs was patched accordingly.

## API venv — Extra Notes
The API venv must be created with `--seed` to include pip (Aspire runs `pip install .`):
```bash
cd services/api && uv venv --seed --clear && uv sync --prerelease=allow
```
The `yt-summarizer-shared` package must also be pre-installed in the API venv:
```bash
.venv/bin/pip install -e ../shared
```
(Aspire's pip install won't remove it since it's not in the API's declared deps.)

## System Dependencies
- **ODBC Driver 18 for SQL Server** must be installed on the host for pyodbc:
  ```bash
  curl -sSL https://packages.microsoft.com/keys/microsoft.asc | sudo gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg
  curl -sSL https://packages.microsoft.com/config/ubuntu/24.04/prod.list | sudo tee /etc/apt/sources.list.d/mssql-release.list
  sudo apt-get update && sudo ACCEPT_EULA=Y apt-get install -y msodbcsql18 unixodbc-dev
  ```
- **Docker group**: The user running Aspire must be in the docker group
  ```bash
  sudo usermod -aG docker $USER
  # Then use: sg docker -c 'dotnet run --no-dashboard'
  ```

## Directory Map
```
services/api/src/                         — FastAPI application
services/workers/{name}/                  — Worker implementations
services/workers/{name}/.venv/            — Python venv (pre-created, not committed)
services/shared/                          — DB models, Alembic, queue client
services/aspire/AppHost/AppHost.cs        — Aspire orchestration
apps/web/src/                             — Next.js pages and components
```

## Autonomous Operation Rules
- Make reasonable decisions without asking — document them in commit messages
- If blocked (missing credential, ambiguous requirement), reply with what you need and stop
- Run health checks after any service change to confirm it's still up
- Run migrations after model changes
- Never commit .env files, user-secrets, or any credentials
- Never use git commit --no-verify
- Azure deployments happen via GitHub Actions on push to main — do not deploy manually
