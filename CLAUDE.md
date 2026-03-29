# yt-summarizer — Claude Code Project Instructions

## Project Location
/home/openclaw/dev/yt-summarizer

> Note: Repo lives at /home/openclaw/dev/ (NOT OneDriveOpenClaw/projects/) because OneDrive's
> FUSE mount does not support symlinks, which Python venvs require.

## Related Repos

### shared-infra
- **Location**: `/home/openclaw/dev/shared-infra` — [GitHub](https://github.com/AshleyHollis/shared-infra)
- **Discord**: `#shared-infra` (channel 1485029874145169583)
- **What it provides**: AKS, ACR, Key Vault, OIDC, workload identity (Terraform); 53 composite GitHub Actions; reusable workflows
- **Impact**: Changes here can break yt-summarizer CI/CD — coordinate in `#shared-infra` first.

---

## Session Recovery (MANDATORY — read this first every session)

```bash
cd /home/openclaw/dev/yt-summarizer
cat PENDING.md 2>/dev/null          # current task state — always read this first
git log --oneline -10               # recent commits
git status                          # uncommitted changes
```

If PENDING.md has an in-progress task, continue it without asking Peter to re-explain.

### PENDING.md protocol

**Inbound sessions** (handle a Discord message, < 5 min):
- Understand the request, estimate size, spawn a background agent if large
- **NEVER write PENDING.md** — put all context in the spawn-agent.sh task description
- Exit immediately after spawning

**Background agents** (spawned via spawn-agent.sh, no timeout):
- **Write PENDING.md immediately on start** — task name, current step, files in progress, next action
- **Update PENDING.md after every significant action** (each commit, each CI fix, each phase transition)
  — this is how Peter can check what you're doing without waiting for a Discord message
- **If you see `=== CONTEXT COMPACTION TRIGGERED ===`**: update PENDING.md before anything else
- **Task complete**: clear PENDING.md, then post result to Discord

### Automatic hooks (configured in .claude/settings.json)
- **SessionStart**: injects PENDING.md if a task is in progress; records session start time
- **PreCompact**: reminds you to checkpoint PENDING.md before context is summarized
- **Stop**: if session ran ≥ 5 min and PENDING.md still has content → posts ⚠️ crash alert to Discord

### How to check agent progress (for Peter)
```bash
cd /home/openclaw/dev/yt-summarizer
cat PENDING.md                                          # current step
git log origin/<branch> --oneline -10                  # recent commits
gh pr view <pr> --repo AshleyHollis/yt-summarizer \
  --json statusCheckRollup \
  --jq '[.statusCheckRollup[]|select(.status!="COMPLETED")|{name,status,conclusion}]'
```

---

## Session Limits and When to Spawn

Inbound sessions have a hard 30-minute timeout. Background agents have NO timeout.

| Task size | Action |
|-----------|--------|
| < 20 min | Do it in this session |
| > 20 min | Spawn a background agent |

**Large tasks**: any CI/CD pipeline, multi-file refactors, preview/prod deployments, waiting for external processes.

```bash
bash /home/openclaw/.openclaw/workspace/scripts/spawn-agent.sh \
  1484763611896479865 \
  "Do <task>. cd /home/openclaw/dev/yt-summarizer. Write PENDING.md at start with current step. Update PENDING.md after each action. Post result to this channel when done."

# GH Actions monitoring
bash /home/openclaw/.openclaw/workspace/scripts/spawn-gh-monitor.sh <run-id> 1484763611896479865
```

**NEVER say 'monitoring', 'watching', or 'continuing to monitor'** — spawn instead.

---

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

## CI / Merge Rules
- **Never merge a PR with failing checks** — all checks must be green before merging
- If a check is failing, fix the root cause. Do not skip, disable, or downgrade tests to pass CI
- Do not change a failing test to a warning/non-fatal just to unblock a merge — fix the underlying issue
- If a check failure is genuinely difficult to fix (intermittent infra issue, unclear root cause, requires credentials you don't have), post to Discord explaining the blocker and wait for instruction
- If multiple fix attempts fail, post to Discord with what you tried and stop — do not merge anyway
