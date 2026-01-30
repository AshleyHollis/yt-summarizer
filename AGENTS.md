# Agent Instructions (YT Summarizer)

<purpose>
Essential rules for AI coding assistants. Discover implementation details by reading files as needed.
</purpose>

## Critical Rules

<critical_rules>
1. **Test before completion**: Run `./scripts/run-tests.ps1` before marking ANY task complete
2. **Pre-commit checks**: Run `python -m pre_commit run --all-files --verbose` before pushing
3. **E2E tests required**: Never use `-SkipE2E` for final verification
4. **Aspire orchestration**: Start Aspire (`aspire run`) before E2E tests if not running
5. **Secret management**: ALL secrets MUST be in Azure Key Vault via Terraform (never manual)
6. **Documentation**: Prefer https://aspire.dev and https://learn.microsoft.com/dotnet/aspire
</critical_rules>

## Architecture Overview

<architecture>
**Stack**: Next.js frontend + FastAPI backend + Python workers orchestrated by .NET Aspire

**Directories**:
- `apps/web` - Next.js (TypeScript, Tailwind)
- `services/api` - FastAPI
- `services/workers` - Python background workers
- `services/shared` - Shared Python libs (DB, logging, queue)
- `services/aspire` - Aspire orchestration (AppHost.cs)
- `scripts` - PowerShell automation
- `infra` - Terraform + K8s manifests
</architecture>

## Quick Start Commands

<commands>
**Setup**:
```bash
# Frontend
cd apps/web && npm install

# Python services (API/workers/shared)
cd services/{api|workers|shared} && uv sync
```

**Run**:
```bash
aspire run                    # Full stack via Aspire
./scripts/run-tests.ps1       # All tests including E2E
./scripts/run-tests.ps1 -Component api  # Specific component
```

**Migrations**:
```bash
cd services/shared
uv run alembic revision --autogenerate -m "description"
uv run alembic upgrade head
```
</commands>

## Code Style Essentials

<style>
**Line length**: 100 chars (Python + TypeScript)

**Python**:
- Type hints everywhere: `list[str]`, `dict[str, Any]`, `str | None`
- Use `dataclass` for payloads
- Structured logging: `get_logger(__name__)` with context fields
- Async DB: `AsyncSession` from `shared.db.connection`

**TypeScript**:
- Named exports (rare defaults)
- PascalCase components/types, camelCase variables/functions
- Hooks: `useX` naming in `src/hooks`
- API types: `src/services/api.ts`

**Formatting**:
- Python: `ruff format .` (100 chars, imports sorted)
- TypeScript: Prettier (singleQuote, semi, printWidth 100)
</style>

## Infrastructure Notes

<infra>
**Validation**: Use `.github/actions/validate` for K8s/Terraform validation
**Deployment**: Auto-recovery scripts in `scripts/ci/lib/` (validate-deployment.sh, argocd-utils.sh)
**K8s Previews**: Use placeholders (`__PR_NUMBER__`, `__PREVIEW_HOST__`) in `k8s/overlays/preview/patches/`
**Queue Config**: `QUEUE_POLL_INTERVAL=10`, `QUEUE_BATCH_SIZE=32` in AppHost.cs
</infra>

## Discovery Pattern

<discovery>
When you need implementation details:
1. Read relevant files (package.json, pyproject.toml, config files)
2. Explore code using glob/grep
3. Check scripts/ for automation examples
4. Read docs/ for architecture patterns
5. **Reference `docs/ai-skills.md` for available CLIs and tools**

This file provides rules; codebase provides details.
</discovery>

## Available Skills

<skills>
**Reference**: `docs/ai-skills.md` - Complete list of available CLIs and tools

**Key tools available**:
- Azure CLI (az) - Azure resource management
- kubectl - Kubernetes operations
- Terraform - Infrastructure as Code
- GitHub CLI (gh) - GitHub operations
- Kustomize - K8s manifest management
- npm - Node.js/frontend tooling
- uv - Python package management
- PowerShell - Windows automation scripts
- Playwright MCP - Browser automation

**Guideline**: Use these CLIs directly instead of asking users to run commands manually.
</skills>
