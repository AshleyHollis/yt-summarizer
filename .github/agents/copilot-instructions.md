````chatagent
# yt-summarizer Development Guidelines

Auto-generated from all feature plans. Last updated: 2025-12-14

## Active Technologies
- Python 3.11, TypeScript 5.x + FastAPI, yt-dlp, Next.js 14, React 18 (001-product-spec)
- Azure SQL (serverless), Azure Blob, Azure Storage Queue (001-product-spec)
- GitHub Actions YAML, Terraform HCL, Python 3.11, Node.js 20+ + GitHub Actions, Terraform azurerm provider, Azure CLI (002-azure-cicd)
- Azure Storage Account (Terraform state), Azure Container Registry (images) (002-azure-cicd)



## Project Structure

```text
apps/web/           # Next.js frontend
services/api/       # FastAPI backend
services/workers/   # Background job workers
services/shared/    # Shared Python package
services/aspire/    # .NET Aspire orchestration
```

## Commands

# Start Aspire (Windows PowerShell - runs as background process)
Start-Process -FilePath "dotnet" -ArgumentList "run", "--project", "services\aspire\AppHost\AppHost.csproj" -WorkingDirectory "services\aspire\AppHost" -WindowStyle Hidden

# Start Aspire (macOS/Linux - runs in foreground)
cd services/aspire/AppHost && dotnet run

## Test Verification Requirements

**NEVER mark a task as complete [X] without passing ALL automated tests.**
**NO MANUAL TESTING REQUIRED** - all verification is automated.

### ALL Test Suites (Must All Pass 100%)

**API Tests:**
```powershell
cd services/api && python -m pytest tests/ -v -p no:asyncio
```

**Worker Tests (includes Message Contracts):**
```powershell
cd services/workers && python -m pytest tests/ -v -p no:asyncio
```

**Shared Package Tests:**
```powershell
cd services/shared && python -m pytest tests/ -v -p no:asyncio
```

**Frontend Tests:**
```powershell
cd apps/web && npm run test:run
```

**E2E Tests (requires Aspire + frontend running):**
```powershell
cd apps/web && $env:USE_EXTERNAL_SERVER = "true"; npx playwright test
```

### Test Coverage Categories

| Category | Location | Purpose |
|----------|----------|---------|
| Unit Tests | `*/tests/` | Route handlers, services, components |
| Integration Tests | `*/tests/` | API to DB, Worker to Queue |
| Message Contracts | `services/workers/tests/test_message_contracts.py` | Worker-to-worker data flow |
| E2E Tests | `apps/web/e2e/` | Full user story flows |

### Verification Gate

Before marking ANY implementation task complete:
1. Run ALL test suites listed above
2. All must pass 100% (0 failures)
3. Update verification checklist in specs/*/checklists/verification.md

If tests fail, fix the issue and re-run until all pass.

## Code Style

General: Follow standard conventions

## Recent Changes
- 002-azure-cicd: Added GitHub Actions YAML, Terraform HCL, Python 3.11, Node.js 20+ + GitHub Actions, Terraform azurerm provider, Azure CLI
- 001-product-spec: Added Python 3.11, TypeScript 5.x + FastAPI, yt-dlp, Next.js 14, React 18



<!-- MANUAL ADDITIONS START -->
<!-- MANUAL ADDITIONS END -->

````
