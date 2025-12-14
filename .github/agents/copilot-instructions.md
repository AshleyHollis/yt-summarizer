# yt-summarizer Development Guidelines

Auto-generated from all feature plans. Last updated: 2025-12-13

## Active Technologies
- Python 3.11, TypeScript 5.x + FastAPI, yt-dlp, Next.js 14, React 18 (001-product-spec)
- Azure SQL (serverless), Azure Blob, Azure Storage Queue (001-product-spec)



## Project Structure

```text
backend/
frontend/
tests/
```

## Commands

# Start Aspire (Windows PowerShell - runs as background process)
Start-Process -FilePath "dotnet" -ArgumentList "run", "--project", "services\aspire\AppHost\AppHost.csproj" -WorkingDirectory "services\aspire\AppHost"

# Start Aspire (macOS/Linux - runs in foreground)
cd services/aspire/AppHost && dotnet run

# Run API tests
cd services/api; .\.venv\Scripts\python.exe -m pytest tests/ -v -p no:asyncio

# Run frontend tests
cd apps/web; npm run test:run

# Run E2E tests (requires Aspire + frontend running)
cd apps/web; $env:USE_EXTERNAL_SERVER = "true"; npx playwright test

## 🚨 CRITICAL: Test Verification Requirements

**NEVER mark a task as complete [X] without passing tests.**

Before marking ANY implementation task complete:
1. Run API tests: Must pass 100%
2. Run frontend tests: Must pass 100%
3. Run E2E tests: Must pass 100%
4. Update verification checklist in specs/*/checklists/verification.md

If tests fail, fix the issue and re-run until all pass.

## Code Style

General: Follow standard conventions

## Recent Changes
- 001-product-spec: Added Python 3.11, TypeScript 5.x + FastAPI, yt-dlp, Next.js 14, React 18



<!-- MANUAL ADDITIONS START -->
<!-- MANUAL ADDITIONS END -->
