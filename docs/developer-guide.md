# Developer Onboarding Guide

Welcome to the YT Summarizer codebase! This guide will help you set up your development environment and understand the project structure.

## Prerequisites

Before starting, ensure you have the following installed:

| Tool | Version | Purpose |
|------|---------|---------|
| **Node.js** | 18+ | Frontend development |
| **Python** | 3.11+ | API and workers |
| **.NET SDK** | 8.0+ | Aspire orchestration |
| **Docker Desktop** | Latest | Containers (SQL, Azurite) |
| **Azure CLI** | Latest | Azure resource management |
| **Git** | Latest | Version control |

### Verify Installation

```bash
node --version    # v18.x or higher
python --version  # Python 3.11.x
dotnet --version  # 8.0.x
docker --version  # Docker version 24.x or higher
az --version      # Azure CLI 2.x
```

## Repository Structure

```
yt-summarizer/
├── apps/
│   └── web/                    # Next.js frontend
├── services/
│   ├── api/                    # FastAPI backend
│   ├── workers/                # Background job processors
│   │   ├── transcribe/         # YouTube transcript extraction
│   │   ├── summarize/          # AI summarization
│   │   ├── embed/              # Embedding generation
│   │   └── relationships/      # Relationship extraction
│   ├── shared/                 # Shared Python package
│   └── aspire/                 # .NET Aspire orchestration
│       └── AppHost/            # AppHost configuration
├── docs/                       # Documentation
├── specs/                      # Feature specifications
├── scripts/                    # Utility scripts
└── tools/                      # Development tools
```

## Getting Started

### 1. Clone the Repository

```bash
git clone https://github.com/AshleyHollis/yt-summarizer.git
cd yt-summarizer
```

### 2. Set Up Environment Variables

Copy the example environment files and configure:

```bash
# API configuration
cp services/api/.env.example services/api/.env

# Workers configuration  
cp services/workers/.env.example services/workers/.env

# Frontend configuration
cp apps/web/.env.example apps/web/.env.local
```

Required secrets (get from team or Azure Key Vault):
- `OPENAI_API_KEY` - OpenAI API key for summarization/embeddings
- `AZURE_OPENAI_ENDPOINT` - Azure OpenAI endpoint (optional)
- `AZURE_OPENAI_API_KEY` - Azure OpenAI key (optional)

### 3. Set Up Python Virtual Environments

Each Python service has its own virtual environment:

```bash
# API
cd services/api
python -m venv .venv
.venv\Scripts\activate  # Windows
pip install -e ".[dev]"
pip install -e ../shared

# Workers (each worker has its own venv)
cd services/workers/transcribe
python -m venv .venv
.venv\Scripts\activate
pip install -e "../../shared"
pip install -e "..[dev]"
# Repeat for summarize, embed, relationships

# Shared package
cd services/shared
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
```

### 4. Set Up Frontend

```bash
cd apps/web
npm install
```

### 5. Run with Aspire

The easiest way to run all services:

```bash
# From repository root
aspire run
```

This starts:
- SQL Server 2025 (with vector support)
- Azurite (Azure Storage emulator)
- FastAPI (http://localhost:8000)
- Next.js (http://localhost:3000)
- All workers

Aspire dashboard: http://localhost:15888

## Running Tests

### Python Tests

```bash
# API tests
cd services/api
python -m pytest tests/ -v

# Worker tests
cd services/workers
python -m pytest tests/ -v

# Shared package tests
cd services/shared
python -m pytest tests/ -v
```

### Frontend Tests

```bash
cd apps/web

# Unit tests
npm run test:run

# Watch mode
npm run test
```

### E2E Tests

```bash
cd apps/web

# Requires Aspire running
$env:USE_EXTERNAL_SERVER = "true"
npx playwright test

# With UI
npx playwright test --ui
```

### Full Test Gate

```bash
.\.specify\scripts\powershell\run-test-gate.ps1
```

## CI: Kustomize validation and preview quota check

The CI pipeline now validates that Kustomize can build overlays and that the preview overlay's total CPU requests fit within a configured quota to prevent preview rollouts from being blocked by ResourceQuota limits.

Key points:
- The workflow job `Kustomize & Preview Quota Validate` runs on PRs and will fail the build if `kustomize build` errors for an overlay or if the preview overlay exceeds the configured CPU threshold (currently 1500m).
- Validation logic is implemented in `scripts/ci/validate_kustomize.py` which parses the rendered manifests and sums CPU requests across deployments.

## Adding New Features

### Adding a New API Endpoint

1. **Create Pydantic models** in `services/api/src/api/models/`
2. **Create service** in `services/api/src/api/services/`
3. **Create route** in `services/api/src/api/routes/`
4. **Register route** in `services/api/src/api/main.py`
5. **Add tests** in `services/api/tests/`

Example route:

```python
# services/api/src/api/routes/example.py
from fastapi import APIRouter, Depends
from ..models.example import ExampleResponse
from ..services.example_service import ExampleService

router = APIRouter(prefix="/api/v1/example", tags=["Example"])

@router.get("/", response_model=ExampleResponse)
async def get_example():
    service = ExampleService()
    return await service.get_example()
```

### Adding a New Worker Stage

1. **Create worker directory** in `services/workers/<stage>/`
2. **Create `__main__.py`** with worker entry point
3. **Create `worker.py`** with processing logic
4. **Add queue configuration** to shared config
5. **Register in Aspire AppHost** (`AppHost.cs`)

Worker template:

```python
# services/workers/<stage>/worker.py
from shared.worker.base_worker import BaseWorker, WorkerResult, run_worker

class MyStageWorker(BaseWorker):
    def __init__(self):
        super().__init__(
            queue_name="my-input-queue",
            service_name="my-stage-worker"
        )
    
    async def process_message(self, message, correlation_id: str) -> WorkerResult:
        # Processing logic - telemetry is automatic
        # Span events like message_received, processing_started are added by BaseWorker
        result = await self.do_work(message)
        return WorkerResult.success(data=result)

if __name__ == "__main__":
    run_worker(MyStageWorker)
```

The `BaseWorker` automatically provides:
- **Span Links**: Links consumer spans back to producer spans
- **Span Events**: `message_received`, `message_parsed`, `processing_completed`, etc.
- **Retry Logic**: Exponential backoff with max retries
- **Dead Letter Handling**: Messages that exceed retries are dead-lettered

### Adding a Frontend Component

1. **Create component** in `apps/web/src/components/<feature>/`
2. **Add types** if needed in `apps/web/src/types/`
3. **Add API calls** in `apps/web/src/services/api.ts`
4. **Add tests** in `apps/web/src/__tests__/`

## Code Style

### Python (ruff)

```bash
# Check
ruff check .

# Fix automatically
ruff check --fix .

# Format
ruff format .
```

Configuration in `services/ruff.toml`.

### TypeScript (ESLint + Prettier)

```bash
cd apps/web

# Lint
npm run lint

# Format
npm run format
```

Configuration in `apps/web/eslint.config.mjs` and `.prettierrc`.

## Database Migrations

Using Alembic for database migrations:

```bash
cd services/shared

# Create migration
alembic revision --autogenerate -m "Description"

# Apply migrations
alembic upgrade head

# Rollback one version
alembic downgrade -1

# View history
alembic history
```

## Useful Commands

```bash
# Start Aspire (background)
aspire run

# View Aspire logs
Get-Content aspire.log -Tail 50 -Wait

# Run specific test
python -m pytest tests/test_specific.py::TestClass::test_method -v

# Generate OpenAPI spec
curl http://localhost:8000/openapi.json > openapi.json

# Check API health
curl http://localhost:8000/health | jq
```

## Troubleshooting

### Aspire won't start
- Check Docker is running
- Clear existing containers: `docker system prune`
- Check ports 8000, 3000 are available

### Database connection fails
- Wait for SQL Server to start (30-60 seconds)
- Check `aspire.log` for connection errors
- Verify connection string in environment

### Workers not processing
- Check queue connections in health endpoint
- Verify worker venvs are activated
- Check for errors in worker logs

### Frontend build errors
- Run `npm install` to update dependencies
- Clear `.next` folder: `rm -rf apps/web/.next`
- Check Node version matches requirements

## Getting Help

- **Documentation**: `/docs` folder
- **Specifications**: `/specs` folder
- **GitHub Issues**: For bug reports and features
- **Team Slack**: #yt-summarizer channel
