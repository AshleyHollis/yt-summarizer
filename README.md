# YouTube Summarizer

AI-powered YouTube video summarizer that extracts transcripts, generates summaries using OpenAI, and provides semantic search across video content.

## Architecture

- **Frontend**: Next.js 14+ with TypeScript, TailwindCSS, App Router
- **API**: Python 3.11+ with FastAPI, SQLAlchemy
- **Workers**: Python background processors (transcribe, summarize, embed, relationships)
- **Database**: Azure SQL (SQL Server locally)
- **Storage**: Azure Blob Storage (Azurite locally)
- **Queue**: Azure Queue Storage (Azurite locally)
- **Orchestration**: .NET Aspire for local development

## Prerequisites

- [.NET 9 SDK](https://dotnet.microsoft.com/download/dotnet/9.0)
- [Python 3.11+](https://www.python.org/downloads/)
- [Node.js 20+](https://nodejs.org/)
- [Docker Desktop](https://www.docker.com/products/docker-desktop/)
- [uv](https://docs.astral.sh/uv/) (Python package manager)

## Project Structure

```
├── apps/
│   └── web/                 # Next.js frontend
├── services/
│   ├── api/                 # FastAPI REST API
│   ├── workers/             # Background job processors
│   │   ├── transcribe/      # YouTube transcript extraction
│   │   ├── summarize/       # OpenAI summarization
│   │   ├── embed/           # Embedding generation
│   │   └── relationships/   # Channel/playlist discovery
│   ├── shared/              # Shared Python code
│   │   ├── db/              # Database models & connections
│   │   ├── queue/           # Azure Queue client
│   │   ├── blob/            # Azure Blob client
│   │   └── logging/         # Structured logging
│   └── aspire/              # .NET Aspire orchestration
│       ├── AppHost/         # Orchestration host
│       └── ServiceDefaults/ # Shared service config
├── db/                      # Database documentation
├── infra/                   # Infrastructure as Code
└── docs/                    # Project documentation
```

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/AshleyHollis/yt-summarizer.git
cd yt-summarizer
```

### 2. Set up environment variables

Copy the example environment files:

```bash
# API service
cp services/api/.env.example services/api/.env

# Workers service
cp services/workers/.env.example services/workers/.env

# Web frontend
cp apps/web/.env.example apps/web/.env.local
```

Edit each `.env` file and add your OpenAI API key:

```
OPENAI_API_KEY=sk-your-key-here
```

### 3. Install dependencies

```bash
# Frontend
cd apps/web
npm install

# API
cd ../../services/api
uv sync

# Workers
cd ../workers
uv sync

# Shared
cd ../shared
uv sync
```

### 4. Start with Aspire

The easiest way to run the full stack locally:

```bash
cd services/aspire/AppHost
dotnet run
```

This will:
- Start Azurite (Azure Storage emulator) for Blob and Queue storage
- Start SQL Server in a container
- Start the FastAPI API on http://localhost:8000
- Start the Next.js frontend on http://localhost:3000
- Open the Aspire dashboard for monitoring

### 5. Access the application

- **Frontend**: http://localhost:3000
- **API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
- **Aspire Dashboard**: https://localhost:17298 (or check terminal output)

## Development

### Running individual services

**Frontend:**
```bash
cd apps/web
npm run dev
```

**API:**
```bash
cd services/api
uv run uvicorn src.api.main:app --reload --host 0.0.0.0 --port 8000
```

**Workers (example - transcribe):**
```bash
cd services/workers
uv run python -m transcribe.main
```

### Running tests

The project has comprehensive tests at multiple levels:

#### Quick smoke test (verify deployment works)

```bash
# Run after starting Aspire to verify core functionality
.\scripts\smoke-test.ps1
```

#### Full test suite

```bash
# Run all unit tests (fast, no infrastructure required)
.\scripts\run-tests.ps1

# Run tests for specific component
.\scripts\run-tests.ps1 -Component web
.\scripts\run-tests.ps1 -Component api
.\scripts\run-tests.ps1 -Component workers

# Run integration tests (requires Aspire running)
.\scripts\run-tests.ps1 -Mode integration

# Run E2E tests (requires Aspire running)
.\scripts\run-tests.ps1 -Mode e2e

# Run with coverage
.\scripts\run-tests.ps1 -Coverage
```

#### Running tests manually

**Frontend (Vitest + Playwright):**
```bash
cd apps/web

# Unit tests
npm run test:run

# E2E tests (start Aspire first)
$env:USE_EXTERNAL_SERVER = "true"
npm run test:e2e

# E2E with interactive UI
npm run test:e2e:ui
```

**API (pytest):**
```bash
cd services/api

# Unit and integration tests
uv run pytest

# Include live E2E tests (start Aspire first)
$env:E2E_TESTS_ENABLED = "true"
uv run pytest -m ""

# With coverage
uv run pytest --cov=api --cov-report=html
```

**Workers (pytest):**
```bash
cd services/workers
uv run pytest
```

### Test Types

| Type | Description | Infrastructure Required |
|------|-------------|------------------------|
| Unit | Fast, mocked dependencies | None |
| Integration | Database + queue mocks | None |
| E2E | Full stack end-to-end | Aspire running |

### Key test files

- `apps/web/e2e/smoke.spec.ts` - Frontend smoke tests
- `apps/web/e2e/video-flow.spec.ts` - Full video submission flow
- `services/api/tests/test_pipeline.py` - Full pipeline integration
- `services/api/tests/test_videos.py` - Video API endpoints
- `services/workers/tests/test_workers.py` - Worker processing

### Linting

```bash
# Frontend (ESLint + Prettier)
cd apps/web
npm run lint
npm run format

# Python services (ruff)
cd services/api
uv run ruff check .
uv run ruff format .
```

### Database migrations

```bash
cd services/shared

# Create a new migration
uv run alembic revision --autogenerate -m "description"

# Apply migrations
uv run alembic upgrade head

# Rollback one migration
uv run alembic downgrade -1
```

## Configuration

### Environment Variables

| Variable | Service | Description |
|----------|---------|-------------|
| `DATABASE_URL` | API, Workers | SQL Server connection string |
| `AZURE_STORAGE_CONNECTION_STRING` | API, Workers | Azure/Azurite storage connection |
| `OPENAI_API_KEY` | Workers | OpenAI API key for summarization |
| `NEXT_PUBLIC_API_URL` | Web | Public API URL (browser) |
| `API_URL` | Web | Internal API URL (SSR) |

## License

MIT
