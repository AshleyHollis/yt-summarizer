# Developer Quickstart: YT Summarizer

**Feature Branch**: `001-product-spec`  
**Created**: 2025-12-13

---

## Overview

This guide gets you running YT Summarizer locally using .NET Aspire for orchestration.

**Prerequisites**:
- .NET 8 SDK (for Aspire orchestration only)
- Python 3.11+
- Node.js 20+
- Docker Desktop
- Azure CLI (for deployment only)
- Git

---

## Repository Structure

```text
yt-summarizer/
├── apps/web/              # Next.js frontend
├── services/
│   ├── api/               # Python FastAPI
│   ├── workers/           # Python workers
│   ├── shared/            # Shared Python package
│   └── aspire/            # .NET Aspire AppHost (orchestration)
├── db/migrations/         # Alembic migration scripts
└── docs/                  # Documentation
```

---

## Initial Setup

### 1. Clone the Repository

```bash
git clone https://github.com/AshleyHollis/yt-summarizer.git
cd yt-summarizer
```

### 2. Install Dependencies

```bash
# Frontend
cd apps/web
npm install
cd ../..

# Python API + Workers (shared virtual environment)
cd services
python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
# source .venv/bin/activate
pip install -r api/requirements.txt
pip install -r workers/requirements.txt
pip install -e shared/  # Install shared package in editable mode
cd ..

# .NET Aspire (for orchestration only)
cd services/aspire/AppHost
dotnet restore
cd ../../..
```

### 3. Configure Local Secrets

Create `.env` files for local development (not committed to repo):

**services/.env** (shared by API and workers):
```bash
OPENAI_API_KEY=your-api-key-here
DATABASE_URL=mssql+pyodbc://sa:YourStrong@Passw0rd@localhost:1433/ytsummarizer?driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes
AZURE_STORAGE_CONNECTION_STRING=UseDevelopmentStorage=true
```

---

## Running Locally

### Option A: Using .NET Aspire (Recommended)

Aspire orchestrates all services together:

```bash
cd services/aspire/AppHost
dotnet run
```

This starts:
- **Web** (Next.js) at http://localhost:3000
- **API** (Python FastAPI) at http://localhost:8000
- **Workers** (Python containers)
- **SQL Server** (container or connection)
- **Azurite** (blob/queue emulator)

Open the **Aspire Dashboard** at http://localhost:15888 to view all services.

> **Note**: Aspire orchestrates the Python services via Docker containers. The .NET SDK is only needed for running the Aspire host.

### Option B: Running Services Individually

If you prefer to run services separately:

**Terminal 1 - API**:
```bash
cd services
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
uvicorn api.src.api.main:app --reload --port 8000
```

**Terminal 2 - Frontend**:
```bash
cd apps/web
npm run dev
```

**Terminal 3 - Workers** (each worker in separate terminal):
```bash
cd services
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
python -m workers.transcribe.main
```

---

## Database Setup

### Local SQL Server (Docker)

If not using Aspire's managed SQL:

```bash
docker run -e "ACCEPT_EULA=Y" -e "SA_PASSWORD=YourStrong@Passw0rd" \
  -p 1433:1433 --name sql-ytsummarizer \
  -d mcr.microsoft.com/mssql/server:2022-latest
```

### Run Migrations

```bash
cd services
source .venv/bin/activate

# Run Alembic migrations
alembic upgrade head
```

### Azure SQL (Development)

For development against Azure SQL, update `services/.env`:

```bash
DATABASE_URL=mssql+pyodbc://user:password@your-server.database.windows.net:1433/ytsummarizer?driver=ODBC+Driver+18+for+SQL+Server
```

---

## Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `OPENAI_API_KEY` | OpenAI API key | Yes |
| `DATABASE_URL` | SQLAlchemy connection string | Yes |
| `AZURE_STORAGE_CONNECTION_STRING` | Azure Storage connection | Yes |
| `ASPIRE_DASHBOARD_PORT` | Aspire dashboard port | No (default: 15888) |

### config.py (Python settings)

```python
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    database_url: str
    openai_api_key: str
    openai_model: str = "gpt-4o"
    embedding_model: str = "text-embedding-3-small"
    azure_storage_connection_string: str = ""
    
    class Config:
        env_file = ".env"
```

---

## Common Tasks

### Submit a Test Video

```bash
curl -X POST http://localhost:8000/api/v1/videos \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ"}'
```

### Check Job Status

```bash
curl http://localhost:8000/api/v1/jobs/{jobId}
```

### Query the Copilot

```bash
curl -X POST http://localhost:8000/api/v1/copilot/query \
  -H "Content-Type: application/json" \
  -d '{"query": "What is discussed in this video?"}'
```

### View Library

Open http://localhost:3000/library in your browser.

---

## Testing

### Run All Tests

```bash
# Python tests (API + workers)
cd services
source .venv/bin/activate
pytest api/tests/ workers/tests/

# E2E tests (requires services running)
cd apps/web
npm run test:e2e
```

### Run Specific Test Categories

```bash
# Unit tests only
pytest -m unit

# Integration tests (requires DB)
pytest -m integration
```

---

## Troubleshooting

### "Database warming up" errors

Azure SQL serverless may pause after inactivity. The API handles this with retries. Wait ~30 seconds for cold start.

### Workers not processing jobs

1. Check queue connection string
2. Verify workers are running: `docker ps` or check Aspire dashboard
3. Check worker logs for errors

### CORS errors in browser

Ensure API allows frontend origin in `main.py`:

```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

### OpenAI rate limiting

Workers implement exponential backoff. If persistent:
- Check API key validity
- Review quota in OpenAI dashboard
- Increase delay between calls in worker config

---

## Next Steps

1. **Ingest test videos**: Start with 5-10 videos to validate the pipeline
2. **Test copilot queries**: Try various question types
3. **Review observability**: Check Aspire dashboard for traces and logs
4. **Deploy to Azure**: See [deployment guide](../docs/runbooks/deployment.md)

---

## Useful Commands

```bash
# Rebuild all containers
docker compose -f services/aspire/docker-compose.yml build

# View logs
docker logs -f ytsummarizer-api

# Reset database
cd services && alembic downgrade base && alembic upgrade head

# Generate new migration
alembic revision --autogenerate -m "description"

# Generate API client from OpenAPI
npm run generate:api-client

# Format code
black services/
ruff check services/ --fix
npm run format
```

---

**Happy hacking!** 🎬
