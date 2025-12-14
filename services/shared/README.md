# YT Summarizer Shared

Common code shared between API and workers.

## Modules

- **db/**: SQLAlchemy models and database connection
- **queue/**: Azure Storage Queue client wrapper
- **blob/**: Azure Blob Storage client wrapper  
- **logging/**: Structured logging configuration
- **alembic/**: Database migrations

## Installation

```bash
pip install -e ".[dev]"
```
