# YT Summarizer API

FastAPI backend for YT Summarizer.

## Development

```bash
cd services/api
python -m venv .venv
.venv\Scripts\activate  # Windows
pip install -e ".[dev]"
uvicorn src.api.main:app --reload --port 8000
```

## Testing

```bash
pytest
```

# Force preview deployment
