# YT Summarizer Workers

Background job processors for YT Summarizer.

## Workers

- **transcribe**: Fetch/generate video transcripts
- **summarize**: Generate summaries via OpenAI
- **embed**: Chunk transcripts and generate embeddings
- **relationships**: Extract video relationships

## Development

```bash
cd services/workers
python -m venv .venv
.venv\Scripts\activate  # Windows
pip install -e ".[dev]"
pip install -e "../shared"  # Install shared package
```

## Testing

```bash
pytest
```
