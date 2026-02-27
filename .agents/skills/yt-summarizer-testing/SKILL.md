---
name: yt-summarizer-testing
description: Testing patterns and commands for the YT Summarizer project including pytest, Vitest, Playwright, and PowerShell test automation
license: MIT
---

# YT Summarizer Testing

## Purpose
Comprehensive testing guidance for the YT Summarizer project covering Python (pytest), TypeScript (Vitest), E2E (Playwright), and PowerShell automation scripts.

## When to Use
- Writing new tests for any component
- Running test suites during development
- Debugging test failures
- Setting up test fixtures and mocks
- Understanding test organization

## Do Not Use When
- Writing production code (use fastapi-patterns or other skills)
- Debugging application bugs (use logging and debugging tools)
- Performance testing (requires specialized tools)

## Test Organization

```
Project Structure:
services/api/tests/          # Python API tests
services/workers/tests/      # Worker tests
services/shared/tests/       # Shared library tests
apps/web/src/__tests__/      # Frontend Vitest tests
apps/web/e2e/               # Playwright E2E tests
```

## Testing Commands

### Unified Test Runner (PowerShell)

**Run all tests**
```powershell
./scripts/run-tests.ps1
```

**Component-specific tests**
```powershell
./scripts/run-tests.ps1 -Component api
./scripts/run-tests.ps1 -Component workers
./scripts/run-tests.ps1 -Component shared
./scripts/run-tests.ps1 -Component web
./scripts/run-tests.ps1 -Component e2e
```

**Integration only**
```powershell
./scripts/run-tests.ps1 -Mode integration
```

**E2E only**
```powershell
./scripts/run-tests.ps1 -Mode e2e
```

### Python Tests (pytest)

**Run specific test file**
```bash
cd services/api
uv run pytest tests/test_videos.py
```

**Run specific test function**
```bash
cd services/api
uv run pytest tests/test_videos.py::test_create_video
```

**Run tests matching pattern**
```bash
cd services/api
uv run pytest tests/ -k "video"
```

**Run with coverage**
```bash
cd services/api
uv run pytest --cov=src --cov-report=html
```

**Debug failing test**
```bash
cd services/api
uv run pytest tests/test_videos.py::test_create_video -v --tb=short
```

### Frontend Tests (Vitest)

**Run all tests**
```bash
cd apps/web
npm run test:run
```

**Run specific test file**
```bash
cd apps/web
npx vitest run src/__tests__/components/SubmitVideoForm.test.tsx
```

**Run in watch mode**
```bash
cd apps/web
npm run test
```

**Run with coverage**
```bash
cd apps/web
npm run test:run -- --coverage
```

### E2E Tests (Playwright)

**Run all E2E tests**
```bash
cd apps/web
npx playwright test
```

**Run specific test**
```bash
cd apps/web
npx playwright test e2e/smoke.spec.ts
```

**Run with visible browser**
```bash
cd apps/web
npx playwright test --headed
```

**Run in debug mode**
```bash
cd apps/web
npx playwright test --debug
```

**Generate test code**
```bash
cd apps/web
npx playwright codegen http://localhost:3000
```

## Test Patterns

### Python Fixtures

**Database fixture**
```python
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

@pytest.fixture
async def db() -> AsyncSession:
    async with get_db() as session:
        yield session
        await session.rollback()
```

**API client fixture**
```python
from fastapi.testclient import TestClient

@pytest.fixture
def client():
    from api.main import app
    return TestClient(app)
```

**Mock fixture**
```python
from unittest.mock import Mock, patch

@pytest.fixture
def mock_openai():
    with patch("services.openai_client.OpenAI") as mock:
        yield mock
```

### Frontend Testing (Vitest)

**Component test**
```typescript
import { render, screen } from '@testing-library/react'
import { SubmitVideoForm } from '@/components/SubmitVideoForm'

describe('SubmitVideoForm', () => {
  it('renders form elements', () => {
    render(<SubmitVideoForm />)
    expect(screen.getByLabelText('Video URL')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Submit' })).toBeInTheDocument()
  })
})
```

**Hook test**
```typescript
import { renderHook, waitFor } from '@testing-library/react'
import { useHealthCheck } from '@/hooks/useHealthCheck'

describe('useHealthCheck', () => {
  it('returns health status', async () => {
    const { result } = renderHook(() => useHealthCheck())
    await waitFor(() => {
      expect(result.current.status).toBe('healthy')
    })
  })
})
```

**API mocking (MSW)**
```typescript
import { rest } from 'msw'
import { setupServer } from 'msw/node'

const server = setupServer(
  rest.get('/api/health', (req, res, ctx) => {
    return res(ctx.json({ status: 'healthy' }))
  })
)

beforeAll(() => server.listen())
afterEach(() => server.resetHandlers())
afterAll(() => server.close())
```

### E2E Testing (Playwright)

**Basic test**
```typescript
import { test, expect } from '@playwright/test'

test('user can submit video', async ({ page }) => {
  await page.goto('/')
  await page.fill('input[name="url"]', 'https://youtube.com/watch?v=123')
  await page.click('button[type="submit"]')
  await expect(page.locator('.success-message')).toBeVisible()
})
```

**Authenticated test**
```typescript
test('authenticated user sees library', async ({ page }) => {
  // Login via API
  await page.request.post('/api/auth/login', {
    data: { email: 'test@example.com', password: 'password' }
  })

  await page.goto('/library')
  await expect(page.locator('.video-list')).toBeVisible()
})
```

**Visual regression**
```typescript
test('homepage visual regression', async ({ page }) => {
  await page.goto('/')
  await expect(page).toHaveScreenshot('homepage.png')
})
```

## Pre-commit Testing

**Run pre-commit hooks**
```bash
python -m pre_commit run --all-files --verbose
```

**Run specific hook**
```bash
python -m pre_commit run ruff --all-files
```

## Best Practices

1. **Use unified test runner** `./scripts/run-tests.ps1` for CI/CD alignment
2. **Write tests first** for new features (TDD approach)
3. **Mock external services** (OpenAI, YouTube API) in unit tests
4. **Use factories** for test data creation, not fixtures with hardcoded data
5. **Test behavior, not implementation** - avoid testing private methods
6. **Keep tests fast** - use in-memory DB, mock slow operations
7. **E2E tests require Aspire** - ensure orchestration is running
8. **Use `-Component` flag** for quick iteration, but run full suite before commit
9. **Never use `-SkipE2E`** for final verification
10. **Clean up resources** in test teardown (DB connections, temp files)

## Debugging Failed Tests

**Python**
```bash
# Verbose output
uv run pytest -v --tb=long

# Stop on first failure
uv run pytest -x

# Run with debugger
uv run pytest --pdb
```

**Frontend**
```bash
# Debug specific test
npx vitest run --reporter=verbose

# Watch mode with debug
npm run test -- --reporter=verbose
```

**E2E**
```bash
# Show browser
npx playwright test --headed

# Debug mode
npx playwright test --debug

# Trace viewer
npx playwright test --trace=on
npx playwright show-trace trace.zip
```
