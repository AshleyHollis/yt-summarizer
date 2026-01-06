# Test Design Document

**Document Version**: 1.0  
**Last Updated**: January 2026  
**Purpose**: Define test strategy, data, and execution guidelines for YT Summarizer

---

## Table of Contents

1. [Test Architecture Overview](#test-architecture-overview)
2. [Test Pyramid](#test-pyramid)
3. [Test Types Reference](#test-types-reference)
4. [Test Data Catalog](#test-data-catalog)
5. [Running Tests](#running-tests)
6. [Environment Management](#environment-management)
7. [Cost Optimization](#cost-optimization)
8. [Test Coverage Matrix](#test-coverage-matrix)
9. [Writing New Tests](#writing-new-tests)

---

## Test Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              TEST LAYERS                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────┐   Few, slow, expensive     ┌─────────────────────────────┐│
│  │    E2E      │◄──────────────────────────►│ Full user journeys          ││
│  │  Playwright │                            │ Real LLM/AI services        ││
│  └──────▲──────┘                            │ Real video processing       ││
│         │                                   └─────────────────────────────┘│
│  ┌──────┴──────┐   Medium count             ┌─────────────────────────────┐│
│  │ Integration │◄──────────────────────────►│ API + mocked DB/queues      ││
│  │   pytest    │                            │ Service layer validation    ││
│  └──────▲──────┘                            └─────────────────────────────┘│
│         │                                                                   │
│  ┌──────┴──────┐   Many, fast, cheap        ┌─────────────────────────────┐│
│  │    Unit     │◄──────────────────────────►│ Pure logic, no I/O          ││
│  │pytest/vitest│                            │ Models, utils, components   ││
│  └─────────────┘                            └─────────────────────────────┘│
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Technology Stack

| Layer | Backend | Frontend |
|-------|---------|----------|
| **Unit** | pytest | Vitest |
| **Integration** | pytest + mocked deps | Vitest + MSW |
| **E2E** | — | Playwright |
| **Smoke** | PowerShell scripts | Playwright |

---

## Test Pyramid

### Current Test Counts (January 2026)

| Category | Count | Execution Time | Cost |
|----------|-------|----------------|------|
| **Python Shared** | 28 | ~1s | Free |
| **Python Workers** | 77 | ~5s | Free |
| **Python API** | 470 | ~3min | Free |
| **Frontend Vitest** | 217 | ~10s | Free |
| **E2E Playwright** | 13 files | ~10min | LLM tokens |
| **Total** | **792+** | ~15min | Variable |

### Recommended Ratios

- **70% Unit Tests**: Fast, isolated, cover edge cases
- **20% Integration Tests**: API with mocked DB/queue
- **10% E2E Tests**: Critical user journeys only

---

## Test Types Reference

### 1. Python Unit Tests (`services/*/tests/`)

**Purpose**: Test pure business logic without external dependencies.

**Characteristics**:
- ✅ Fast (<1s per test)
- ✅ No database, network, or queue access
- ✅ All dependencies mocked
- ✅ Free to run

**Files**:
| File | Purpose | Count |
|------|---------|-------|
| `shared/tests/test_blob_helpers.py` | Blob path utilities | ~5 |
| `shared/tests/test_job_service.py` | Job state machine logic | ~20 |
| `workers/tests/test_workers.py` | Worker message parsing, processing | ~30 |
| `workers/tests/test_message_contracts.py` | Queue message schema validation | ~20 |
| `workers/tests/test_transcribe_resilience.py` | Rate limit & retry logic | ~10 |
| `api/tests/test_models.py` | Pydantic model validation | ~50 |

**When to use**:
- Testing data transformations
- Validating Pydantic models
- Testing utility functions
- Testing worker message parsing

---

### 2. Python Integration Tests (`services/api/tests/`)

**Purpose**: Test API endpoints with mocked database session.

**Characteristics**:
- ✅ Medium speed (~0.5s per test)
- ✅ Uses FastAPI TestClient
- ✅ Database session is mocked
- ✅ No real external services

**Files**:
| File | Purpose | Count |
|------|---------|-------|
| `test_health.py` | Health endpoint responses | ~10 |
| `test_videos.py` | Video CRUD endpoints | ~40 |
| `test_jobs.py` | Job management endpoints | ~30 |
| `test_batches.py` | Batch processing endpoints | ~50 |
| `test_channels.py` | Channel ingestion endpoints | ~40 |
| `test_copilot.py` | Copilot query endpoints | ~60 |
| `test_synthesis.py` | Learning path/watchlist endpoints | ~20 |
| `test_search_service.py` | Vector search logic | ~30 |

**Design Pattern** (from `conftest.py`):
```python
@pytest.fixture
def mock_session():
    """Mock SQLAlchemy session - returns empty results by default."""
    session = AsyncMock()
    mock_result = MagicMock()
    mock_result.scalars().all.return_value = []
    mock_result.scalar_one_or_none.return_value = None
    session.execute = AsyncMock(return_value=mock_result)
    return session

@pytest.fixture
def app(mock_session):
    """FastAPI app with mocked dependencies."""
    app = create_test_app()
    app.dependency_overrides[get_session] = lambda: mock_session
    return app
```

**Note on 500 Acceptance**: Some tests accept `HTTP_500` as valid because:
- They test endpoint existence/validation without full service mocking
- The focus is on input validation (422) vs server errors
- Full happy-path testing happens in E2E tests

---

### 3. Frontend Unit Tests (`apps/web/src/__tests__/`)

**Purpose**: Test React components in isolation with mocked APIs.

**Characteristics**:
- ✅ Fast (~50ms per test)
- ✅ Uses Vitest + React Testing Library
- ✅ No real API calls
- ✅ Tests component rendering and user interactions

**Directories**:
| Directory | Purpose |
|-----------|---------|
| `__tests__/components/` | UI component tests |
| `__tests__/hooks/` | Custom hook tests |
| `__tests__/services/` | API client tests |

**Design Pattern**:
```typescript
// Mock API calls
vi.mock('@/services/api', () => ({
  submitVideo: vi.fn().mockResolvedValue({ video_id: 'test-id' }),
}));

test('shows success message after submission', async () => {
  render(<SubmitVideoForm />);
  await userEvent.type(screen.getByLabelText(/url/i), 'https://youtube.com/watch?v=abc');
  await userEvent.click(screen.getByRole('button', { name: /submit/i }));
  expect(await screen.findByText(/success/i)).toBeVisible();
});
```

---

### 4. E2E Tests (`apps/web/e2e/`)

**Purpose**: Validate complete user journeys through the real UI and backend.

**Characteristics**:
- ⚠️ Slow (10s - 3min per test)
- ⚠️ Requires Aspire running
- ⚠️ Uses real LLM services (costs money!)
- ⚠️ Depends on pre-seeded test videos

**Files**:
| File | User Story | Purpose |
|------|------------|---------|
| `smoke.spec.ts` | — | Basic UI renders, navigation works |
| `video-flow.spec.ts` | US1 | Single video submission flow |
| `channel-ingest.spec.ts` | US2 | Channel batch ingestion |
| `library.spec.ts` | US3 | Library filtering and browsing |
| `copilot.spec.ts` | US4 | Copilot query interface |
| `synthesis.spec.ts` | US6 | Learning path/watchlist UI |
| `synthesis-api.spec.ts` | US6 | Synthesis API with ordering validation |
| `explain.spec.ts` | US5 | "Why this?" transparency |
| `full-journey.spec.ts` | All | Complete ingest → query flow |
| `queue-progress.spec.ts` | US1 | Job progress tracking |
| `processing-history.spec.ts` | US1 | Processing history display |

**Global Setup** (`global-setup.ts`):
- Runs ONCE before all E2E tests
- Submits test videos (skips if already exist - 409)
- Waits for videos to have segments (min 25 segments)
- Timeout: 5 minutes max wait

---

## Test Data Catalog

### Pre-Seeded Test Videos

All test videos are automatically seeded by `global-setup.ts` when running E2E tests. These videos are chosen for:
- ✅ **Short duration** (<5 minutes) - minimizes LLM token costs
- ✅ **Auto-captions available** - avoids expensive Whisper transcription
- ✅ **Topical clusters** - tests relationship detection

#### Push-Up Cluster (Tests similarity matching)

| Video ID | Title | Duration | Channel |
|----------|-------|----------|---------|
| `IODxDxX7oi4` | The Perfect Push Up | 3:37 | Calisthenicmovement |
| `0GsVJsS6474` | You CAN do pushups, my friend! | 3:09 | Hybrid Calisthenics |
| `c-lBErfxszs` | The Perfect Push-Up (short) | 0:31 | Davis Diley |

#### Kettlebell Cluster

| Video ID | Title | Duration | Channel |
|----------|-------|----------|---------|
| `aSYap2yhW8s` | The BEST Kettlebell Swing Tutorial | 0:58 | Squat University |
| `hp3qVqIHNOI` | How To Do Kettlebell Swings | 4:37 | (Fitness Channel) |

#### Ordering Verification Videos (Learning Path Tests)

These videos have **explicit difficulty progression** for testing LLM ordering:

| Order | Video ID | Title | Level |
|-------|----------|-------|-------|
| 1 | `xxOdD929ty8` | How to Push-Up for Complete Beginners | Beginner |
| 2 | `0GsVJsS6474` | You CAN do pushups, my friend! | Intermediate |
| 3 | `IL4iDaBzu2w` | 50 Push Up Variations (Easy to Extreme) | Advanced |

**Usage in Tests**:
```typescript
import { ORDERED_TEST_VIDEOS } from './global-setup';

const expectedOrder = ORDERED_TEST_VIDEOS.pushUpProgression.expectedOrder;
// expectedOrder[0].level === 'beginner'
// expectedOrder[1].level === 'intermediate'
// expectedOrder[2].level === 'advanced'
```

### Verifying Video Has Captions

Before adding a new test video, verify it has auto-captions:

```bash
yt-dlp --list-subs "https://www.youtube.com/watch?v=VIDEO_ID"
# Look for: "Available automatic captions for VIDEO_ID"
# If you see "has no automatic captions" - the video needs Whisper (expensive!)
```

---

## Running Tests

### ⚠️ Test Gate Script (REQUIRED before marking tasks complete)

**Before marking ANY implementation task as complete, run the test gate:**

```powershell
.\.specify\scripts\powershell\run-test-gate.ps1
```

This script:
- Runs ALL test suites (API, Workers, Shared, Frontend, E2E)
- Outputs a clear PASS/FAIL result
- Writes failure details to `test-gate-failures.log` for debugging
- Auto-starts Aspire if needed for E2E tests

**Rules:**
1. **NEVER mark a task [X] if the test gate returns FAIL**
2. **NEVER rationalize skipping E2E tests** - they catch integration issues
3. Review `test-gate-failures.log` to diagnose and fix failures

**Options:**
```powershell
# Full gate (required for task completion)
.\.specify\scripts\powershell\run-test-gate.ps1

# Skip E2E (faster, but incomplete - use only during development)
.\.specify\scripts\powershell\run-test-gate.ps1 -SkipE2E

# JSON output for CI integration
.\.specify\scripts\powershell\run-test-gate.ps1 -Json
```

---

### Quick Reference

```powershell
# === Unit Tests (Fast, Free) ===
# Python shared
cd services/shared; python -m pytest tests/ -v

# Python workers
cd services/workers; python -m pytest tests/ -v

# Python API
cd services/api; python -m pytest tests/ -v

# Frontend Vitest
cd apps/web; npm run test:run

# === E2E Tests (Slow, Costs Tokens) ===
# First, start Aspire:
aspire run

# Then run E2E:
cd apps/web
$env:USE_EXTERNAL_SERVER = "true"
npx playwright test

# Run specific E2E file:
npx playwright test smoke.spec.ts

# Run with visible browser:
npx playwright test --headed

# === All Tests ===
.\scripts\run-tests.ps1 -Component all -Mode unit
.\scripts\run-tests.ps1 -Component all -Mode e2e
```

### Test Script Reference

| Script | Purpose |
|--------|---------|
| `.specify/scripts/powershell/run-test-gate.ps1` | **Pre-completion verification gate** |
| `scripts/run-tests.ps1` | Master test runner with flags |
| `scripts/smoke-test.ps1` | Quick deployment verification |
| `scripts/clean-dev.ps1` | Reset development environment |

### Test Markers (Python)

```python
@pytest.mark.unit        # No external services
@pytest.mark.integration # Uses mocked dependencies
@pytest.mark.e2e         # Requires running infrastructure
@pytest.mark.live        # Requires E2E_TESTS_ENABLED=true
```

---

## Environment Management

### Clearing Development Data

```powershell
# Remove containers only (preserves data volumes)
.\scripts\clean-dev.ps1

# Complete reset (removes all data)
.\scripts\clean-dev.ps1 -All -Force
```

### Database Reset

```powershell
# With Aspire running, connect to SQL and truncate:
$conn = "Server=localhost,57402;Database=ytsummarizer;User Id=sa;Password=YourStrong@Passw0rd;TrustServerCertificate=True"

# Or restart Aspire containers fresh:
.\scripts\clean-dev.ps1 -All
aspire run
```

### Re-seeding Test Videos

E2E global-setup automatically handles this, but to manually re-seed:

```powershell
# Delete from database first, then run E2E tests:
# Videos will be re-submitted if they return 404
cd apps/web
$env:USE_EXTERNAL_SERVER = "true"
npx playwright test smoke.spec.ts
```

---

## Cost Optimization

### Token Cost Drivers

| Operation | Approximate Cost | When Used |
|-----------|-----------------|-----------|
| Whisper transcription | ~$0.006/min audio | Videos without captions |
| Summary generation | ~$0.01/video | Every new video |
| Embedding generation | ~$0.0001/1K tokens | Every video chunk |
| Copilot query | ~$0.03/query | E2E copilot tests |
| Learning path synthesis | ~$0.05/synthesis | Synthesis E2E tests |

### Cost Reduction Strategies

#### 1. **Reuse Existing Test Videos**
- E2E tests skip videos that already exist (409 response)
- Only pay for processing once per environment
- Test data persists across runs unless explicitly cleared

#### 2. **Use Short Videos Only**
- All test videos <5 minutes
- Fewer tokens for transcript/summary
- Current catalog: 7 videos, total ~20 min content

#### 3. **Minimize LLM-Dependent Tests**
```typescript
// ❌ DON'T: Test LLM response content in UI tests
test('copilot gives good answer', async ({ page }) => {
  // This makes real LLM call every time
  await page.fill('[data-testid="chat"]', 'How do I do a pushup?');
  await expect(page.locator('.response')).toContainText('keep your core tight');
});

// ✅ DO: Test UI behavior, mock LLM response
test('copilot shows response', async ({ page }) => {
  // Test that UI renders response, not that LLM is smart
  await page.fill('[data-testid="chat"]', 'test query');
  await expect(page.locator('.response')).toBeVisible();
});
```

#### 4. **API-Level Tests for LLM Behavior**
```python
# Test synthesis ordering at API level (single LLM call)
# instead of E2E tests (LLM call + UI overhead)
@pytest.mark.integration
async def test_learning_path_orders_by_difficulty():
    # Mock LLM to return expected order
    # Verify API correctly processes response
```

#### 5. **Skip Expensive Tests Locally**

```typescript
// In E2E tests
test.skip(() => !process.env.LIVE_PROCESSING, 
  'Skipping - requires real LLM processing');
```

---

## Test Coverage Matrix

### User Story Coverage

| User Story | Unit | Integration | E2E |
|------------|------|-------------|-----|
| **US1: Single Video** | test_videos.py, test_workers.py | test_pipeline.py | video-flow.spec.ts |
| **US2: Channel Batch** | test_batches.py, test_channels.py | test_e2e_smoke.py | channel-ingest.spec.ts |
| **US3: Library Browse** | test_library.py | test_library_service.py | library.spec.ts |
| **US4: Copilot Query** | test_copilot.py | test_copilot_integration.py | copilot.spec.ts |
| **US5: Explain Why** | (in copilot tests) | test_expanded_rag.py | explain.spec.ts |
| **US6: Synthesis** | test_synthesis.py | (API tests) | synthesis.spec.ts |

### Test Overlap Analysis

| Test Type | smoke.spec.ts | video-flow.spec.ts | full-journey.spec.ts |
|-----------|---------------|--------------------|-----------------------|
| Submit page renders | ✅ | ✅ | ✅ |
| Form validation | ✅ | | |
| Video submission | | ✅ | ✅ |
| Progress tracking | | ✅ | ✅ |
| Copilot query | | | ✅ |

**Recommendation**: `full-journey.spec.ts` overlaps with both others. Consider:
1. Keep `smoke.spec.ts` for fast CI gate (no LLM)
2. Keep `video-flow.spec.ts` for US1 regression
3. Use `full-journey.spec.ts` only for release validation

---

## Writing New Tests

### Checklist for New Tests

1. **Choose the right layer**:
   - Pure logic → Unit test
   - API endpoint → Integration test
   - User journey → E2E test

2. **Reuse existing test videos** when possible

3. **Mock LLM responses** in unit/integration tests

4. **Add test to appropriate file** (see coverage matrix)

5. **Document expensive tests** with skip conditions

### Adding New Test Videos

If you need a new video for testing:

```typescript
// 1. Verify auto-captions exist
// yt-dlp --list-subs "URL"

// 2. Add to TEST_VIDEOS in global-setup.ts
const TEST_VIDEOS = [
  // ...existing videos...
  'https://www.youtube.com/watch?v=NEW_VIDEO_ID', // Short description
];

// 3. Document in this file's Test Data Catalog
```

### E2E Test Template

```typescript
import { test, expect } from '@playwright/test';

test.describe('Feature: [Name]', () => {
  test.skip(
    () => !process.env.USE_EXTERNAL_SERVER,
    'Requires backend - run with USE_EXTERNAL_SERVER=true'
  );

  test('user can [action]', async ({ page }) => {
    // Arrange
    await page.goto('/page');
    
    // Act
    await page.fill('[data-testid="input"]', 'value');
    await page.click('[data-testid="submit"]');
    
    // Assert
    await expect(page.locator('[data-testid="result"]')).toBeVisible();
  });
});
```

### API Test Template

```python
import pytest
from fastapi import status

class TestFeatureName:
    """Tests for [feature] endpoint."""
    
    def test_endpoint_returns_expected_response(self, client, headers):
        """Test [specific behavior]."""
        response = client.get("/api/v1/endpoint", headers=headers)
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "expected_field" in data
    
    @pytest.mark.asyncio
    async def test_service_handles_edge_case(self, mock_session):
        """Test [edge case] in service layer."""
        # Configure mock
        mock_session.execute.return_value.scalar_one_or_none.return_value = None
        
        # Call service
        result = await my_service.get_something()
        
        # Assert
        assert result is None
```

---

## Appendix: File Reference

### Backend Test Files

```
services/
├── shared/tests/
│   ├── conftest.py              # Shared fixtures
│   ├── test_blob_helpers.py     # Blob path utilities
│   └── test_job_service.py      # Job state transitions
├── workers/tests/
│   ├── conftest.py              # Worker fixtures
│   ├── test_workers.py          # Worker processing tests
│   ├── test_message_contracts.py # Queue message validation
│   └── test_transcribe_resilience.py  # Rate limit handling
└── api/tests/
    ├── conftest.py              # FastAPI test fixtures
    ├── test_*.py                # Endpoint tests (20+ files)
    └── __init__.py
```

### Frontend Test Files

```
apps/web/
├── src/__tests__/
│   ├── setup.ts                 # Vitest setup
│   ├── components/              # Component tests
│   ├── hooks/                   # Hook tests
│   └── services/                # API client tests
├── e2e/
│   ├── global-setup.ts          # Test video seeding
│   └── *.spec.ts                # Playwright tests
├── vitest.config.ts             # Unit test config
└── playwright.config.ts         # E2E test config
```

---

## Changelog

| Date | Version | Changes |
|------|---------|---------|
| 2026-01 | 1.0 | Initial document creation |
