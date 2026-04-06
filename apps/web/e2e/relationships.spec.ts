import { test, expect } from '@playwright/test';
import { getApiUrl, getSeededVideoId } from './helpers';

/**
 * Relationship Graph API Tests
 *
 * Tests the GET /api/v1/copilot/neighbors/{video_id} endpoint which returns
 * videos related to a source video via stored relationship edges.
 *
 * This endpoint requires NO authentication — it runs in CI without cookie issues.
 *
 * Prerequisites:
 * - Backend running (Aspire or USE_EXTERNAL_SERVER=true)
 * - global-setup seeds 15+ videos so neighbor data may exist after relationship
 *   worker has processed them.
 */

const API_URL = getApiUrl();

test.describe('Relationship Graph API', () => {
  test.skip(
    () => !process.env.USE_EXTERNAL_SERVER,
    'Requires full backend - run with USE_EXTERNAL_SERVER=true after starting Aspire'
  );

  test('returns valid response structure for a seeded video', async ({ request }) => {
    const videoId = await getSeededVideoId();
    if (!videoId) {
      test.skip(true, 'No seeded videos available — global-setup may not have run');
      return;
    }

    const response = await request.get(`${API_URL}/api/v1/copilot/neighbors/${videoId}`);

    expect(response.ok()).toBeTruthy();

    const data = await response.json();

    // Top-level structure
    expect(data).toHaveProperty('sourceVideoId');
    expect(data).toHaveProperty('neighbors');
    expect(Array.isArray(data.neighbors)).toBeTruthy();
  });

  test('sourceVideoId in response matches the requested video id', async ({ request }) => {
    const videoId = await getSeededVideoId();
    if (!videoId) {
      test.skip(true, 'No seeded videos available');
      return;
    }

    const response = await request.get(`${API_URL}/api/v1/copilot/neighbors/${videoId}`);
    expect(response.ok()).toBeTruthy();

    const data = await response.json();

    // sourceVideoId should echo back the requested video (may be UUID form)
    const returnedId: string = data.sourceVideoId;
    expect(returnedId).toBeTruthy();
    // The returned UUID should contain or match the requested id
    expect(returnedId.replace(/-/g, '')).toContain(videoId.replace(/-/g, ''));
  });

  test('neighbor items have required fields when neighbors exist', async ({ request }) => {
    const videoId = await getSeededVideoId();
    if (!videoId) {
      test.skip(true, 'No seeded videos available');
      return;
    }

    const response = await request.get(`${API_URL}/api/v1/copilot/neighbors/${videoId}`);
    expect(response.ok()).toBeTruthy();

    const data = await response.json();

    if (data.neighbors.length === 0) {
      // Relationships are built by the relationship worker; they may not exist yet.
      console.log(`Video ${videoId} has no relationship neighbors yet — worker may not have run`);
      return;
    }

    const neighbor = data.neighbors[0];

    // Each neighbor must have a video object and relationship metadata
    expect(neighbor).toHaveProperty('video');
    expect(neighbor).toHaveProperty('confidence');
    expect(typeof neighbor.confidence).toBe('number');
    expect(neighbor.confidence).toBeGreaterThanOrEqual(0);
    expect(neighbor.confidence).toBeLessThanOrEqual(1);

    // Video object must have an id and title
    expect(neighbor.video).toHaveProperty('videoId');
    expect(neighbor.video).toHaveProperty('title');
  });

  test('respects limit query parameter', async ({ request }) => {
    const videoId = await getSeededVideoId();
    if (!videoId) {
      test.skip(true, 'No seeded videos available');
      return;
    }

    const limit = 3;
    const response = await request.get(
      `${API_URL}/api/v1/copilot/neighbors/${videoId}?limit=${limit}`
    );
    expect(response.ok()).toBeTruthy();

    const data = await response.json();
    expect(data.neighbors.length).toBeLessThanOrEqual(limit);
  });

  test('returns empty neighbors gracefully for a video with no relationships', async ({
    request,
  }) => {
    // Use a well-known nil-like UUID that will never have relationships in the DB.
    // The endpoint should return 200 with an empty neighbors list (not 404 or 500).
    const nonExistentId = '00000000-0000-0000-0000-000000000001';

    const response = await request.get(`${API_URL}/api/v1/copilot/neighbors/${nonExistentId}`);

    // Should respond gracefully — either 200 with empty list or 404.
    // A 500 would be a bug.
    expect(response.status()).not.toBe(500);

    if (response.ok()) {
      const data = await response.json();
      expect(Array.isArray(data.neighbors)).toBeTruthy();
      expect(data.neighbors.length).toBe(0);
    }
  });

  test('rejects malformed video id with 422', async ({ request }) => {
    const response = await request.get(`${API_URL}/api/v1/copilot/neighbors/not-a-valid-uuid`);

    // FastAPI validates UUID path params and returns 422 Unprocessable Entity
    expect(response.status()).toBe(422);
  });
});
