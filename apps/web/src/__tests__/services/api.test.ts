/**
 * Tests for API client service
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { api, ApiClientError, videoApi, jobApi, healthApi } from '@/services/api';

describe('API Client', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    global.fetch = vi.fn();
  });

  describe('Base API methods', () => {
    it('makes GET requests correctly', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({ data: 'test' }),
      } as Response);

      const result = await api.get('/test');
      expect(result).toEqual({ data: 'test' });
      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/test'),
        expect.objectContaining({ method: 'GET' })
      );
    });

    it('makes POST requests correctly', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 201,
        headers: new Headers(),
        json: async () => ({ id: '123' }),
      } as Response);

      const result = await api.post('/test', { body: { name: 'test' } });
      expect(result).toEqual({ id: '123' });
    });

    it('includes correlation ID header', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({}),
      } as Response);

      await api.get('/test', { correlationId: 'test-correlation-id' });

      expect(global.fetch).toHaveBeenCalledWith(
        expect.any(String),
        expect.objectContaining({
          headers: expect.objectContaining({
            'X-Correlation-ID': 'test-correlation-id',
          }),
        })
      );
    });

    it('includes query parameters in URL', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({}),
      } as Response);

      await api.get('/test', { params: { page: 1, status: 'active' } });

      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringMatching(/page=1/),
        expect.any(Object)
      );
    });
  });

  describe('Error handling', () => {
    it('throws ApiClientError on non-OK response', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: false,
        status: 404,
        headers: new Headers(),
        json: async () => ({ error: { code: 404, message: 'Not found' } }),
      } as Response);

      await expect(api.get('/test')).rejects.toThrow(ApiClientError);
    });

    it('includes status code in error', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: false,
        status: 422,
        headers: new Headers(),
        json: async () => ({ error: { code: 422, message: 'Validation failed' } }),
      } as Response);

      try {
        await api.get('/test');
      } catch (error) {
        expect(error).toBeInstanceOf(ApiClientError);
        expect((error as ApiClientError).status).toBe(422);
      }
    });

    it('handles 204 No Content response', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 204,
        headers: new Headers(),
      } as Response);

      const result = await api.delete('/test');
      expect(result).toBeUndefined();
    });
  });

  describe('videoApi', () => {
    it('submit calls POST /api/v1/videos', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 201,
        headers: new Headers(),
        json: async () => ({
          video_id: '123',
          youtube_video_id: 'abc',
          title: 'Test',
          channel: { channel_id: '1', name: 'Test', youtube_channel_id: 'UC123' },
          processing_status: 'pending',
          submitted_at: new Date().toISOString(),
          jobs_queued: 1,
        }),
      } as Response);

      await videoApi.submit({ url: 'https://youtube.com/watch?v=abc' });

      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/videos'),
        expect.objectContaining({ method: 'POST' })
      );
    });

    it('getById calls GET /api/v1/videos/{id}', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({ video_id: '123', title: 'Test' }),
      } as Response);

      await videoApi.getById('123');

      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/videos/123'),
        expect.objectContaining({ method: 'GET' })
      );
    });

    it('reprocess calls POST /api/v1/videos/{id}/reprocess', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({ video_id: '123' }),
      } as Response);

      await videoApi.reprocess('123');

      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/videos/123/reprocess'),
        expect.objectContaining({ method: 'POST' })
      );
    });
  });

  describe('jobApi', () => {
    it('list calls GET /api/v1/jobs', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({ items: [], pagination: {} }),
      } as Response);

      await jobApi.list();

      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/jobs'),
        expect.objectContaining({ method: 'GET' })
      );
    });

    it('list includes filter parameters', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({ items: [], pagination: {} }),
      } as Response);

      await jobApi.list({ video_id: '123', status: 'pending' });

      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringMatching(/video_id=123/),
        expect.any(Object)
      );
    });

    it('getVideoProgress calls correct endpoint', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({
          video_id: '123',
          overall_progress: 50,
          stages: [],
          is_complete: false,
          has_failed: false,
        }),
      } as Response);

      await jobApi.getVideoProgress('123');

      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/jobs/video/123/progress'),
        expect.any(Object)
      );
    });

    it('retry calls POST /api/v1/jobs/{id}/retry', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({ job_id: '123' }),
      } as Response);

      await jobApi.retry('123', { reset_retry_count: true });

      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/v1/jobs/123/retry'),
        expect.objectContaining({ method: 'POST' })
      );
    });
  });

  describe('healthApi', () => {
    it('getHealth calls GET /health', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({ status: 'healthy', version: '1.0.0' }),
      } as Response);

      await healthApi.getHealth();

      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/health'),
        expect.objectContaining({ method: 'GET' })
      );
    });

    it('getReadiness calls GET /health/ready', async () => {
      vi.mocked(global.fetch).mockResolvedValue({
        ok: true,
        status: 200,
        headers: new Headers(),
        json: async () => ({ ready: true, checks: {} }),
      } as Response);

      await healthApi.getReadiness();

      expect(global.fetch).toHaveBeenCalledWith(
        expect.stringContaining('/health/ready'),
        expect.any(Object)
      );
    });
  });
});
