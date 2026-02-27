/**
 * Mock data factories for tests
 *
 * Provides factory functions to create properly-typed mock data for tests.
 * All factories create complete objects with required fields filled in.
 */

import type {
  JobSummaryResponse,
  VideoJobsProgress,
  VideoCard,
  VideoDetailResponse,
  SubmitVideoResponse,
} from '@/services/api';
import type { User } from '@/contexts/AuthContext';

/**
 * Create a mock JobSummaryResponse
 */
export function createMockJobSummary(
  overrides: Partial<JobSummaryResponse> = {}
): JobSummaryResponse {
  return {
    job_id: 'job-123',
    job_type: 'transcribe',
    stage: 'queued',
    status: 'pending',
    error_message: null,
    retry_count: 0,
    created_at: new Date().toISOString(),
    updated_at: null,
    next_retry_at: null,
    ...overrides,
  };
}

/**
 * Create a mock VideoJobsProgress
 */
export function createMockVideoJobsProgress(
  overrides: Partial<VideoJobsProgress> = {}
): VideoJobsProgress {
  return {
    video_id: '123',
    overall_status: 'processing',
    overall_progress: 50,
    jobs: [
      createMockJobSummary({
        job_id: 'job-1',
        job_type: 'transcribe',
        stage: 'completed',
        status: 'succeeded',
      }),
      createMockJobSummary({
        job_id: 'job-2',
        job_type: 'summarize',
        stage: 'running',
        status: 'running',
      }),
      createMockJobSummary({
        job_id: 'job-3',
        job_type: 'embed',
        stage: 'queued',
        status: 'pending',
      }),
      createMockJobSummary({
        job_id: 'job-4',
        job_type: 'build_relationships',
        stage: 'queued',
        status: 'pending',
      }),
    ],
    eta: null,
    current_stage_name: null,
    ...overrides,
  };
}

/**
 * Create a mock VideoCard
 */
export function createMockVideoCard(overrides: Partial<VideoCard> = {}): VideoCard {
  return {
    video_id: 'vid-123',
    youtube_video_id: 'abc123',
    title: 'Test Video',
    channel_id: 'ch-123',
    channel_name: 'Test Channel',
    channel_thumbnail_url: null,
    duration: 300,
    publish_date: new Date().toISOString(),
    thumbnail_url: null,
    processing_status: 'completed',
    segment_count: 10,
    facets: [],
    ...overrides,
  };
}

/**
 * Create a mock VideoDetailResponse
 */
export function createMockVideoDetail(
  overrides: Partial<VideoDetailResponse> = {}
): VideoDetailResponse {
  return {
    video_id: 'vid-123',
    youtube_video_id: 'abc123',
    youtube_url: 'https://youtube.com/watch?v=abc123',
    title: 'Test Video',
    description: 'Test description',
    duration: 300,
    publish_date: new Date().toISOString(),
    thumbnail_url: null,
    processing_status: 'completed',
    channel: {
      channel_id: 'ch-123',
      youtube_channel_id: 'yt-ch-123',
      name: 'Test Channel',
      thumbnail_url: null,
    },
    facets: [],
    summary: 'Test summary',
    summary_artifact: null,
    transcript_artifact: null,
    segment_count: 10,
    relationship_count: 5,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
    ...overrides,
  };
}

/**
 * Create a mock SubmitVideoResponse
 */
export function createMockSubmitVideoResponse(
  overrides: Partial<SubmitVideoResponse> = {}
): SubmitVideoResponse {
  return {
    video_id: 'vid-123',
    youtube_video_id: 'abc123',
    title: 'Test Video',
    channel: {
      channel_id: 'ch-123',
      name: 'Test Channel',
      youtube_channel_id: 'yt-ch-123',
    },
    processing_status: 'pending',
    submitted_at: new Date().toISOString(),
    jobs_queued: 4,
    ...overrides,
  };
}

/**
 * Create a mock User
 */
export function createMockUser(overrides: Partial<User> = {}): User {
  return {
    sub: 'auth0|123456',
    email: 'test@example.com',
    email_verified: true,
    'https://yt-summarizer.com/role': 'normal',
    updated_at: new Date().toISOString(),
    ...overrides,
  };
}
