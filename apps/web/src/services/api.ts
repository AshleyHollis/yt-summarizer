/**
 * API client service with fetch wrapper for type-safe API calls.
 */

import { generateCorrelationId } from './correlation';

// API base URL - use relative path for client-side requests (handled by Next.js rewrites)
// Only use absolute URL on server-side or when explicitly set
const API_BASE_URL =
  typeof window === 'undefined'
    ? process.env.NEXT_PUBLIC_API_URL || process.env.API_URL || 'http://localhost:8000'
    : ''; // Client-side: use relative URLs for Next.js rewrite proxy

// Correlation ID header name
const CORRELATION_ID_HEADER = 'X-Correlation-ID';

/**
 * Standard API error response structure
 */
export interface ApiError {
  error: {
    code: number;
    message: string;
    correlation_id?: string;
    details?: Array<{
      field: string;
      message: string;
      type: string;
    }>;
  };
}

/**
 * Pagination metadata
 */
export interface PaginationMeta {
  page: number;
  per_page: number;
  total: number;
  total_pages: number;
  has_next: boolean;
  has_prev: boolean;
}

/**
 * Paginated response wrapper
 */
export interface PaginatedResponse<T> {
  items: T[];
  pagination: PaginationMeta;
}

/**
 * API request options
 */
export interface ApiRequestOptions extends Omit<RequestInit, 'body'> {
  /** Request body (will be JSON stringified) */
  body?: unknown;
  /** Query parameters */
  params?: Record<string, string | number | boolean | undefined>;
  /** Correlation ID (auto-generated if not provided) */
  correlationId?: string;
}

/**
 * API client error class
 */
export class ApiClientError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly correlationId: string | null,
    public readonly details?: ApiError['error']['details']
  ) {
    super(message);
    this.name = 'ApiClientError';
  }
}

/**
 * Build URL with query parameters
 */
function buildUrl(
  endpoint: string,
  params?: Record<string, string | number | boolean | undefined>
): string {
  // For client-side with empty base URL, use relative path
  let urlString: string;
  if (API_BASE_URL) {
    const url = new URL(endpoint, API_BASE_URL);
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) {
          url.searchParams.set(key, String(value));
        }
      });
    }
    urlString = url.toString();
  } else {
    // Relative URL for client-side (Next.js rewrites will proxy to API)
    urlString = endpoint;
    if (params) {
      const searchParams = new URLSearchParams();
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) {
          searchParams.set(key, String(value));
        }
      });
      const queryString = searchParams.toString();
      if (queryString) {
        urlString += (endpoint.includes('?') ? '&' : '?') + queryString;
      }
    }
  }

  return urlString;
}

/**
 * Make an API request with automatic JSON handling and error processing
 */
async function request<T>(
  endpoint: string,
  options: ApiRequestOptions = {}
): Promise<T> {
  const { body, params, correlationId, ...fetchOptions } = options;

  // Generate or use provided correlation ID
  const requestCorrelationId = correlationId || generateCorrelationId();

  // Build request headers
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    [CORRELATION_ID_HEADER]: requestCorrelationId,
    ...options.headers,
  };

  // Build request options
  const requestOptions: RequestInit = {
    ...fetchOptions,
    headers,
  };

  // Add body if present
  if (body !== undefined) {
    requestOptions.body = JSON.stringify(body);
  }

  // Make the request
  const url = buildUrl(endpoint, params);
  const response = await fetch(url, requestOptions);

  // Get correlation ID from response
  const responseCorrelationId = response.headers.get(CORRELATION_ID_HEADER);

  // Handle error responses
  if (!response.ok) {
    let errorMessage = `Request failed with status ${response.status}`;
    let details: ApiError['error']['details'] | undefined;

    try {
      const errorData: ApiError = await response.json();
      errorMessage = errorData.error.message;
      details = errorData.error.details;
    } catch {
      // Ignore JSON parsing errors for error response
    }

    throw new ApiClientError(
      errorMessage,
      response.status,
      responseCorrelationId,
      details
    );
  }

  // Handle empty responses
  if (response.status === 204) {
    return undefined as T;
  }

  // Parse JSON response
  return response.json() as Promise<T>;
}

/**
 * API client with typed methods for all endpoints
 */
export const api = {
  /**
   * Make a GET request
   */
  get: <T>(endpoint: string, options?: ApiRequestOptions): Promise<T> =>
    request<T>(endpoint, { ...options, method: 'GET' }),

  /**
   * Make a POST request
   */
  post: <T>(endpoint: string, options?: ApiRequestOptions): Promise<T> =>
    request<T>(endpoint, { ...options, method: 'POST' }),

  /**
   * Make a PUT request
   */
  put: <T>(endpoint: string, options?: ApiRequestOptions): Promise<T> =>
    request<T>(endpoint, { ...options, method: 'PUT' }),

  /**
   * Make a PATCH request
   */
  patch: <T>(endpoint: string, options?: ApiRequestOptions): Promise<T> =>
    request<T>(endpoint, { ...options, method: 'PATCH' }),

  /**
   * Make a DELETE request
   */
  delete: <T>(endpoint: string, options?: ApiRequestOptions): Promise<T> =>
    request<T>(endpoint, { ...options, method: 'DELETE' }),
};

// ============================================================================
// Typed API endpoints
// ============================================================================

/**
 * Health check response
 */
export interface HealthStatus {
  status: 'healthy' | 'degraded' | 'unhealthy';
  timestamp: string;
  version: string;
  checks: Record<string, boolean>;
}

/**
 * Health API
 */
export const healthApi = {
  /**
   * Get health status
   */
  getHealth: (): Promise<HealthStatus> => api.get('/health'),

  /**
   * Get readiness status
   */
  getReadiness: (): Promise<{ ready: boolean; checks: Record<string, boolean> }> =>
    api.get('/health/ready'),

  /**
   * Get liveness status
   */
  getLiveness: (): Promise<{ status: string }> => api.get('/health/live'),
};

// ============================================================================
// Video Types
// ============================================================================

/**
 * Video processing status
 */
export type ProcessingStatus =
  | 'pending'
  | 'transcribing'
  | 'summarizing'
  | 'embedding'
  | 'building_relationships'
  | 'completed'
  | 'failed';

/**
 * Request to submit a video for processing
 */
export interface SubmitVideoRequest {
  url: string;
}

/**
 * Channel summary information
 */
export interface ChannelSummary {
  channel_id: string;
  name: string;
  youtube_channel_id: string;
}

/**
 * Response after submitting a video
 */
export interface SubmitVideoResponse {
  video_id: string;
  youtube_video_id: string;
  title: string;
  channel: ChannelSummary;
  processing_status: ProcessingStatus;
  submitted_at: string;
  jobs_queued: number;
}

/**
 * Full video response
 */
export interface VideoResponse {
  video_id: string;
  youtube_video_id: string;
  title: string;
  description: string | null;
  thumbnail_url: string | null;
  duration_seconds: number | null;
  published_at: string | null;
  channel: ChannelSummary;
  processing_status: ProcessingStatus;
  created_at: string;
  updated_at: string;
  transcript_url: string | null;
  summary_url: string | null;
  has_embeddings: boolean;
  related_videos_count: number;
}

// ============================================================================
// Job Types
// ============================================================================

/**
 * Job type
 */
export type JobType = 'transcribe' | 'summarize' | 'embed' | 'build_relationships';

/**
 * Job stage
 */
export type JobStage = 'queued' | 'processing' | 'completed' | 'failed';

/**
 * Job status
 */
export type JobStatus = 'pending' | 'running' | 'completed' | 'failed' | 'retrying';

/**
 * Job response
 */
export interface JobResponse {
  job_id: string;
  video_id: string;
  job_type: JobType;
  stage: JobStage;
  status: JobStatus;
  error_message: string | null;
  retry_count: number;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

/**
 * Summary of a job (minimal info)
 */
export interface JobSummaryResponse {
  job_id: string;
  job_type: JobType;
  stage: JobStage;
  status: JobStatus;
}

/**
 * Stage progress information
 */
export interface StageProgress {
  job_type: JobType;
  stage: JobStage;
  status: JobStatus;
  completed: boolean;
}

/**
 * Video jobs progress
 */
export interface VideoJobsProgress {
  video_id: string;
  overall_status: string;
  overall_progress: number; // 0-100
  jobs: JobSummaryResponse[];
}

/**
 * Request to retry a failed job
 */
export interface RetryJobRequest {
  reset_retry_count?: boolean;
}

// ============================================================================
// Video API
// ============================================================================

export const videoApi = {
  /**
   * Submit a video for processing
   */
  submit: (request: SubmitVideoRequest): Promise<SubmitVideoResponse> =>
    api.post('/api/v1/videos', { body: request }),

  /**
   * Get a video by ID
   */
  getById: (videoId: string): Promise<VideoResponse> =>
    api.get(`/api/v1/videos/${videoId}`),

  /**
   * Reprocess a video
   */
  reprocess: (videoId: string): Promise<SubmitVideoResponse> =>
    api.post(`/api/v1/videos/${videoId}/reprocess`),
};

// ============================================================================
// Job API
// ============================================================================

export interface ListJobsParams {
  [key: string]: string | number | boolean | undefined;
  video_id?: string;
  job_type?: JobType;
  status?: JobStatus;
  page?: number;
  per_page?: number;
}

export const jobApi = {
  /**
   * List jobs with filtering
   */
  list: (params?: ListJobsParams): Promise<PaginatedResponse<JobResponse>> =>
    api.get('/api/v1/jobs', { params }),

  /**
   * Get a job by ID
   */
  getById: (jobId: string): Promise<JobResponse> =>
    api.get(`/api/v1/jobs/${jobId}`),

  /**
   * Retry a failed job
   */
  retry: (jobId: string, request?: RetryJobRequest): Promise<JobResponse> =>
    api.post(`/api/v1/jobs/${jobId}/retry`, { body: request }),

  /**
   * Get video jobs progress
   */
  getVideoProgress: (videoId: string): Promise<VideoJobsProgress> =>
    api.get(`/api/v1/jobs/video/${videoId}/progress`),
};

export default api;
