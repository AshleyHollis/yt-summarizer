/**
 * API client service with fetch wrapper for type-safe API calls.
 */

import { generateCorrelationId } from './correlation';

// API base URL - use configured API URL or fallback
// Client-side uses NEXT_PUBLIC_API_URL (e.g., "/api/proxy" for SWA deployments)
// Server-side uses API_URL or NEXT_PUBLIC_API_URL
const API_BASE_URL =
  typeof window === 'undefined'
    ? process.env.API_URL || process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'
    : process.env.NEXT_PUBLIC_API_URL || '';

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
 * Delay helper for exponential backoff
 */
function delay(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Configuration for retry behavior on degraded/unavailable API
 */
const RETRY_CONFIG = {
  /** Maximum number of retry attempts */
  maxRetries: 3,
  /** Base delay in milliseconds (doubles each retry) */
  baseDelayMs: 1000,
  /** Maximum delay between retries */
  maxDelayMs: 10000,
  /** Status codes that trigger retry (503 = service unavailable, 502 = bad gateway) */
  retryableStatusCodes: [502, 503, 504],
};

/**
 * Make an API request with automatic JSON handling, error processing,
 * and retry logic for degraded service (serverless DB wake-up).
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

  // Make the request with retry logic for degraded service
  const url = buildUrl(endpoint, params);
  let lastError: Error | null = null;
  let response: Response | null = null;
  
  for (let attempt = 0; attempt <= RETRY_CONFIG.maxRetries; attempt++) {
    try {
      response = await fetch(url, requestOptions);
      
      // If successful or not a retryable status, break out of retry loop
      if (response.ok || !RETRY_CONFIG.retryableStatusCodes.includes(response.status)) {
        break;
      }
      
      // Retryable error - wait and try again
      if (attempt < RETRY_CONFIG.maxRetries) {
        const delayMs = Math.min(
          RETRY_CONFIG.baseDelayMs * Math.pow(2, attempt),
          RETRY_CONFIG.maxDelayMs
        );
        console.log(`API returned ${response.status}, retrying in ${delayMs}ms (attempt ${attempt + 1}/${RETRY_CONFIG.maxRetries})`);
        await delay(delayMs);
      }
    } catch (err) {
      // Network error - save it and retry
      lastError = err instanceof Error ? err : new Error(String(err));
      
      if (attempt < RETRY_CONFIG.maxRetries) {
        const delayMs = Math.min(
          RETRY_CONFIG.baseDelayMs * Math.pow(2, attempt),
          RETRY_CONFIG.maxDelayMs
        );
        console.log(`Network error, retrying in ${delayMs}ms (attempt ${attempt + 1}/${RETRY_CONFIG.maxRetries})`);
        await delay(delayMs);
      }
    }
  }
  
  // If we never got a response, throw the last network error
  if (!response) {
    throw lastError || new Error('Failed to connect to API');
  }

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
  uptime_seconds: number | null;
  started_at: string | null;
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
  | 'failed'
  | 'rate_limited';

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
export type JobStage = 'queued' | 'running' | 'completed' | 'failed' | 'dead_lettered' | 'rate_limited';

/**
 * Job status
 */
export type JobStatus = 'pending' | 'running' | 'succeeded' | 'failed';

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
  error_message?: string | null;
  retry_count: number;
  created_at: string;
  updated_at?: string | null;
  next_retry_at?: string | null;
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
 * Estimated time for a processing stage
 */
export interface StageEstimate {
  stage: string;
  estimated_seconds: number;
}

/**
 * Historical record of a completed processing stage
 */
export interface StageHistoryItem {
  /** Stage name (transcribe, summarize, embed, build_relationships) */
  stage: string;
  /** Human-readable stage label */
  stage_label: string;
  /** Final status (succeeded, failed) */
  status: string;
  /** When the job was queued (ISO string) */
  queued_at: string | null;
  /** When the stage started (ISO string) */
  started_at: string | null;
  /** When the stage completed (ISO string) */
  completed_at: string | null;
  /** Time spent waiting in queue before processing */
  wait_seconds: number | null;
  /** Predicted queue wait time at submission */
  estimated_wait_seconds: number | null;
  /** Intentional delay for rate limiting (e.g., yt-dlp subtitle_sleep) */
  enforced_delay_seconds: number | null;
  /** Actual processing time in seconds */
  actual_seconds: number | null;
  /** Estimated processing time based on historical averages */
  estimated_seconds: number;
  /** Estimated enforced delay based on historical averages */
  estimated_delay_seconds: number;
  /** Difference between actual and estimated (positive = slower than expected) */
  variance_seconds: number | null;
  /** Percentage difference from estimate */
  variance_percent: number | null;
  /** Number of retries for this stage */
  retry_count: number;
}

/**
 * Complete processing history for a video
 */
export interface VideoProcessingHistory {
  video_id: string;
  video_title: string | null;
  video_duration_seconds: number | null;
  processing_status: string;
  
  /** When the video was first submitted (ISO string) */
  submitted_at: string | null;
  /** When first job started (ISO string) */
  first_job_started_at: string | null;
  /** When last job completed (ISO string) */
  last_job_completed_at: string | null;
  /** Total time spent waiting in queues */
  total_wait_seconds: number | null;
  /** Total estimated queue wait time at submission */
  total_estimated_wait_seconds: number | null;
  /** Total intentional delays for rate limiting (e.g., yt-dlp subtitle_sleep) */
  total_enforced_delay_seconds: number | null;
  /** Total actual processing time in seconds */
  total_actual_seconds: number | null;
  /** Total estimated processing time in seconds */
  total_estimated_seconds: number;
  /** Total estimated enforced delays */
  total_estimated_delay_seconds: number;
  /** Total wall-clock time from submission to completion */
  total_elapsed_seconds: number | null;
  /** Total variance (positive = slower than expected) */
  total_variance_seconds: number | null;
  
  /** History for each processing stage */
  stages: StageHistoryItem[];
  
  /** Number of stages completed */
  stages_completed: number;
  /** Number of stages failed */
  stages_failed: number;
  /** Total retry attempts across all stages */
  total_retries: number;
  
  /** Whether this video processed faster than average */
  faster_than_average: boolean | null;
  /** Processing speed percentile (1-100, higher = faster) */
  percentile: number | null;
}

/**
 * Estimated time of arrival information
 */
export interface ETAInfo {
  /** Total estimated seconds until processing completes */
  estimated_seconds_remaining: number;
  /** Total estimated processing time for all stages */
  estimated_total_seconds: number;
  /** Estimated datetime when video will be ready (ISO string) */
  estimated_ready_at: string;
  /** Seconds elapsed since processing started */
  elapsed_seconds: number;
  /** When processing first started (ISO string, for timer continuity) */
  processing_started_at: string | null;
  /** Position in the processing queue (1-indexed, 1 = you're next) */
  queue_position: number;
  /** Total videos currently in the queue */
  total_in_queue: number;
  /** Number of videos ahead in the queue */
  videos_ahead: number;
  /** Estimated seconds waiting for videos ahead */
  queue_wait_seconds: number;
  /** Breakdown of remaining stages and their estimates */
  stages_remaining: StageEstimate[];
}

/**
 * Video jobs progress
 */
export interface VideoJobsProgress {
  video_id: string;
  overall_status: string;
  overall_progress: number; // 0-100
  jobs: JobSummaryResponse[];
  /** Estimated time and queue position info (only for in-progress videos) */
  eta: ETAInfo | null;
  /** Human-readable name of the current processing stage */
  current_stage_name: string | null;
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

  /**
   * Get video processing history with actual vs estimated times
   */
  getVideoHistory: (videoId: string): Promise<VideoProcessingHistory> =>
    api.get(`/api/v1/jobs/video/${videoId}/history`),
};

// ============================================================================
// Library Types
// ============================================================================

/**
 * Processing status filter for library
 */
export type ProcessingStatusFilter = 'pending' | 'processing' | 'completed' | 'failed' | 'rate_limited';

/**
 * Sort field options
 */
export type SortField = 'publishDate' | 'title' | 'createdAt';

/**
 * Sort order options
 */
export type SortOrder = 'asc' | 'desc';

/**
 * Facet tag attached to a video
 */
export interface FacetTag {
  facet_id: string;
  name: string;
  type: string;
}

/**
 * Video card for list display
 */
export interface VideoCard {
  video_id: string;
  youtube_video_id: string;
  title: string;
  channel_id: string;
  channel_name: string;
  channel_thumbnail_url: string | null;
  duration: number;
  publish_date: string;
  thumbnail_url: string | null;
  processing_status: string;
  segment_count: number;
  facets: FacetTag[];
}

/**
 * Video list response
 */
export interface VideoListResponse {
  videos: VideoCard[];
  page: number;
  page_size: number;
  total_count: number;
}

/**
 * Channel summary in video detail context
 */
export interface ChannelSummaryLibrary {
  channel_id: string;
  youtube_channel_id: string;
  name: string;
  thumbnail_url: string | null;
}

/**
 * Artifact information
 */
export interface ArtifactInfo {
  artifact_id: string;
  type: string;
  content_length: number;
  model_name: string | null;
  created_at: string;
}

/**
 * Full video detail response
 */
export interface VideoDetailResponse {
  video_id: string;
  youtube_video_id: string;
  title: string;
  description: string | null;
  channel: ChannelSummaryLibrary;
  duration: number;
  publish_date: string;
  thumbnail_url: string | null;
  youtube_url: string;
  processing_status: string;
  summary: string | null;
  summary_artifact: ArtifactInfo | null;
  transcript_artifact: ArtifactInfo | null;
  segment_count: number;
  relationship_count: number;
  facets: FacetTag[];
  created_at: string;
  updated_at: string;
}

/**
 * Transcript segment
 */
export interface Segment {
  segment_id: string;
  sequence_number: number;
  start_time: number;
  end_time: number;
  text: string;
  youtube_url: string;
}

/**
 * Segment list response
 */
export interface SegmentListResponse {
  video_id: string;
  segments: Segment[];
  page: number;
  page_size: number;
  total_count: number;
}

/**
 * Channel card for list display
 */
export interface ChannelCard {
  channel_id: string;
  youtube_channel_id: string;
  name: string;
  thumbnail_url: string | null;
  video_count: number;
  last_synced_at: string | null;
}

/**
 * Channel list response
 */
export interface ChannelListResponse {
  channels: ChannelCard[];
  page: number;
  page_size: number;
  total_count: number;
}

/**
 * Facet with video count
 */
export interface FacetCount {
  facet_id: string;
  name: string;
  type: string;
  video_count: number;
}

/**
 * Facet list response
 */
export interface FacetListResponse {
  facets: FacetCount[];
}

/**
 * Library statistics
 */
export interface LibraryStatsResponse {
  total_channels: number;
  total_videos: number;
  completed_videos: number;
  total_segments: number;
  total_relationships: number;
  total_facets: number;
  last_updated_at: string | null;
}

/**
 * Video filter parameters
 */
export interface VideoFilterParams {
  channel_id?: string;
  from_date?: string;
  to_date?: string;
  facets?: string[];
  status?: ProcessingStatusFilter;
  search?: string;
  sort_by?: SortField;
  sort_order?: SortOrder;
  page?: number;
  page_size?: number;
}

// ============================================================================
// Library API
// ============================================================================

export const libraryApi = {
  /**
   * List videos with filtering
   */
  listVideos: (params?: VideoFilterParams): Promise<VideoListResponse> =>
    api.get('/api/v1/library/videos', {
      params: params as Record<string, string | number | boolean | undefined>,
    }),

  /**
   * Get video detail
   */
  getVideoDetail: (videoId: string): Promise<VideoDetailResponse> =>
    api.get(`/api/v1/library/videos/${videoId}`),

  /**
   * List video segments
   */
  listSegments: (
    videoId: string,
    page?: number,
    pageSize?: number
  ): Promise<SegmentListResponse> =>
    api.get(`/api/v1/library/videos/${videoId}/segments`, {
      params: { page, page_size: pageSize },
    }),

  /**
   * List channels
   */
  listChannels: (
    page?: number,
    pageSize?: number,
    search?: string
  ): Promise<ChannelListResponse> =>
    api.get('/api/v1/library/channels', {
      params: { page, page_size: pageSize, search },
    }),

  /**
   * List facets
   */
  listFacets: (
    facetType?: string,
    minCount?: number
  ): Promise<FacetListResponse> =>
    api.get('/api/v1/library/facets', {
      params: { facet_type: facetType, min_count: minCount },
    }),

  /**
   * Get library statistics
   */
  getStats: (): Promise<LibraryStatsResponse> =>
    api.get('/api/v1/library/stats'),
};

// ============================================================================
// Channel Ingestion Types (US2)
// ============================================================================

/**
 * Request to fetch videos from a channel
 */
export interface FetchChannelRequest {
  channel_url: string;
  cursor?: string;
  limit?: number;
}

/**
 * Video available from a channel for ingestion
 */
export interface ChannelVideo {
  youtube_video_id: string;
  title: string;
  duration: number;
  publish_date: string;
  thumbnail_url: string | null;
  already_ingested: boolean;
}

/**
 * Response with channel videos
 */
export interface ChannelVideosResponse {
  channel_id: string | null;
  youtube_channel_id: string;
  channel_name: string;
  total_video_count: number | null;
  returned_count: number;
  videos: ChannelVideo[];
  next_cursor: string | null;
  has_more: boolean;
}

// ============================================================================
// Batch Types (US2)
// ============================================================================

/**
 * Batch status
 */
export type BatchStatus = 'pending' | 'running' | 'completed' | 'failed';

/**
 * Batch item status
 */
export type BatchItemStatus = 'pending' | 'running' | 'succeeded' | 'failed';

/**
 * Request to create a batch
 */
export interface CreateBatchRequest {
  channel_id?: string;
  youtube_channel_id?: string;
  name: string;
  video_ids: string[];
  ingest_all?: boolean;
}

/**
 * Batch item in a batch
 */
export interface BatchItem {
  id: string;
  video_id: string | null;
  youtube_video_id: string;
  title: string;
  status: BatchItemStatus;
  error_message: string | null;
  created_at: string;
  updated_at: string;
}

/**
 * Batch summary for list views
 */
export interface BatchResponse {
  id: string;
  name: string;
  channel_name: string | null;
  status: BatchStatus;
  total_count: number;
  pending_count: number;
  running_count: number;
  succeeded_count: number;
  failed_count: number;
  created_at: string;
  updated_at: string;
}

/**
 * Full batch details with items
 */
export interface BatchDetailResponse extends BatchResponse {
  items: BatchItem[];
}

/**
 * Batch list response
 */
export interface BatchListResponse {
  batches: BatchResponse[];
  total_count: number;
  page: number;
  page_size: number;
}

/**
 * Batch retry response
 */
export interface BatchRetryResponse {
  batch_id: string;
  retried_count: number;
  message: string;
}

// ============================================================================
// Channel Ingestion API (US2)
// ============================================================================

export const channelApi = {
  /**
   * Fetch videos from a YouTube channel
   */
  fetchVideos: (request: FetchChannelRequest): Promise<ChannelVideosResponse> =>
    api.post('/api/v1/channels', { body: request }),
};

// ============================================================================
// Batch API (US2)
// ============================================================================

export const batchApi = {
  /**
   * Create a batch for ingestion
   */
  create: (request: CreateBatchRequest): Promise<BatchResponse> =>
    api.post('/api/v1/batches', { body: request }),

  /**
   * List all batches
   */
  list: (page?: number, pageSize?: number): Promise<BatchListResponse> =>
    api.get('/api/v1/batches', { params: { page, page_size: pageSize } }),

  /**
   * Get batch details
   */
  getById: (batchId: string): Promise<BatchDetailResponse> =>
    api.get(`/api/v1/batches/${batchId}`),

  /**
   * Stream batch progress via Server-Sent Events
   * Returns an EventSource that emits batch detail updates
   */
  streamProgress: (
    batchId: string,
    onUpdate: (batch: BatchDetailResponse) => void,
    onComplete?: (batch: BatchDetailResponse) => void,
    onError?: (error: Error) => void
  ): (() => void) => {
    // Build the SSE URL - use direct backend URL to avoid Next.js proxy buffering
    // SSE connections should bypass the rewrite proxy for proper streaming
    const directApiUrl = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';
    const sseUrl = `${directApiUrl}/api/v1/batches/${batchId}/stream`;

    const eventSource = new EventSource(sseUrl);

    eventSource.onmessage = (event) => {
      try {
        const batch = JSON.parse(event.data) as BatchDetailResponse;
        onUpdate(batch);
      } catch (err) {
        console.error('Failed to parse SSE data:', err);
      }
    };

    eventSource.addEventListener('complete', (event) => {
      try {
        const batch = JSON.parse((event as MessageEvent).data) as BatchDetailResponse;
        onComplete?.(batch);
      } catch (err) {
        console.error('Failed to parse SSE complete event:', err);
      }
      eventSource.close();
    });

    eventSource.addEventListener('error', (event) => {
      // Check if it's a custom error event with data
      const messageEvent = event as MessageEvent;
      if (messageEvent.data) {
        try {
          const errorData = JSON.parse(messageEvent.data);
          onError?.(new Error(errorData.error || 'SSE error'));
        } catch {
          onError?.(new Error('SSE connection error'));
        }
      }
      // Don't close on transient errors - EventSource will reconnect
    });

    eventSource.onerror = () => {
      // EventSource automatically reconnects on errors
      // Only call onError if the connection is closed
      if (eventSource.readyState === EventSource.CLOSED) {
        onError?.(new Error('SSE connection closed'));
      }
    };

    // Return cleanup function
    return () => {
      eventSource.close();
    };
  },

  /**
   * Retry failed items in a batch
   */
  retryFailed: (batchId: string): Promise<BatchRetryResponse> =>
    api.post(`/api/v1/batches/${batchId}/retry`),

  /**
   * Retry a single failed item in a batch
   */
  retryItem: (batchId: string, videoId: string): Promise<BatchRetryResponse> =>
    api.post(`/api/v1/batches/${batchId}/items/${videoId}/retry`),
};

export default api;
