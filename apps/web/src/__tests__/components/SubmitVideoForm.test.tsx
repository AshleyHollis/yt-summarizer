/**
 * Tests for SubmitVideoForm component
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor, cleanup } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import '@testing-library/jest-dom';
import { SubmitVideoForm } from '@/components/SubmitVideoForm';
import { createMockSubmitVideoResponse } from '../helpers/mockFactories';
import type { SubmitVideoResponse } from '@/services/api';

// Mock the API module
vi.mock('@/services/api', () => ({
  videoApi: {
    submit: vi.fn(),
  },
  ApiClientError: class ApiClientError extends Error {
    constructor(
      message: string,
      public status: number,
      public correlationId: string | null,
      public details?: Array<{ field: string; message: string; type: string }>
    ) {
      super(message);
    }
  },
}));

import { videoApi, ApiClientError } from '@/services/api';

describe('SubmitVideoForm', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  afterEach(() => {
    cleanup();
  });

  describe('Rendering', () => {
    it('renders the form with input and button', () => {
      render(<SubmitVideoForm />);

      expect(screen.getByLabelText(/youtube video url/i)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /process video/i })).toBeInTheDocument();
    });

    it('renders placeholder text', () => {
      render(<SubmitVideoForm />);

      expect(screen.getByPlaceholderText(/youtube\.com\/watch/i)).toBeInTheDocument();
    });

    it('renders helper text', () => {
      render(<SubmitVideoForm />);

      expect(screen.getByText(/paste a youtube url/i)).toBeInTheDocument();
    });
  });

  describe('Validation', () => {
    it('disables submit button when input is empty', () => {
      render(<SubmitVideoForm />);

      const button = screen.getByRole('button', { name: /process video/i });
      expect(button).toBeDisabled();
    });

    it('shows error for invalid URL', async () => {
      render(<SubmitVideoForm />);

      const input = screen.getByLabelText(/youtube video url/i);
      await userEvent.type(input, 'https://example.com/video');

      const button = screen.getByRole('button', { name: /process video/i });
      fireEvent.click(button);

      await waitFor(() => {
        expect(screen.getByText(/valid youtube url/i)).toBeInTheDocument();
      });
    });

    it('accepts valid YouTube URL format', async () => {
      vi.mocked(videoApi.submit).mockResolvedValue({
        video_id: '123',
        youtube_video_id: 'dQw4w9WgXcQ',
        title: 'Test Video',
        channel: { channel_id: '1', name: 'Test', youtube_channel_id: 'UC123' },
        processing_status: 'pending',
        submitted_at: new Date().toISOString(),
        jobs_queued: 1,
      });

      render(<SubmitVideoForm />);

      const input = screen.getByLabelText(/youtube video url/i);
      await userEvent.type(input, 'https://www.youtube.com/watch?v=dQw4w9WgXcQ');

      const button = screen.getByRole('button', { name: /process video/i });
      fireEvent.click(button);

      await waitFor(() => {
        expect(videoApi.submit).toHaveBeenCalledWith({
          url: 'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
        });
      });
    });
  });

  describe('Submission', () => {
    it('shows loading state during submission', async () => {
      // Create a deferred promise to control resolution
      let resolveSubmit: (value: SubmitVideoResponse) => void;
      vi.mocked(videoApi.submit).mockImplementation(
        () =>
          new Promise((resolve) => {
            resolveSubmit = resolve;
          })
      );

      render(<SubmitVideoForm />);

      const input = screen.getByLabelText(/youtube video url/i);
      await userEvent.type(input, 'https://www.youtube.com/watch?v=dQw4w9WgXcQ');

      const button = screen.getByRole('button', { name: /process video/i });
      fireEvent.click(button);

      // Check for loading state
      await waitFor(() => {
        expect(screen.getByText(/submitting/i)).toBeInTheDocument();
      });

      // Resolve the promise to clean up
      resolveSubmit!(
        createMockSubmitVideoResponse({
          video_id: '123',
          youtube_video_id: 'dQw4w9WgXcQ',
          title: 'Test',
        })
      );
    });

    it('shows success message after successful submission', async () => {
      vi.mocked(videoApi.submit).mockResolvedValue({
        video_id: '123',
        youtube_video_id: 'dQw4w9WgXcQ',
        title: 'Never Gonna Give You Up',
        channel: { channel_id: '1', name: 'Rick Astley', youtube_channel_id: 'UC123' },
        processing_status: 'pending',
        submitted_at: new Date().toISOString(),
        jobs_queued: 1,
      });

      render(<SubmitVideoForm />);

      const input = screen.getByLabelText(/youtube video url/i);
      await userEvent.type(input, 'https://www.youtube.com/watch?v=dQw4w9WgXcQ');

      const button = screen.getByRole('button', { name: /process video/i });
      fireEvent.click(button);

      await waitFor(() => {
        expect(screen.getByText(/submitted successfully/i)).toBeInTheDocument();
        expect(screen.getByText(/never gonna give you up/i)).toBeInTheDocument();
      });
    });

    it('shows error message on API failure', async () => {
      vi.mocked(videoApi.submit).mockRejectedValue(
        new ApiClientError('Video already exists', 409, null)
      );

      render(<SubmitVideoForm />);

      const input = screen.getByLabelText(/youtube video url/i);
      await userEvent.type(input, 'https://www.youtube.com/watch?v=dQw4w9WgXcQ');

      const button = screen.getByRole('button', { name: /process video/i });
      fireEvent.click(button);

      await waitFor(() => {
        expect(screen.getByText(/video already exists/i)).toBeInTheDocument();
      });
    });

    it('calls onSuccess callback when provided', async () => {
      const mockOnSuccess = vi.fn();
      const response = {
        video_id: '123',
        youtube_video_id: 'dQw4w9WgXcQ',
        title: 'Test Video',
        channel: { channel_id: '1', name: 'Test', youtube_channel_id: 'UC123' },
        processing_status: 'pending' as const,
        submitted_at: new Date().toISOString(),
        jobs_queued: 1,
      };
      vi.mocked(videoApi.submit).mockResolvedValue(response);

      render(<SubmitVideoForm onSuccess={mockOnSuccess} />);

      const input = screen.getByLabelText(/youtube video url/i);
      await userEvent.type(input, 'https://www.youtube.com/watch?v=dQw4w9WgXcQ');

      const button = screen.getByRole('button', { name: /process video/i });
      fireEvent.click(button);

      await waitFor(() => {
        expect(mockOnSuccess).toHaveBeenCalledWith(response);
      });
    });
  });

  describe('Accessibility', () => {
    it('has accessible form labels', () => {
      render(<SubmitVideoForm />);

      const input = screen.getByLabelText(/youtube video url/i);
      expect(input).toHaveAttribute('id', 'youtube-url');
    });

    it('shows error alert with accessible role when validation fails', async () => {
      render(<SubmitVideoForm />);

      const input = screen.getByLabelText(/youtube video url/i);
      // Use a URL that passes type="url" validation but fails YouTube regex
      await userEvent.type(input, 'https://example.com/video');

      const button = screen.getByRole('button', { name: /process video/i });
      fireEvent.click(button);

      await waitFor(() => {
        expect(screen.getByRole('alert')).toBeInTheDocument();
      });
    });

    it('disables input and button during submission', async () => {
      // Create a deferred promise to control resolution
      let resolveSubmit: (value: SubmitVideoResponse) => void;
      vi.mocked(videoApi.submit).mockImplementation(
        () =>
          new Promise((resolve) => {
            resolveSubmit = resolve;
          })
      );

      render(<SubmitVideoForm />);

      const input = screen.getByLabelText(/youtube video url/i);
      await userEvent.type(input, 'https://www.youtube.com/watch?v=dQw4w9WgXcQ');

      const button = screen.getByRole('button', { name: /process video/i });
      fireEvent.click(button);

      await waitFor(() => {
        expect(input).toBeDisabled();
        expect(button).toBeDisabled();
      });

      // Resolve the promise to clean up
      resolveSubmit!(
        createMockSubmitVideoResponse({
          video_id: '123',
        })
      );
    });
  });
});
