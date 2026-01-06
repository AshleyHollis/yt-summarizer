"""Tests for transcribe worker resilience - content validation and retry logic.

These tests verify that the transcribe worker:
1. Detects HTML error pages vs valid transcripts
2. Retries on rate limit responses
3. Properly fails after max retries
"""

import pytest
from unittest.mock import AsyncMock, patch, MagicMock


class TestContentValidation:
    """Tests for _is_valid_transcript_content method."""

    @pytest.fixture
    def worker(self):
        """Create a transcribe worker instance."""
        from transcribe.worker import TranscribeWorker
        return TranscribeWorker()

    def test_valid_transcript_passes(self, worker):
        """Valid VTT/transcript content should pass validation."""
        valid_content = """WEBVTT

00:00:00.000 --> 00:00:05.000
Hello and welcome to this tutorial.

00:00:05.000 --> 00:00:10.000
Today we're going to learn about push-ups.
"""
        assert worker._is_valid_transcript_content(valid_content) is True

    def test_valid_plain_text_passes(self, worker):
        """Plain text transcript should pass validation."""
        valid_content = "Hello and welcome to this tutorial. Today we're going to learn about push-ups."
        assert worker._is_valid_transcript_content(valid_content) is True

    def test_empty_content_fails(self, worker):
        """Empty content should fail validation."""
        assert worker._is_valid_transcript_content("") is False
        assert worker._is_valid_transcript_content("   ") is False

    def test_short_content_fails(self, worker):
        """Content shorter than 10 characters should fail."""
        assert worker._is_valid_transcript_content("abc") is False
        assert worker._is_valid_transcript_content("123456789") is False

    def test_html_page_fails(self, worker):
        """HTML pages starting with DOCTYPE should be detected and rejected."""
        html_content = """<!DOCTYPE html>
<html>
<head><title>Error</title></head>
<body>This is an error page</body>
</html>"""
        assert worker._is_valid_transcript_content(html_content) is False

    def test_google_rate_limit_page_fails(self, worker):
        """Google rate limit error page should be detected."""
        google_error = """<!DOCTYPE html><html><head></head><body>Sorry... body { font-family: verdana, arial, sans-serif; background-color: #fff; color: #000; }GoogleSorry...We're sorry...... but your computer or network may be sending automated queries. To protect our users, we can't process your request right now.See Google Help for more information.Google Home</body></html>"""
        assert worker._is_valid_transcript_content(google_error) is False

    def test_legitimate_transcript_mentioning_captcha_passes(self, worker):
        """A real transcript that mentions captcha in context should PASS."""
        # This is a key test - we don't want false positives!
        legitimate_transcript = """
        Welcome to this web scraping tutorial. Today we'll discuss how to handle
        situations where websites use captcha to block automated queries. 
        Sometimes you'll see unusual traffic warnings, but there are ethical ways
        to scrape data. Let's look at rate limiting strategies and how to respect
        robots.txt files. Remember, automated queries should be done responsibly.
        """
        assert worker._is_valid_transcript_content(legitimate_transcript) is True

    def test_legitimate_transcript_mentioning_google_sorry_passes(self, worker):
        """A transcript mentioning Google and sorry in normal context should PASS."""
        legitimate_transcript = """
        I'm sorry to say that Google has changed their API again. This is frustrating
        for developers who rely on these services. Let me show you the workaround
        that our team developed. We spent weeks on this solution after Google 
        deprecated the old endpoint. Sorry for the long explanation but it's important
        to understand the context here.
        """
        assert worker._is_valid_transcript_content(legitimate_transcript) is True

    def test_short_html_with_rate_limit_fails(self, worker):
        """Short HTML response with rate limit message should fail."""
        # This is the actual error pattern we're trying to catch
        short_error = """<html><head></head><body>We've detected automated queries from your network. To protect our users, please try again later.</body></html>"""
        assert worker._is_valid_transcript_content(short_error) is False


class TestFetchTranscriptRetry:
    """Tests for transcript fetch retry logic with yt-dlp."""

    @pytest.fixture
    def worker(self):
        """Create a transcribe worker instance."""
        from transcribe.worker import TranscribeWorker
        return TranscribeWorker()

    @pytest.mark.asyncio
    async def test_succeeds_on_valid_content(self, worker):
        """Fetch should succeed when yt-dlp downloads valid subtitles to temp directory."""
        import tempfile
        import os
        import json
        
        valid_json3 = json.dumps({
            "events": [
                {"tStartMs": 0, "dDurationMs": 5000, "segs": [{"utf8": "Hello and welcome to this tutorial about push-ups."}]},
                {"tStartMs": 5000, "dDurationMs": 5000, "segs": [{"utf8": "Let's get started."}]},
            ]
        })
        
        # Create a temp directory with a mock subtitle file
        with tempfile.TemporaryDirectory() as tmpdir:
            # Mock yt-dlp to write to our temp directory
            mock_info = {
                "subtitles": {"en": [{"ext": "json3"}]},
                "automatic_captions": {},
            }
            
            async def mock_download():
                # Write a mock subtitle file
                subtitle_path = os.path.join(tmpdir, "test_video_id.en.json3")
                with open(subtitle_path, "w") as f:
                    f.write(valid_json3)
                return mock_info
            
            with patch("yt_dlp.YoutubeDL") as mock_ydl_class:
                mock_ydl = MagicMock()
                mock_ydl.__enter__ = MagicMock(return_value=mock_ydl)
                mock_ydl.__exit__ = MagicMock(return_value=False)
                mock_ydl.extract_info.return_value = mock_info
                mock_ydl_class.return_value = mock_ydl
                
                with patch("tempfile.TemporaryDirectory") as mock_tempdir:
                    mock_tempdir.return_value.__enter__ = MagicMock(return_value=tmpdir)
                    mock_tempdir.return_value.__exit__ = MagicMock(return_value=False)
                    
                    # Write the subtitle file before calling the method
                    subtitle_path = os.path.join(tmpdir, "test_video_id.en.json3")
                    with open(subtitle_path, "w") as f:
                        f.write(valid_json3)
                    
                    transcript, segments = await worker._fetch_transcript_with_timestamps_and_text("test_video_id")
                    
                    assert transcript is not None
                    assert "Hello and welcome" in transcript
                    assert segments is not None

    @pytest.mark.asyncio
    async def test_uses_only_yt_dlp(self, worker):
        """Verify worker uses yt-dlp exclusively (no youtube-transcript-api)."""
        # The worker should only have yt-dlp methods, not youtube-transcript-api
        assert hasattr(worker, '_fetch_transcript_with_timestamps_and_text')
        assert hasattr(worker, '_parse_vtt_subtitles')
        assert hasattr(worker, '_parse_json3_subtitles')
        
        # Verify method docstring mentions yt-dlp
        docstring = worker._fetch_transcript_with_timestamps_and_text.__doc__
        assert "yt-dlp" in docstring.lower()

    @pytest.mark.asyncio
    async def test_raises_rate_limit_on_download_error(self, worker):
        """Fetch should raise RateLimitError when yt-dlp encounters rate limiting."""
        import yt_dlp
        from transcribe.worker import RateLimitError
        
        with patch("yt_dlp.YoutubeDL") as mock_ydl_class:
            mock_ydl = MagicMock()
            mock_ydl.__enter__ = MagicMock(return_value=mock_ydl)
            mock_ydl.__exit__ = MagicMock(return_value=False)
            # Simulate rate limit error from yt-dlp
            mock_ydl.extract_info.side_effect = yt_dlp.utils.DownloadError("HTTP Error 429: Too Many Requests")
            mock_ydl_class.return_value = mock_ydl
            
            with pytest.raises(RateLimitError):
                await worker._fetch_transcript_with_timestamps_and_text("test_video_id")


class TestWorkerResultOnInvalidContent:
    """Tests for worker behavior when content is invalid."""

    @pytest.mark.asyncio
    async def test_job_fails_with_clear_message_when_no_transcript(self):
        """Job should fail with clear message when no valid transcript is available."""
        from transcribe.worker import TranscribeWorker, TranscribeMessage
        from shared.worker.base_worker import WorkerStatus
        
        worker = TranscribeWorker()
        
        message = TranscribeMessage(
            job_id="test-job-id",
            video_id="test-video-id",
            youtube_video_id="invalid_video",
            correlation_id="test-correlation",
            retry_count=0,
        )
        
        with patch("transcribe.worker.mark_job_running", new_callable=AsyncMock), \
             patch("transcribe.worker.mark_job_failed", new_callable=AsyncMock) as mock_failed, \
             patch.object(worker, "_fetch_transcript_with_timestamps_and_text", new_callable=AsyncMock) as mock_fetch:
            
            # Simulate no transcript available
            mock_fetch.return_value = (None, None)
            
            result = await worker.process_message(message, "test-correlation")
            
            assert result.status == WorkerStatus.FAILED
            assert "No transcript available" in result.message
            mock_failed.assert_called_once()


class TestRateLimitHandling:
    """Tests for RateLimitError and infinite retry behavior."""

    @pytest.fixture
    def worker(self):
        from transcribe.worker import TranscribeWorker
        return TranscribeWorker()

    @pytest.fixture
    def message(self):
        from transcribe.worker import TranscribeMessage
        return TranscribeMessage(
            job_id="test-job-123",
            video_id="test-video-456",
            youtube_video_id="dQw4w9WgXcQ",
            correlation_id="test-correlation",
        )

    async def test_rate_limit_error_returns_rate_limited_result(self, worker, message):
        """When RateLimitError is raised, should return rate_limited result for infinite retry."""
        from transcribe.worker import RateLimitError
        from shared.worker.base_worker import WorkerStatus
        
        with patch("transcribe.worker.mark_job_running", new_callable=AsyncMock), \
             patch("transcribe.worker.mark_job_rate_limited", new_callable=AsyncMock) as mock_rate_limited, \
             patch.object(worker, "_fetch_transcript_with_timestamps_and_text", new_callable=AsyncMock) as mock_fetch, \
             patch.object(worker, "_check_existing_transcript", new_callable=AsyncMock) as mock_check:
            
            # No existing transcript in blob storage
            mock_check.return_value = None
            # Simulate rate limit error
            mock_fetch.side_effect = RateLimitError("YouTube is rate limiting requests")
            
            result = await worker.process_message(message, "test-correlation")
            
            assert result.status == WorkerStatus.RATE_LIMITED
            assert "rate limit" in result.message.lower()
            assert result.data["retry_delay"] == 300  # 5 minutes
            # Verify the rate limit function was called with job_id, video_id, and retry_delay
            mock_rate_limited.assert_called_once_with(message.job_id, message.video_id, 300)

    async def test_rate_limit_does_not_increment_retry_count(self, worker, message):
        """Rate limited jobs should not count toward max_retries."""
        from transcribe.worker import RateLimitError
        from shared.worker.base_worker import WorkerStatus
        
        with patch("transcribe.worker.mark_job_running", new_callable=AsyncMock), \
             patch("transcribe.worker.mark_job_rate_limited", new_callable=AsyncMock), \
             patch.object(worker, "_fetch_transcript_with_timestamps_and_text", new_callable=AsyncMock) as mock_fetch, \
             patch.object(worker, "_check_existing_transcript", new_callable=AsyncMock) as mock_check:
            
            # No existing transcript in blob storage
            mock_check.return_value = None
            mock_fetch.side_effect = RateLimitError("IP blocked")
            
            result = await worker.process_message(message, "test-correlation")
            
            # Rate limited should use WorkerStatus.RATE_LIMITED, not FAILED
            # This means the base worker won't increment retry_count
            assert result.status == WorkerStatus.RATE_LIMITED
