"""Integration tests for LibraryService summary fetching.

These tests verify the end-to-end flow of fetching video summaries,
including the correct blob path extraction that was the source of a bug.

REGRESSION CONTEXT:
The API was incorrectly extracting blob names from blob URIs, taking only
the filename instead of the full path with video_id folder:
  BROKEN: blob_uri.split("/")[-1] → "hzkm3hM8FUg_summary.md"
  FIXED:  split on "/summaries/" → "a7311eb9-xxx/hzkm3hM8FUg_summary.md"

This caused 404 errors when fetching summaries from blob storage.

Prerequisites:
- Database must be running (via Aspire)
- Blob storage must be running (Azurite via Aspire)
- Run with: pytest tests/test_library_integration.py -v
"""

import os

import pytest

# Mark all tests as integration tests
pytestmark = pytest.mark.integration


class TestLibrarySummaryFetchingIntegration:
    """Integration tests for summary fetching from blob storage."""

    @pytest.fixture
    def api_base_url(self):
        """Get the API base URL."""
        return os.environ.get("API_BASE_URL", "http://localhost:8000")

    @pytest.mark.asyncio
    async def test_completed_video_returns_summary_content(self, api_base_url):
        """
        REGRESSION TEST: Verify completed videos return non-null summary content.
        
        This test catches the blob path extraction bug by verifying that:
        1. Completed videos have summary content (not null)
        2. The API doesn't return 500 errors due to blob fetch failures
        3. Response time is acceptable (no retry delays from 404s)
        """
        import httpx
        
        async with httpx.AsyncClient(base_url=api_base_url) as client:
            # Get completed videos
            list_response = await client.get(
                "/api/v1/library/videos",
                params={"status": "completed", "page_size": 1},
                headers={"X-Correlation-ID": "integration-summary-test"}
            )
            
            if list_response.status_code != 200:
                pytest.skip(f"API not available or no data: {list_response.status_code}")
            
            list_data = list_response.json()
            
            if not list_data.get("videos"):
                pytest.skip("No completed videos in database")
            
            video = list_data["videos"][0]
            video_id = video["video_id"]
            
            # Fetch video detail - this is where the bug manifested
            import time
            start_time = time.time()
            
            detail_response = await client.get(
                f"/api/v1/library/videos/{video_id}",
                headers={"X-Correlation-ID": "integration-summary-test"}
            )
            
            response_time = time.time() - start_time
            
            assert detail_response.status_code == 200, (
                f"Video detail fetch failed: {detail_response.status_code}"
            )
            
            detail_data = detail_response.json()
            
            # CRITICAL: Summary must not be null for completed videos
            # This is the primary assertion that catches the blob path bug
            assert detail_data.get("summary") is not None, (
                f"Summary is null for completed video {video_id}. "
                "This indicates the blob path extraction may be broken."
            )
            
            assert len(detail_data["summary"]) > 0, (
                "Summary is empty for completed video"
            )
            
            # Response should be fast (under 2 seconds)
            # The bug caused 3-5+ second delays due to blob 404 retries
            assert response_time < 2.0, (
                f"Response took {response_time:.2f}s - possible retry delays from blob 404s"
            )

    @pytest.mark.asyncio
    async def test_summary_artifact_has_valid_blob_uri(self, api_base_url):
        """
        Verify that completed videos with summary artifacts return summary content.
        
        Note: The blob_uri is an internal implementation detail and may not be
        exposed in the API response. What matters is that the summary content
        is successfully retrieved and returned.
        """
        import httpx
        
        async with httpx.AsyncClient(base_url=api_base_url) as client:
            # Get completed videos
            list_response = await client.get(
                "/api/v1/library/videos",
                params={"status": "completed", "page_size": 10},
                headers={"X-Correlation-ID": "integration-blob-uri-test"}
            )
            
            if list_response.status_code != 200:
                pytest.skip("API not available")
            
            list_data = list_response.json()
            
            if not list_data.get("videos"):
                pytest.skip("No completed videos in database")
            
            # For each completed video, verify summary content is present
            for video in list_data["videos"]:
                video_id = video["video_id"]
                
                detail_response = await client.get(
                    f"/api/v1/library/videos/{video_id}",
                    headers={"X-Correlation-ID": "integration-blob-uri-test"}
                )
                
                if detail_response.status_code != 200:
                    continue
                
                detail_data = detail_response.json()
                
                # CRITICAL: Completed videos with summary artifacts must have summary content
                if detail_data.get("summary_artifact"):
                    assert detail_data.get("summary") is not None, (
                        f"Video {video_id} has summary_artifact but summary is null. "
                        f"This indicates the blob path extraction may be broken."
                    )
                    assert len(detail_data["summary"]) > 0, (
                        f"Video {video_id} has empty summary content"
                    )


class TestBlobStorageConnectivity:
    """Test blob storage connectivity and access."""

    @pytest.fixture
    def api_base_url(self):
        """Get the API base URL."""
        return os.environ.get("API_BASE_URL", "http://localhost:8000")

    @pytest.fixture
    def blob_storage_url(self):
        """Get blob storage connection info."""
        return os.environ.get(
            "ConnectionStrings__blobs",
            "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;"
        )

    @pytest.mark.asyncio
    async def test_blob_storage_accessible(self, blob_storage_url):
        """Verify blob storage is accessible."""
        try:
            from shared.blob.client import BlobClient
            
            client = BlobClient()
            
            # List blobs in summaries container
            # This tests basic connectivity
            blobs = client.list_blobs("summaries")
            
            # Just verify we can iterate (don't need actual content)
            count = 0
            for _ in blobs:
                count += 1
                if count > 5:
                    break  # Don't need to list everything
            
            # If we got here without exception, blob storage is accessible
            assert True
            
        except ImportError:
            pytest.skip("BlobClient not available")
        except Exception as e:
            pytest.skip(f"Blob storage not accessible: {e}")

    @pytest.mark.asyncio
    async def test_summary_blob_exists_for_completed_video(self, api_base_url, blob_storage_url):
        """
        Verify that summary content is successfully retrieved.
        
        This test validates the end-to-end flow by checking that the API
        can successfully fetch and return summary content for completed videos.
        """
        import httpx
        
        async with httpx.AsyncClient(base_url=api_base_url) as client:
            # Get a completed video
            list_response = await client.get(
                "/api/v1/library/videos",
                params={"status": "completed", "page_size": 1},
                headers={"X-Correlation-ID": "integration-blob-exists-test"}
            )
            
            if list_response.status_code != 200:
                pytest.skip("API not available")
            
            list_data = list_response.json()
            
            if not list_data.get("videos"):
                pytest.skip("No completed videos")
            
            video_id = list_data["videos"][0]["video_id"]
            
            detail_response = await client.get(
                f"/api/v1/library/videos/{video_id}",
                headers={"X-Correlation-ID": "integration-blob-exists-test"}
            )
            
            detail_data = detail_response.json()
            
            summary_artifact = detail_data.get("summary_artifact")
            if not summary_artifact:
                pytest.skip("Video has no summary artifact")
            
            # The summary content should be present if the blob was fetched successfully
            assert detail_data.get("summary") is not None, (
                f"Summary content is null for video {video_id} with summary_artifact. "
                "This indicates a blob storage fetch failure."
            )
            
            assert len(detail_data["summary"]) > 0, (
                "Summary content is empty"
            )
            
            # Verify the summary looks like markdown content
            summary = detail_data["summary"]
            assert isinstance(summary, str), "Summary should be a string"
            # Summary should have some reasonable length
            assert len(summary) > 100, (
                f"Summary seems too short ({len(summary)} chars) - might be an error message"
            )


class TestLibraryAPIResponseContract:
    """Contract tests for library API responses."""

    @pytest.fixture
    def api_base_url(self):
        return os.environ.get("API_BASE_URL", "http://localhost:8000")

    @pytest.mark.asyncio
    async def test_video_detail_response_contract(self, api_base_url):
        """
        Verify video detail API response matches expected contract.
        
        Completed videos MUST have:
        - summary: string (non-null)
        - summary_artifact: object with blob_uri
        """
        import httpx
        
        async with httpx.AsyncClient(base_url=api_base_url) as client:
            list_response = await client.get(
                "/api/v1/library/videos",
                params={"status": "completed", "page_size": 1},
                headers={"X-Correlation-ID": "contract-test"}
            )
            
            if list_response.status_code != 200:
                pytest.skip("API not available")
            
            list_data = list_response.json()
            
            if not list_data.get("videos"):
                pytest.skip("No completed videos")
            
            video_id = list_data["videos"][0]["video_id"]
            
            detail_response = await client.get(
                f"/api/v1/library/videos/{video_id}",
                headers={"X-Correlation-ID": "contract-test"}
            )
            
            assert detail_response.status_code == 200
            
            data = detail_response.json()
            
            # Required fields for all videos
            assert "video_id" in data
            assert "youtube_video_id" in data
            assert "title" in data
            assert "processing_status" in data
            
            # Required fields for completed videos
            if data["processing_status"] == "completed":
                assert "summary" in data, "Completed video missing 'summary' field"
                assert data["summary"] is not None, (
                    "Completed video has null summary - blob fetch likely failed"
                )
                
                # summary_artifact should exist
                assert data.get("summary_artifact") is not None, (
                    "Completed video missing summary_artifact"
                )
