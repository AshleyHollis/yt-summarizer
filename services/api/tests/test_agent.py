"""Agent API route tests — unit tests for /api/v1/agent/* endpoints."""

import pytest


@pytest.mark.unit
class TestAgentAuth:
    def test_valid_api_key_accepted(self):
        pass  # Kane will implement

    def test_missing_api_key_returns_401(self):
        pass  # Kane will implement


@pytest.mark.unit
class TestSemanticSearch:
    def test_search_returns_response_shape(self):
        pass


@pytest.mark.unit
class TestYouTubeSearch:
    def test_youtube_search_returns_response_shape(self):
        pass


@pytest.mark.unit
class TestGetVideo:
    def test_returns_segment_index_without_transcript(self):
        pass

    def test_unknown_id_returns_404(self):
        pass


@pytest.mark.unit
class TestGetSegments:
    def test_filters_by_timestamp_range(self):
        pass


@pytest.mark.unit
class TestAsk:
    def test_returns_answer_with_citations(self):
        pass

    def test_citations_capped_at_max_evidence_segments(self):
        pass


@pytest.mark.unit
class TestIngest:
    def test_returns_ingest_response(self):
        pass


@pytest.mark.unit
class TestJobStatus:
    def test_returns_job_status_response(self):
        pass
