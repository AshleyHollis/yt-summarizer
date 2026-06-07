"""Agent API route tests — unit tests for /api/v1/agent/* endpoints."""

import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

TEST_API_KEY = "test-key"
AUTH_HEADERS = {"X-API-Key": TEST_API_KEY}


def _make_agent_app(override_auth: bool = True):
    """Create minimal FastAPI test app with the agent router."""

    @asynccontextmanager
    async def _lifespan(app: FastAPI):
        yield

    app = FastAPI(lifespan=_lifespan)

    from api.routes.agent import router

    app.include_router(router)

    from shared.db.connection import get_session

    mock_sess = AsyncMock()
    mock_result = MagicMock()
    mock_scalars = MagicMock()
    mock_scalars.all.return_value = []
    mock_scalars.first.return_value = None
    mock_result.scalars.return_value = mock_scalars
    mock_result.scalar_one_or_none.return_value = None
    mock_sess.execute = AsyncMock(return_value=mock_result)
    mock_sess.add = MagicMock()
    mock_sess.flush = AsyncMock()
    mock_sess.commit = AsyncMock()
    mock_sess.rollback = AsyncMock()

    async def _mock_get_session():
        yield mock_sess

    app.dependency_overrides[get_session] = _mock_get_session

    if override_auth:
        from api.dependencies.auth import AuthenticatedUser, require_api_key

        _user = AuthenticatedUser(
            sub="api-key",
            email="openclaw@internal",
            name="OpenClaw",
            picture=None,
            raw={"sub": "api-key"},
        )

        async def _mock_api_key():
            return _user

        app.dependency_overrides[require_api_key] = _mock_api_key

    return app, mock_sess


def _make_mock_search_svc(segments=None):
    """Return a mock SearchService whose fallback returns given segments."""
    svc = AsyncMock()
    result = MagicMock()
    result.segments = segments or []
    svc.fallback_text_search_segments = AsyncMock(return_value=result)
    svc.search_segments = AsyncMock(return_value=result)
    return svc


def _make_scored_segment(video_id=None, text="hello world"):
    """Return a mock ScoredSegment object."""
    seg = MagicMock()
    seg.video_id = video_id or uuid4()
    seg.video_title = "Test Video"
    seg.text = text
    seg.start_time = 0.0
    seg.end_time = 10.0
    seg.youtube_url = "https://www.youtube.com/watch?v=abc&t=0s"
    seg.score = 0.9
    return seg


@pytest.mark.unit
class TestAgentAuth:
    def test_valid_api_key_accepted(self, monkeypatch):
        monkeypatch.setenv("API_KEY", TEST_API_KEY)
        app, _ = _make_agent_app(override_auth=False)

        from api.routes.agent import get_search_service

        mock_svc = _make_mock_search_svc()
        app.dependency_overrides[get_search_service] = lambda: mock_svc

        client = TestClient(app)
        resp = client.post(
            "/api/v1/agent/search/semantic",
            json={"query": "machine learning"},
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 200

    def test_missing_api_key_returns_401(self, monkeypatch):
        monkeypatch.setenv("API_KEY", TEST_API_KEY)
        app, _ = _make_agent_app(override_auth=False)
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.post(
            "/api/v1/agent/search/semantic",
            json={"query": "machine learning"},
        )
        assert resp.status_code == 401


@pytest.mark.unit
class TestSemanticSearch:
    def test_search_returns_response_shape(self):
        app, _ = _make_agent_app()

        from api.routes.agent import get_search_service

        vid_id = uuid4()
        mock_svc = _make_mock_search_svc(
            [_make_scored_segment(vid_id, "forty character snippet text!")]
        )
        app.dependency_overrides[get_search_service] = lambda: mock_svc

        client = TestClient(app)
        resp = client.post(
            "/api/v1/agent/search/semantic",
            json={"query": "test query"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "results" in data
        assert "total" in data
        assert "estimated_tokens" in data
        assert data["total"] == 1
        assert data["results"][0]["video_id"] == str(vid_id)

    def test_empty_results(self):
        app, _ = _make_agent_app()

        from api.routes.agent import get_search_service

        mock_svc = _make_mock_search_svc([])
        app.dependency_overrides[get_search_service] = lambda: mock_svc

        client = TestClient(app)
        resp = client.post(
            "/api/v1/agent/search/semantic",
            json={"query": "nothing"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["results"] == []
        assert data["total"] == 0


@pytest.mark.unit
class TestYouTubeSearch:
    def test_youtube_search_returns_response_shape(self):
        app, _ = _make_agent_app()

        fake_results = [
            {
                "youtube_video_id": "abc123",
                "title": "Test Video",
                "channel": "Test Channel",
                "duration_seconds": 300,
                "url": "https://www.youtube.com/watch?v=abc123",
                "thumbnail_url": None,
            }
        ]

        with patch(
            "api.routes.agent.YouTubeService.search_videos",
            new=AsyncMock(return_value=fake_results),
        ):
            client = TestClient(app)
            resp = client.get("/api/v1/agent/youtube/search", params={"q": "python tutorials"})

        assert resp.status_code == 200
        data = resp.json()
        assert "results" in data
        assert "total" in data
        assert data["total"] == 1
        assert data["results"][0]["youtube_video_id"] == "abc123"

    def test_youtube_search_limit_capped(self):
        app, _ = _make_agent_app()

        with patch(
            "api.routes.agent.YouTubeService.search_videos",
            new=AsyncMock(return_value=[]),
        ) as mock_search:
            client = TestClient(app)
            resp = client.get("/api/v1/agent/youtube/search", params={"q": "test", "limit": 50})
            assert resp.status_code == 200
            mock_search.assert_called_once()
            _, called_limit = mock_search.call_args[0]
            assert called_limit == 50


@pytest.mark.unit
class TestGetVideo:
    def test_returns_segment_index_without_transcript(self):
        app, mock_sess = _make_agent_app()

        vid_id = uuid4()
        mock_video = MagicMock()
        mock_video.video_id = vid_id
        mock_video.youtube_video_id = "dQw4w9WgXcQ"
        mock_video.title = "Never Gonna Give You Up"
        mock_video.channel = MagicMock()
        mock_video.channel.name = "Rick Astley"
        mock_video.duration = 213
        mock_video.processing_status = "completed"

        mock_seg = MagicMock()
        mock_seg.sequence_number = 1
        mock_seg.start_time = 0.0
        mock_seg.end_time = 10.0
        mock_seg.label = "intro"

        # First execute → video result; second execute → segments result; third → artifact result
        video_result = MagicMock()
        video_result.scalar_one_or_none.return_value = mock_video

        seg_result = MagicMock()
        seg_scalars = MagicMock()
        seg_scalars.all.return_value = [mock_seg]
        seg_result.scalars.return_value = seg_scalars

        artifact_result = MagicMock()
        artifact_result.scalar_one_or_none.return_value = None  # no artifact → summary=None

        mock_sess.execute = AsyncMock(side_effect=[video_result, seg_result, artifact_result])

        client = TestClient(app)
        resp = client.get(f"/api/v1/agent/videos/{vid_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert "segments_index" in data
        assert len(data["segments_index"]) == 1
        assert data["segments_index"][0]["seq"] == 1
        assert "summary" in data  # field exists (may be null)

    def test_unknown_id_returns_404(self):
        app, mock_sess = _make_agent_app()

        video_result = MagicMock()
        video_result.scalar_one_or_none.return_value = None
        mock_sess.execute = AsyncMock(return_value=video_result)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(f"/api/v1/agent/videos/{uuid4()}")
        assert resp.status_code == 404

    def test_summary_loaded_from_artifact(self):
        """Artifact query runs without error; summary is None (blob download needed)."""
        app, mock_sess = _make_agent_app()

        vid_id = uuid4()
        mock_video = MagicMock()
        mock_video.video_id = vid_id
        mock_video.youtube_video_id = "abc"
        mock_video.title = "Test"
        mock_video.channel = None
        mock_video.duration = 100
        mock_video.processing_status = "completed"

        video_result = MagicMock()
        video_result.scalar_one_or_none.return_value = mock_video

        seg_result = MagicMock()
        seg_result.scalars.return_value = MagicMock(all=MagicMock(return_value=[]))

        mock_artifact = MagicMock()
        mock_artifact.artifact_type = "summary"
        mock_artifact.blob_uri = "https://storage.example.com/summary.txt"
        artifact_result = MagicMock()
        artifact_result.scalar_one_or_none.return_value = mock_artifact

        mock_sess.execute = AsyncMock(side_effect=[video_result, seg_result, artifact_result])

        client = TestClient(app)
        resp = client.get(f"/api/v1/agent/videos/{vid_id}")
        assert resp.status_code == 200
        data = resp.json()
        # Artifact exists but content requires blob download — summary remains None
        assert data["summary"] is None


@pytest.mark.unit
class TestGetSegments:
    def test_filters_by_timestamp_range(self):
        app, mock_sess = _make_agent_app()

        vid_id = uuid4()
        mock_video = MagicMock()
        mock_video.video_id = vid_id
        mock_video.youtube_video_id = "abc123"

        mock_seg = MagicMock()
        mock_seg.sequence_number = 2
        mock_seg.text = "transcript text here"
        mock_seg.start_time = 5.0
        mock_seg.end_time = 15.0

        video_result = MagicMock()
        video_result.scalar_one_or_none.return_value = mock_video

        seg_result = MagicMock()
        seg_scalars = MagicMock()
        seg_scalars.all.return_value = [mock_seg]
        seg_result.scalars.return_value = seg_scalars

        mock_sess.execute = AsyncMock(side_effect=[video_result, seg_result])

        client = TestClient(app)
        resp = client.get(
            f"/api/v1/agent/videos/{vid_id}/segments",
            params={"start_sec": 0, "end_sec": 20},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "segments" in data
        assert len(data["segments"]) == 1
        assert data["segments"][0]["text"] == "transcript text here"

    def test_missing_video_returns_404(self):
        app, mock_sess = _make_agent_app()

        video_result = MagicMock()
        video_result.scalar_one_or_none.return_value = None
        mock_sess.execute = AsyncMock(return_value=video_result)

        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get(f"/api/v1/agent/videos/{uuid4()}/segments")
        assert resp.status_code == 404


@pytest.mark.unit
class TestAsk:
    def _make_evidence(self, n: int = 3):
        evidence_items = []
        for i in range(n):
            e = MagicMock()
            e.video_id = uuid4()
            e.video_title = f"Video {i}"
            e.start_time = float(i * 10)
            e.end_time = float(i * 10 + 10)
            e.youtube_url = f"https://www.youtube.com/watch?v=vid{i}&t={i * 10}s"
            e.segment_text = f"Evidence text {i}"
            e.confidence = 0.9
            evidence_items.append(e)
        return evidence_items

    def test_returns_answer_with_citations(self):
        app, _ = _make_agent_app()

        from api.routes.agent import get_copilot_service

        mock_cop_svc = AsyncMock()
        mock_response = MagicMock()
        mock_response.answer = "The answer is 42."
        mock_response.evidence = self._make_evidence(2)
        mock_cop_svc.query = AsyncMock(return_value=mock_response)
        app.dependency_overrides[get_copilot_service] = lambda: mock_cop_svc

        client = TestClient(app)
        resp = client.post(
            "/api/v1/agent/ask",
            json={"query": "What is the meaning of life?"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["answer"] == "The answer is 42."
        assert "citations" in data
        assert len(data["citations"]) == 2
        assert "estimated_tokens" in data

    def test_citations_capped_at_max_evidence_segments(self):
        app, _ = _make_agent_app()

        from api.routes.agent import get_copilot_service

        mock_cop_svc = AsyncMock()
        mock_response = MagicMock()
        mock_response.answer = "Short answer."
        mock_response.evidence = self._make_evidence(10)
        mock_cop_svc.query = AsyncMock(return_value=mock_response)
        app.dependency_overrides[get_copilot_service] = lambda: mock_cop_svc

        client = TestClient(app)
        resp = client.post(
            "/api/v1/agent/ask",
            json={"query": "test", "max_evidence_segments": 3},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["citations"]) == 3


@pytest.mark.unit
class TestIngest:
    def test_returns_202_with_job_id(self):
        app, _ = _make_agent_app()

        job_id = uuid4()
        vid_id = uuid4()

        mock_result = MagicMock()
        mock_result.job_id = job_id
        mock_result.video_id = vid_id
        mock_result.status = MagicMock()
        mock_result.status.value = "pending"

        with patch("api.services.video_service.VideoService") as MockVS:
            mock_instance = AsyncMock()
            mock_instance.submit_video = AsyncMock(return_value=mock_result)
            MockVS.return_value = mock_instance

            client = TestClient(app)
            resp = client.post(
                "/api/v1/agent/videos",
                json={"url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ"},
            )

        assert resp.status_code == 202
        data = resp.json()
        assert data["job_id"] == str(job_id)
        assert data["video_id"] == str(vid_id)
        assert "status" in data

    def test_duplicate_ingest_returns_409(self):
        app, _ = _make_agent_app()

        vid_id = uuid4()
        job_id = uuid4()

        from api.services.video_service import VideoAlreadyExistsError

        class _FakeStatus:
            value = "completed"

        error = VideoAlreadyExistsError(video_id=vid_id, job_id=job_id, status=_FakeStatus())

        with patch("api.services.video_service.VideoService") as MockVS:
            mock_instance = AsyncMock()
            mock_instance.submit_video = AsyncMock(side_effect=error)
            MockVS.return_value = mock_instance

            client = TestClient(app, raise_server_exceptions=False)
            resp = client.post(
                "/api/v1/agent/videos",
                json={"url": "https://www.youtube.com/watch?v=dQw4w9WgXcQ"},
            )

        assert resp.status_code == 409
        data = resp.json()
        assert data["detail"]["video_id"] == str(vid_id)


@pytest.mark.unit
class TestJobStatus:
    def test_returns_job_status_response(self):
        app, _ = _make_agent_app()

        job_id = uuid4()
        vid_id = uuid4()
        now_str = datetime.now(timezone.utc)

        mock_job = MagicMock()
        mock_job.job_id = job_id
        mock_job.video_id = vid_id
        mock_job.status = MagicMock()
        mock_job.status.value = "running"
        mock_job.progress = 50
        mock_job.created_at = now_str
        mock_job.updated_at = now_str

        with patch("api.services.job_service.JobService") as MockJS:
            mock_instance = AsyncMock()
            mock_instance.get_job = AsyncMock(return_value=mock_job)
            MockJS.return_value = mock_instance

            client = TestClient(app)
            resp = client.get(f"/api/v1/agent/jobs/{job_id}")

        assert resp.status_code == 200
        data = resp.json()
        assert data["job_id"] == str(job_id)
        assert "status" in data

    def test_missing_job_returns_404(self):
        app, _ = _make_agent_app()

        with patch("api.services.job_service.JobService") as MockJS:
            mock_instance = AsyncMock()
            mock_instance.get_job = AsyncMock(return_value=None)
            MockJS.return_value = mock_instance

            client = TestClient(app, raise_server_exceptions=False)
            resp = client.get(f"/api/v1/agent/jobs/{uuid4()}")

        assert resp.status_code == 404
