"""Tests for admin backup status endpoints."""

from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock
from uuid import uuid4

from api.dependencies.auth import AuthenticatedUser
from api.routes import admin


def _backup_job(**overrides):
    metadata = overrides.pop(
        "metadata_json",
        """
        {
          "run_id": "20260609T160000Z-test",
          "current_channel": "mark-wildman",
          "total_channels": 1,
          "completed_channels": 0,
          "copied_blobs": 2,
          "skipped_blobs": 3,
          "missing_blobs": 0,
          "bytes_copied": 2048,
          "warnings": [],
          "report_blob_path": null,
          "channels": [
            {
              "slug": "mark-wildman",
              "name": "Mark Wildman",
              "status": "running",
              "phase": "copying",
              "total_videos": 10,
              "processed_videos": 4,
              "copied_blobs": 2,
              "skipped_blobs": 3,
              "missing_blobs": 0,
              "bytes_copied": 2048,
              "warnings": []
            }
          ]
        }
        """,
    )
    values = {
        "job_id": uuid4(),
        "correlation_id": "20260609T160000Z-test",
        "status": "running",
        "stage": "running",
        "progress": 40,
        "started_at": datetime(2026, 6, 9, 16, 0, 0),
        "completed_at": None,
        "error_message": None,
        "metadata_json": metadata,
    }
    values.update(overrides)
    return SimpleNamespace(**values)


async def _mock_admin():
    return AuthenticatedUser(
        sub="auth0|admin",
        email="admin@example.com",
        name="Admin",
        picture=None,
        raw={"sub": "auth0|admin", "email": "admin@example.com"},
    )


def test_backup_run_from_job_parses_metadata():
    job = _backup_job()

    result = admin._backup_run_from_job(job)

    assert result.run_id == "20260609T160000Z-test"
    assert result.current_channel == "mark-wildman"
    assert result.copied_blobs == 2
    assert result.channels[0].processed_videos == 4


def test_backup_status_returns_empty_when_no_runs(app, client):
    app.dependency_overrides[admin.require_admin] = _mock_admin

    response = client.get("/api/v1/admin/backups/status")

    assert response.status_code == 200
    assert response.json() == {"latest_run": None}


def test_backup_runs_lists_system_jobs(app, client, mock_session):
    app.dependency_overrides[admin.require_admin] = _mock_admin
    result = MagicMock()
    scalars = MagicMock()
    scalars.all.return_value = [_backup_job()]
    result.scalars.return_value = scalars
    mock_session.execute.return_value = result

    response = client.get("/api/v1/admin/backups/runs")

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["runs"][0]["current_channel"] == "mark-wildman"
