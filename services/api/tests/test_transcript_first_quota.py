"""Tests for transcript-first quota and processing-mode contracts."""

from api.dependencies.quota import (
    AI_FEATURES_OPERATION,
    TRANSCRIPT_EXTRACT_OPERATION,
    get_quota_operation_for_job_type,
)
from api.models.batch import CreateBatchRequest
from api.models.processing import ProcessingMode
from api.models.video import SubmitVideoRequest


def test_processing_mode_defaults_to_full_analysis():
    video_request = SubmitVideoRequest(url="https://youtube.com/watch?v=dQw4w9WgXcQ")
    batch_request = CreateBatchRequest(
        name="Test Batch",
        video_ids=["dQw4w9WgXcQ"],
    )

    assert video_request.processing_mode == ProcessingMode.FULL_ANALYSIS
    assert batch_request.processing_mode == ProcessingMode.FULL_ANALYSIS


def test_processing_mode_accepts_transcript_only():
    request = SubmitVideoRequest(
        url="https://youtube.com/watch?v=dQw4w9WgXcQ",
        processing_mode=ProcessingMode.TRANSCRIPT_ONLY,
    )

    assert request.processing_mode == ProcessingMode.TRANSCRIPT_ONLY


def test_quota_operation_mapping():
    assert get_quota_operation_for_job_type("transcribe") == TRANSCRIPT_EXTRACT_OPERATION
    assert get_quota_operation_for_job_type("summarize") == AI_FEATURES_OPERATION
    assert get_quota_operation_for_job_type("embed") == AI_FEATURES_OPERATION
    assert get_quota_operation_for_job_type("build_relationships") == AI_FEATURES_OPERATION
    assert get_quota_operation_for_job_type("unknown") is None
