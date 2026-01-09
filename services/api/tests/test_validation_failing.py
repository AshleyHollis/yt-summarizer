"""
Intentional failing test to validate CI blocks merge on test failure.
This file should be deleted after T089 validation is complete.
"""

import pytest


def test_intentional_failure_for_ci_validation():
    """This test intentionally fails to verify CI blocks merge."""
    assert False, "INTENTIONAL FAILURE: This test validates CI blocks merge when tests fail"
