"""
Test file to validate CI workflow - originally contained failing test.
The failing test was fixed to demonstrate CI passes after fix.
This file should be deleted after T089 validation is complete.
"""

import pytest


def test_ci_validation_now_passes():
    """This test now passes - CI should allow merge."""
    assert True, "Test passes - CI validation complete"
