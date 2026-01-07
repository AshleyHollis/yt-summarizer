"""Pytest configuration for shared package tests."""

import sys
from pathlib import Path

# Add shared package to path for imports
shared_path = Path(__file__).parent.parent / "shared"
if str(shared_path.parent) not in sys.path:
    sys.path.insert(0, str(shared_path.parent))
