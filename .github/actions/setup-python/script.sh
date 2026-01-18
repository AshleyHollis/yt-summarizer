#!/bin/bash
# =============================================================================
# Setup Python
# =============================================================================
# PURPOSE:
#   Setup Python with uv package manager and dependency caching
#
# INPUTS (via environment variables):
#   PYTHON_VERSION       Python version to install
#
# OUTPUTS:
#   Installed Python environment with uv and dependencies
#
# LOGIC:
#   Note: Python and uv setup handled by external actions (setup-python,
#   setup-uv). This script handles the pip install step.
#   Install package in development mode
#   (Note: GitHub Actions sets working-directory via action.yml)
#
# =============================================================================
set -euo pipefail

echo "Installing dependencies with uv..."
uv pip install --system -e ".[dev]"
