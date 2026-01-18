#!/bin/bash
# =============================================================================
# Setup Python
# =============================================================================
# PURPOSE:
#   Setup Python with uv package manager and dependency caching
#
# INPUTS (via environment variables):
#   PYTHON_VERSION       Python version to install
#   WORKING_DIRECTORY    Working directory for pip install
#
# OUTPUTS:
#   Installed Python environment with uv and dependencies
#
# LOGIC:
#   Note: Python and uv setup handled by external actions (setup-python,
#   setup-uv). This script handles the pip install step.
#   1. Change to working directory
#   2. Install package in development mode
#
# =============================================================================
set -euo pipefail

cd "${WORKING_DIRECTORY}"

echo "Installing dependencies with uv..."
uv pip install --system -e ".[dev]"
