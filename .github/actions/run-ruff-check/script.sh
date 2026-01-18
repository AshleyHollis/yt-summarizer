#!/bin/bash
# =============================================================================
# Run ruff Checks
# =============================================================================
# PURPOSE:
#   Runs ruff linter and formatter checks on Python code
#
# INPUTS (via environment variables):
#   TARGET_PATH         Path to check with ruff
#
# OUTPUTS:
#   Linting and formatting diagnostics
#
# LOGIC:
#   1. Install ruff via pip
#   2. Change to target path
#   3. Run ruff linter with auto-discovered config
#   4. Run ruff formatter check
#
# =============================================================================
set -euo pipefail

echo "Installing ruff..."
pip install ruff

cd "${TARGET_PATH}"

echo "🔍 Running ruff linter in ${TARGET_PATH}..."
# Ruff auto-discovers configuration from pyproject.toml or ruff.toml
# in the current directory or parent directories
ruff check .

echo "✨ Checking ruff formatting in ${TARGET_PATH}..."
ruff format --check .
