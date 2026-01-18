#!/bin/bash
# =============================================================================
# CI: Run Pre-commit on Workflow Files
# =============================================================================
# Validates GitHub Actions workflow YAML files with pre-commit hooks
#
# BEHAVIOR:
#   - Runs pre-commit on all .yml and .yaml files in .github/workflows/
#   - Does NOT fail the workflow if pre-commit fails (|| true)
#   - Useful for catching common formatting/linting issues
#
# USAGE:
#   scripts/workflows/ci-run-precommit-workflows.sh
# =============================================================================

set -e

# Run pre-commit on workflow files
# Use || true to not fail the workflow if pre-commit detects issues
pre-commit run --files .github/workflows/*.yml || true
pre-commit run --files .github/workflows/*.yaml || true

echo "✓ Pre-commit validation complete (non-blocking)"
