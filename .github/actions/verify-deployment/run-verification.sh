#!/bin/bash
# =============================================================================
# Verify Deployment Image - Wrapper Script
# =============================================================================
# PURPOSE:
#   Wrapper to normalize GitHub Actions composite action inputs into
#   environment variables for the main script.sh
#
# INPUTS (via environment variables from composite action):
#   INPUT_NAMESPACE             Kubernetes namespace
#   INPUT_DEPLOYMENT_NAME       Name of the deployment
#   INPUT_EXPECTED_TAG          Expected image tag
#   INPUT_REGISTRY              Container registry
#   INPUT_IMAGE_NAME            Image name (without registry)
#   INPUT_TIMEOUT_SECONDS       Timeout in seconds (optional)
#   INPUT_WAIT_FOR_READY        Wait for rollout (optional)
#
# LOGIC:
#   1. Ensure action path is set
#   2. Source the main verification script
#
# =============================================================================

set -euo pipefail

cd "${{ github.action_path }}" && bash script.sh
