#!/bin/bash
# =============================================================================
# Validate Terraform Configuration
# =============================================================================
# PURPOSE:
#   Initializes and validates Terraform configuration
#
# INPUTS (via environment variables):
#   BACKEND_CONFIG       Whether to initialize with backend (true/false)
#
# OUTPUTS:
#   Exit code 0 if validation passes, 1 if fails
#
# LOGIC:
#   1. Run terraform init (with or without backend)
#   2. Run terraform validate
#   (Note: GitHub Actions sets working-directory via action.yml)
#
# =============================================================================
set -euo pipefail

if [ "${BACKEND_CONFIG}" = "true" ]; then
  echo "Initializing Terraform with backend configuration..."
  terraform init -input=false
else
  echo "Initializing Terraform without backend..."
  terraform init -backend=false
fi

echo "Validating Terraform configuration..."
terraform validate -no-color
