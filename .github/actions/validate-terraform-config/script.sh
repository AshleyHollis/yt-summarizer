#!/bin/bash
# =============================================================================
# Validate Terraform Configuration
# =============================================================================
# PURPOSE:
#   Initializes and validates Terraform configuration
#
# INPUTS (via environment variables):
#   WORKING_DIRECTORY    Directory containing Terraform configuration
#   BACKEND_CONFIG       Whether to initialize with backend (true/false)
#
# OUTPUTS:
#   Exit code 0 if validation passes, 1 if fails
#
# LOGIC:
#   1. Change to working directory
#   2. Run terraform init (with or without backend)
#   3. Run terraform validate
#
# =============================================================================
set -euo pipefail

cd "${WORKING_DIRECTORY}"

if [ "${BACKEND_CONFIG}" = "true" ]; then
  echo "Initializing Terraform with backend configuration..."
  terraform init -input=false
else
  echo "Initializing Terraform without backend..."
  terraform init -backend=false
fi

echo "Validating Terraform configuration..."
terraform validate -no-color
