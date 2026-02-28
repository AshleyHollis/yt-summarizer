#!/usr/bin/env bash
# =============================================================================
# Terraform Config Validator
# =============================================================================
# Validates Terraform configuration syntax and formatting
# Replaces: validate-terraform-config action (partially)

set -uo pipefail

# Load common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$SCRIPT_DIR/common.sh"

# Configuration
TF_DIR="${TERRAFORM_DIRECTORY:-}"
BACKEND_CONFIG="${TERRAFORM_BACKEND_CONFIG:-false}"

log_info "Terraform Config Validator"
log_info "Directory: ${TF_DIR:-<not set>}"
log_info "Backend config check: $BACKEND_CONFIG"
echo ""

# Validate required inputs
if [[ -z "$TF_DIR" ]]; then
  log_error "TERRAFORM_DIRECTORY is required"
  exit 1
fi

if ! require_directory "$TF_DIR"; then
  exit 1
fi

# Check terraform is available
if ! require_command terraform "https://www.terraform.io/downloads"; then
  exit 1
fi

# Change to terraform directory
cd "$TF_DIR"

# Check 1: Terraform format
log_info "Check 1: Terraform formatting"
if terraform fmt -check -recursive .; then
  log_success "Terraform files are properly formatted"
else
  log_error "Terraform files need formatting"
  log_info "Run: terraform fmt -recursive"
  exit 1
fi
echo ""

# Check 2: Terraform validate
log_info "Check 2: Terraform validation"

# Always re-initialize to ensure provider checksums match the lock file.
# Skipping init when .terraform exists can cause stale cache mismatches.
log_info "Initializing Terraform (backend=false)..."
terraform init -backend=false -reconfigure

if terraform validate; then
  log_success "Terraform configuration is valid"
else
  log_error "Terraform validation failed"
  exit 1
fi
echo ""

log_success "All Terraform validation checks passed"
exit 0
