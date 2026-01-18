#!/usr/bin/env bash
# =============================================================================
# Common Utilities for Validators
# =============================================================================
# Shared functions used by all validator scripts

set -uo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
  echo -e "${BLUE}ℹ️  $*${NC}"
}

log_success() {
  echo -e "${GREEN}✅ $*${NC}"
}

log_warning() {
  echo -e "${YELLOW}⚠️  $*${NC}"
}

log_error() {
  echo -e "${RED}❌ $*${NC}"
}

# Check if a command exists
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Require a command to be installed
require_command() {
  local cmd="$1"
  local install_hint="${2:-}"

  if ! command_exists "$cmd"; then
    log_error "Required command not found: $cmd"
    [[ -n "$install_hint" ]] && log_info "Install with: $install_hint"
    return 1
  fi
  return 0
}

# Check if environment variable is set
require_env() {
  local var_name="$1"
  local var_value="${!var_name:-}"

  if [[ -z "$var_value" ]]; then
    log_error "Required environment variable not set: $var_name"
    return 1
  fi
  return 0
}

# Check if file exists
require_file() {
  local file_path="$1"

  if [[ ! -f "$file_path" ]]; then
    log_error "Required file not found: $file_path"
    return 1
  fi
  return 0
}

# Check if directory exists
require_directory() {
  local dir_path="$1"

  if [[ ! -d "$dir_path" ]]; then
    log_error "Required directory not found: $dir_path"
    return 1
  fi
  return 0
}

# Verbose logging (only if VERBOSE=true)
log_verbose() {
  if [[ "${VERBOSE:-false}" == "true" ]]; then
    log_info "[VERBOSE] $*"
  fi
}

# Export functions for use in validators
export -f log_info log_success log_warning log_error
export -f command_exists require_command require_env require_file require_directory
export -f log_verbose
