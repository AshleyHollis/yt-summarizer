#!/bin/bash
# =============================================================================
# GitHub Actions Integration Utilities
# =============================================================================
# Purpose:
#   Provides reusable functions for GitHub Actions workflows to interact with
#   the GitHub Actions environment, including output variables, error messages,
#   and workflow grouping.
#
# Functions:
#   - output_var(name, value)         Write variable to $GITHUB_OUTPUT
#   - set_output(name, value)         Alias for output_var()
#   - get_input(name)                 Read input from $GITHUB_INPUT
#   - error(message)                  Output error and exit with code 1
#   - warning(message)                Output warning message (non-fatal)
#   - group_start(name)               Start a GitHub actions ::group::
#   - group_end()                     End the current ::group::
#   - info(message)                   Output informational message
#   - set_step_summary(text)          Append to $GITHUB_STEP_SUMMARY
#   - append_step_summary(text)       Append markdown to step summary
#
# Usage:
#   source ./lib/github-utils.sh
#   output_var "image_tag" "sha-abc1234"
#   warning "This is a non-blocking warning"
#   error "This is fatal"
#
# Exit codes:
#   error() exits with 1
#   All others return 0 on success
#
# =============================================================================

# Output variable to GitHub Actions
# Args:
#   $1: Variable name (required)
#   $2: Variable value (required)
# Returns: 0 on success
# Example: output_var "image_tag" "sha-abc1234"
output_var() {
  local name="${1:-}"
  local value="${2:-}"

  if [ -z "$name" ] || [ -z "$value" ]; then
    echo "::error::output_var requires name and value arguments"
    return 1
  fi

  if [ -z "$GITHUB_OUTPUT" ]; then
    echo "::warning::GITHUB_OUTPUT not set (not in GitHub Actions?)"
    return 0
  fi

  echo "${name}=${value}" >> "$GITHUB_OUTPUT"
  return 0
}

# Alias for output_var (shorter name for convenience)
# Args:
#   $1: Variable name (required)
#   $2: Variable value (required)
# Returns: 0 on success
# Example: set_output "status" "success"
set_output() {
  output_var "$@"
}

# Get input from GitHub Actions
# Args:
#   $1: Input name (required)
# Returns: Input value (empty string if not found)
# Example: branch=$(get_input "branch")
get_input() {
  local name="${1:-}"

  if [ -z "$name" ]; then
    echo "::error::get_input requires name argument"
    return 1
  fi

  # GitHub Actions provides inputs via env vars with INPUT_ prefix
  local env_name="INPUT_${name^^}"
  echo "${!env_name:-}"
}

# Output error message and exit with code 1
# Args:
#   $1: Error message (required)
# Returns: Does not return (exits with 1)
# Example: error "Failed to build image"
error() {
  local message="${1:-Unknown error}"
  echo "::error::${message}"
  exit 1
}

# Output warning message (non-fatal)
# Args:
#   $1: Warning message (required)
# Returns: 0
# Example: warning "Image tag is 'latest' (non-deterministic)"
warning() {
  local message="${1:-}"

  if [ -z "$message" ]; then
    return 0
  fi

  echo "::warning::${message}"
}

# Output info message (plain text)
# Args:
#   $1: Info message (required)
# Returns: 0
# Example: info "Using image tag: sha-abc1234"
info() {
  local message="${1:-}"

  if [ -z "$message" ]; then
    return 0
  fi

  echo "ℹ️  ${message}"
}

# Start a GitHub Actions group (collapsible section)
# Args:
#   $1: Group title (required)
# Returns: 0
# Example: group_start "Building images"
group_start() {
  local title="${1:-}"

  if [ -z "$title" ]; then
    return 0
  fi

  echo "::group::${title}"
}

# End the current GitHub Actions group
# Returns: 0
# Example: group_end
group_end() {
  echo "::endgroup::"
}

# Set workflow step summary (overwrites existing)
# Args:
#   $1: Markdown text to write
# Returns: 0
# Example: set_step_summary "## Build Result\n- Status: ✅ Success"
set_step_summary() {
  local text="${1:-}"

  if [ -z "$GITHUB_STEP_SUMMARY" ]; then
    echo "::warning::GITHUB_STEP_SUMMARY not set (not in GitHub Actions?)"
    return 0
  fi

  echo -e "$text" > "$GITHUB_STEP_SUMMARY"
}

# Append to workflow step summary (adds to existing)
# Args:
#   $1: Markdown text to append
# Returns: 0
# Example: append_step_summary "## Additional Info\n- Details..."
append_step_summary() {
  local text="${1:-}"

  if [ -z "$text" ]; then
    return 0
  fi

  if [ -z "$GITHUB_STEP_SUMMARY" ]; then
    echo "::warning::GITHUB_STEP_SUMMARY not set (not in GitHub Actions?)"
    return 0
  fi

  echo -e "$text" >> "$GITHUB_STEP_SUMMARY"
}
