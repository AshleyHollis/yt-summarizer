#!/bin/bash
# =============================================================================
# Git Operations Utilities
# =============================================================================
# Purpose:
#   Provides reusable functions for common git operations used in CI/CD
#   workflows, including SHA extraction, file change detection, and repo
#   state validation.
#
# Functions:
#   - get_short_sha(sha)              Get 7-character commit SHA
#   - get_commit_message(sha)         Get commit message/title
#   - git_diff_exists(directory)      Check if files changed in directory
#   - git_diff_files(directory)       Get list of changed files in directory
#   - git_log_summary(count)          Get commit summary for recent commits
#   - validate_git_state()            Check repo is clean (no uncommitted)
#   - get_current_branch()            Get current branch name
#   - is_main_branch(branch)          Check if branch is main
#
# Usage:
#   source ./lib/git-utils.sh
#   short_sha=$(get_short_sha "$GITHUB_SHA")
#   if git_diff_exists "services/api"; then
#     echo "API code changed"
#   fi
#
# Dependencies:
#   - git: Must be available in PATH
#
# Exit codes:
#   Functions return 0 for true/success, 1 for false/failure
#
# =============================================================================

# Get short SHA (7 characters) of a commit
# Args:
#   $1: Commit SHA (optional, defaults to HEAD)
# Returns: 7-character SHA on stdout
# Example: short_sha=$(get_short_sha "abc123def456")
get_short_sha() {
  local sha="${1:-.}"

  if ! git rev-parse --short=7 "$sha" 2>/dev/null; then
    echo "::error::Failed to get short SHA for: $sha"
    return 1
  fi

  return 0
}

# Get commit message (first line/title) of a commit
# Args:
#   $1: Commit SHA (optional, defaults to HEAD)
# Returns: Commit message on stdout
# Example: msg=$(get_commit_message "$GITHUB_SHA")
get_commit_message() {
  local sha="${1:-HEAD}"

  if ! git log -1 --format='%s' "$sha" 2>/dev/null; then
    echo "::error::Failed to get message for: $sha"
    return 1
  fi

  return 0
}

# Check if files changed in a specific directory
# Args:
#   $1: Directory path to check (required)
#   $2: Base ref for comparison (optional, defaults to origin/main)
# Returns: 0 if files changed, 1 if not
# Example: if git_diff_exists "services/api"; then echo "API changed"; fi
git_diff_exists() {
  local directory="${1:-}"
  local base_ref="${2:-origin/main}"

  if [ -z "$directory" ]; then
    echo "::error::git_diff_exists requires directory argument"
    return 1
  fi

  # Check if there are any differences in the directory
  if git diff --quiet "$base_ref...HEAD" -- "$directory" 2>/dev/null; then
    return 1  # No changes
  fi

  return 0  # Changes detected
}

# Get list of changed files in a specific directory
# Args:
#   $1: Directory path to check (required)
#   $2: Base ref for comparison (optional, defaults to origin/main)
# Returns: Changed files (one per line) on stdout
# Example: files=$(git_diff_files "services/api")
git_diff_files() {
  local directory="${1:-}"
  local base_ref="${2:-origin/main}"

  if [ -z "$directory" ]; then
    echo "::error::git_diff_files requires directory argument"
    return 1
  fi

  git diff --name-only "$base_ref...HEAD" -- "$directory" 2>/dev/null || return 1
}

# Get log summary for recent commits
# Args:
#   $1: Number of commits to show (optional, defaults to 10)
# Returns: Log output on stdout
# Example: summary=$(git_log_summary 5)
git_log_summary() {
  local count="${1:-10}"

  if ! git log -n "$count" --oneline 2>/dev/null; then
    echo "::error::Failed to get git log"
    return 1
  fi

  return 0
}

# Validate that git repo is in clean state (no uncommitted changes)
# Args: None
# Returns: 0 if clean, 1 if dirty
# Example: if ! validate_git_state; then echo "Repo has uncommitted changes"; fi
validate_git_state() {
  if ! git diff-index --quiet HEAD -- 2>/dev/null; then
    echo "::warning::Repository has uncommitted changes:"
    git status --short
    return 1
  fi

  return 0
}

# Get current branch name
# Args: None
# Returns: Branch name on stdout
# Example: branch=$(get_current_branch)
get_current_branch() {
  git rev-parse --abbrev-ref HEAD 2>/dev/null || {
    echo "::error::Failed to get current branch"
    return 1
  }
}

# Check if a branch name is main/master
# Args:
#   $1: Branch name (required)
# Returns: 0 if main/master, 1 otherwise
# Example: if is_main_branch "main"; then echo "On main"; fi
is_main_branch() {
  local branch="${1:-}"

  if [ -z "$branch" ]; then
    echo "::error::is_main_branch requires branch argument"
    return 1
  fi

  if [[ "$branch" == "main" ]] || [[ "$branch" == "master" ]]; then
    return 0
  fi

  return 1
}
