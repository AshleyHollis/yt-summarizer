#!/bin/bash
# =============================================================================
# Image Tag Resolution and Management Utilities
# =============================================================================
# Purpose:
#   Provides reusable functions for managing container image tags in CI/CD
#   workflows. Consolidates logic from prod-extract-ci-image-tag.sh,
#   prod-find-last-image.sh, and prod-determine-image-tag.sh.
#
# Functions:
#   - generate_image_tag(sha)         Create sha-{short_sha} tag format
#   - extract_tag_from_kustomize()   Read tag from kustomization.yaml
#   - validate_image_tag(tag)        Verify tag format/validity
#   - get_ci_image_tag(sha)          Get CI-built tag for commit
#   - get_last_prod_image()          Get existing production image tag
#   - determine_image_tag(ci_result, prod_result, ci_tag, prod_tag)
#                                    Select which tag to deploy
#
# Usage:
#   source ./lib/image-utils.sh
#   tag=$(generate_image_tag "$GITHUB_SHA")
#   existing_tag=$(extract_tag_from_kustomize)
#   final_tag=$(determine_image_tag "$ci_status" "$prod_status" "$ci_tag" "$prod_tag")
#
# Dependencies:
#   - git: For SHA extraction
#   - grep: For kustomization parsing
#   - github-utils.sh: For output_var() function
#
# Exit codes:
#   Functions return 0 for success, 1 for failure
#
# =============================================================================

# Generate deterministic image tag from commit SHA
# Args:
#   $1: Commit SHA (required, e.g., github.sha)
# Returns: Image tag on stdout (format: sha-{short_sha})
# Example: tag=$(generate_image_tag "$GITHUB_SHA")
generate_image_tag() {
  local commit_sha="${1:-}"

  if [ -z "$commit_sha" ]; then
    echo "::error::generate_image_tag requires commit SHA argument"
    return 1
  fi

  local short_sha
  short_sha=$(git rev-parse --short=7 "$commit_sha" 2>/dev/null) || {
    echo "::error::Failed to extract short SHA from: $commit_sha"
    return 1
  }

  local image_tag="sha-${short_sha}"
  echo "$image_tag"
  return 0
}

# Extract image tag from kustomization.yaml
# Args:
#   $1: Path to kustomization.yaml (optional, defaults to k8s/overlays/prod)
# Returns: Image tag on stdout
# Example: tag=$(extract_tag_from_kustomize "k8s/overlays/prod/kustomization.yaml")
extract_tag_from_kustomize() {
  local kustomize_path="${1:-k8s/overlays/prod/kustomization.yaml}"

  if [ ! -f "$kustomize_path" ]; then
    echo "::error::Kustomization file not found: $kustomize_path"
    return 1
  fi

  local image_tag
  image_tag=$(grep -oP 'newTag: \K.*' "$kustomize_path" | head -1)

  if [ -z "$image_tag" ]; then
    echo "::error::Could not find image tag in: $kustomize_path"
    return 1
  fi

  echo "$image_tag"
  return 0
}

# Validate image tag format
# Args:
#   $1: Image tag to validate (required)
# Returns: 0 if valid, 1 if invalid
# Example: if validate_image_tag "$tag"; then echo "Valid tag"; fi
validate_image_tag() {
  local tag="${1:-}"

  if [ -z "$tag" ]; then
    echo "::error::validate_image_tag requires tag argument"
    return 1
  fi

  # Warn if using 'latest' (non-deterministic)
  if [ "$tag" = "latest" ]; then
    echo "::warning::Image tag is 'latest' (non-deterministic)"
    echo "::warning::Consider using SHA-based tags (e.g., sha-abc1234)"
    return 0  # Still valid, but warn
  fi

  # Check format: should match sha-{7chars} or semantic version pattern
  if [[ "$tag" =~ ^sha-[a-f0-9]{7}$ ]] || [[ "$tag" =~ ^v?[0-9]+\.[0-9]+\.[0-9]+ ]]; then
    return 0
  fi

  # If not matching expected patterns, warn but don't fail
  echo "::warning::Image tag doesn't match expected patterns: $tag"
  return 0
}

# Get CI-built image tag for a commit
# This consolidates logic from prod-extract-ci-image-tag.sh
# Args:
#   $1: Commit SHA (optional, defaults to git HEAD)
# Returns: 0 on success, 1 on failure
# Outputs: Sets GITHUB_OUTPUT (if running in Actions)
# Example: get_ci_image_tag "$GITHUB_SHA"
get_ci_image_tag() {
  local commit_sha="${1:-.}"

  # Generate the image tag
  local image_tag
  image_tag=$(generate_image_tag "$commit_sha") || return 1

  # Validate it
  if ! validate_image_tag "$image_tag"; then
    return 1
  fi

  # Output for GitHub Actions
  if command -v output_var &>/dev/null; then
    output_var "image_tag" "$image_tag"
  else
    echo "image_tag=$image_tag"
  fi

  echo "✅ Using CI-built image tag: $image_tag"
  return 0
}

# Get existing production image tag from kustomization
# This consolidates logic from prod-find-last-image.sh
# Args:
#   $1: Path to kustomization (optional)
# Returns: 0 on success, 1 on failure
# Outputs: Sets GITHUB_OUTPUT (if running in Actions)
# Example: get_last_prod_image "k8s/overlays/prod/kustomization.yaml"
get_last_prod_image() {
  local kustomize_path="${1:-k8s/overlays/prod/kustomization.yaml}"

  echo "📋 Reading current production image tag from kustomization..."

  # Extract the tag
  local image_tag
  image_tag=$(extract_tag_from_kustomize "$kustomize_path") || return 1

  # Validate it
  if ! validate_image_tag "$image_tag"; then
    return 1
  fi

  # Output for GitHub Actions
  if command -v output_var &>/dev/null; then
    output_var "image_tag" "$image_tag"
  else
    echo "image_tag=$image_tag"
  fi

  echo "✅ Using existing production image tag: $image_tag"
  return 0
}

# Determine which image tag to deploy based on what changed
# This consolidates logic from prod-determine-image-tag.sh
# Args:
#   $1: CI job result ('success'/'failure') - indicates code changes path
#   $2: Prod job result ('success'/'failure') - indicates infra-only path
#   $3: CI image tag (e.g., sha-abc1234)
#   $4: Prod image tag (existing deployed tag)
# Returns: 0 on success, 1 on failure
# Outputs: Sets GITHUB_OUTPUT with image_tag and deployment_type
# Example: determine_image_tag "success" "failure" "sha-abc1234" "sha-xyz9999"
determine_image_tag() {
  local ci_result="${1:-}"
  local prod_result="${2:-}"
  local ci_image_tag="${3:-}"
  local prod_image_tag="${4:-}"

  if [ -z "$ci_result" ] || [ -z "$prod_result" ]; then
    echo "::error::determine_image_tag requires ci_result and prod_result"
    return 1
  fi

  # Path 1: Code changes (CI job succeeded - use CI-built image)
  if [ "$ci_result" = "success" ]; then
    if [ -z "$ci_image_tag" ]; then
      echo "::error::CI result is success but no CI image tag provided"
      return 1
    fi

    local image_tag="$ci_image_tag"
    local deployment_type="ci-build"
    echo "📦 Using CI-built image: $image_tag"

    if command -v output_var &>/dev/null; then
      output_var "image_tag" "$image_tag"
      output_var "deployment_type" "$deployment_type"
    else
      echo "image_tag=$image_tag"
      echo "deployment_type=$deployment_type"
    fi

    return 0

  # Path 2: K8s/infra only (Prod job succeeded - reuse existing prod image)
  elif [ "$prod_result" = "success" ]; then
    if [ -z "$prod_image_tag" ]; then
      echo "::error::Prod result is success but no prod image tag provided"
      return 1
    fi

    local image_tag="$prod_image_tag"
    local deployment_type="existing-image"
    echo "📦 Using existing production image: $image_tag"
    echo "ℹ️  Deploying K8s/infra changes only (no code changes)"

    if command -v output_var &>/dev/null; then
      output_var "image_tag" "$image_tag"
      output_var "deployment_type" "$deployment_type"
    else
      echo "image_tag=$image_tag"
      echo "deployment_type=$deployment_type"
    fi

    return 0

  else
    echo "::error::Neither CI nor Prod job succeeded"
    echo "::error::Cannot determine which image tag to deploy"
    return 1
  fi
}
