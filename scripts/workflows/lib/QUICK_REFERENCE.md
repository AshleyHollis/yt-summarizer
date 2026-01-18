#!/bin/bash
# =============================================================================
# Quick Reference: Shared Utilities Library
# =============================================================================
# This file shows how to use the utilities library in your scripts
# Location: scripts/workflows/lib/
#
# Usage Pattern:
#   source ./lib/utility-name.sh
#   function_name arguments...
# =============================================================================

# =============================================================================
# GITHUB ACTIONS UTILITIES
# =============================================================================
# File: scripts/workflows/lib/github-utils.sh

# Example 1: Output a variable to GitHub Actions
source ./lib/github-utils.sh
output_var "my_var" "my_value"       # Sets my_var=my_value in $GITHUB_OUTPUT

# Example 2: Error handling
error "Something went wrong"          # Outputs ::error:: and exits with 1

# Example 3: Warning messages
warning "This is not critical"        # Outputs ::warning:: (non-fatal)

# Example 4: Create workflow group
group_start "Building images"
  echo "Building..."
group_end

# Example 5: Append to workflow summary
append_step_summary "## Summary\n- Item 1\n- Item 2"

# =============================================================================
# GIT UTILITIES
# =============================================================================
# File: scripts/workflows/lib/git-utils.sh

source ./lib/git-utils.sh

# Example 1: Get short SHA
short_sha=$(get_short_sha "$GITHUB_SHA")
echo "Building tag: sha-$short_sha"

# Example 2: Check if files changed
if git_diff_exists "services/api"; then
  echo "API code changed, running tests..."
fi

# Example 3: Get list of changed files
changed_files=$(git_diff_files "apps/web")

# Example 4: Check if on main branch
if is_main_branch "main"; then
  echo "Running full validation"
fi

# =============================================================================
# IMAGE TAG UTILITIES (Consolidates 3 scripts)
# =============================================================================
# File: scripts/workflows/lib/image-utils.sh

source ./lib/image-utils.sh

# Example 1: Get CI-built image tag
# Replaces: prod-extract-ci-image-tag.sh
get_ci_image_tag "$GITHUB_SHA"
# → Outputs: image_tag=sha-abc1234

# Example 2: Get existing production image
# Replaces: prod-find-last-image.sh
get_last_prod_image "k8s/overlays/prod/kustomization.yaml"
# → Outputs: image_tag={current_tag}

# Example 3: Determine which tag to deploy
# Replaces: prod-determine-image-tag.sh
determine_image_tag \
  "success" \              # CI job result (success/failure)
  "failure" \              # Prod job result (success/failure)
  "sha-abc1234" \          # CI image tag
  "sha-xyz9999"            # Prod image tag
# → Outputs: image_tag and deployment_type

# Example 4: Standalone image tag generation
tag=$(generate_image_tag "$COMMIT_SHA")
echo "Generated tag: $tag"

# =============================================================================
# KUBERNETES UTILITIES
# =============================================================================
# File: scripts/workflows/lib/k8s-utils.sh

source ./lib/k8s-utils.sh

# Example 1: Wait for deployment to be ready
kubectl_wait_ready "deployment" "api-service" 300 "production"

# Example 2: Verify correct image deployed
kubectl_check_image "production" "api" "sha-abc1234"

# Example 3: Get deployment info
kubectl_get_deployment "production" "api"

# Example 4: Get pod logs
logs=$(kubectl_get_pod_logs "production" "api-xyz-123" "app" 100)

# =============================================================================
# HEALTH CHECK UTILITIES
# =============================================================================
# File: scripts/workflows/lib/health-utils.sh

source ./lib/health-utils.sh

# Example 1: Single health check
if http_health_check "https://api.example.com/health" 5; then
  echo "Service is healthy"
fi

# Example 2: Wait for service to be healthy (with retries)
if wait_for_health "https://api.example.com/health" 60 10; then
  echo "Service is ready!"
else
  echo "Service failed to become healthy"
  exit 1
fi

# Example 3: Check DNS resolution
check_dns_resolution "api.example.com"

# Example 4: Verify TLS certificate
check_tls_certificate "api.example.com" 443 30

# Example 5: Comprehensive readiness check
check_service_ready "https://api.example.com"

# =============================================================================
# COMMON PATTERNS
# =============================================================================

# Pattern 1: Source utilities at start of script
#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/lib/image-utils.sh"
source "$SCRIPT_DIR/lib/github-utils.sh"

# Pattern 2: Use utilities in workflow
get_ci_image_tag "$GITHUB_SHA" || error "Failed to get image tag"

# Pattern 3: Combine utilities
source ./lib/github-utils.sh
source ./lib/git-utils.sh
if git_diff_exists "services/api"; then
  output_var "should_build" "true"
else
  output_var "should_build" "false"
fi

# Pattern 4: Chain operations
source ./lib/image-utils.sh
source ./lib/k8s-utils.sh
tag=$(generate_image_tag "$GITHUB_SHA")
kubectl_wait_ready "deployment" "api" 300 "prod"
kubectl_check_image "prod" "api" "$tag"

# =============================================================================
# BEST PRACTICES
# =============================================================================

# ✅ DO:
# - Source utilities at the beginning of your script
# - Check return codes from utility functions
# - Use utilities instead of duplicating logic
# - Document dependencies (what utilities your script uses)

# ❌ DON'T:
# - Copy/paste logic from utilities (source them instead)
# - Ignore return codes (check them with || error "message")
# - Mix old patterns with new utilities in same script

# =============================================================================
# MIGRATION EXAMPLES
# =============================================================================

# BEFORE (old pattern):
#!/bin/bash
set -e
SHORT_SHA=$(git rev-parse --short=7 "$COMMIT_SHA")
IMAGE_TAG="sha-${SHORT_SHA}"
echo "image_tag=$IMAGE_TAG" >> "$GITHUB_OUTPUT"

# AFTER (using utilities):
#!/bin/bash
set -e
source ./lib/image-utils.sh
get_ci_image_tag "$COMMIT_SHA"

# BEFORE (old pattern):
if [ -z "$PROD_TAG" ]; then
  echo "::error::Could not find image tag"
  exit 1
fi

# AFTER (using utilities):
source ./lib/github-utils.sh
[ -z "$PROD_TAG" ] && error "Could not find image tag"

# =============================================================================
