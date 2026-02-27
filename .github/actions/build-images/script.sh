#!/bin/bash

################################################################################
# Action: build-images / script.sh
#
# Purpose: Build and push Docker images for services (api, workers) to ACR.
#          Supports both pushing to registry and validation-only builds.
#
# Inputs (Environment Variables):
#   SERVICE           - The service to build (api, workers)
#   IMAGE_TAG         - The image tag to use
#   PUSH_FLAG         - Whether to push images to registry (default: true)
#   ACR_LOGIN_SERVER  - Azure Container Registry login server (required if PUSH_FLAG=true)
#
# Process:
#   1. Determine Dockerfile and image name based on service type
#   2. Configure build command with appropriate flags
#   3. If pushing: use registry cache, tag with ACR prefix, push to registry
#   4. If validation-only: build locally with temporary tag
#   5. Report build status
#
# Docker Build Flags:
#   --cache-from      - Use registry cache to speed up builds
#   --push            - Push image to registry after build (when PUSH_FLAG=true)
#   --tag             - Tag the image
#
################################################################################

set -euo pipefail

# Logging helpers
print_header() {
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "[INFO] 🚀 $1"
  shift
  for line in "$@"; do
    echo "[INFO]    $line"
  done
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo ""
}

print_footer() {
  echo ""
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
  echo "[INFO] $1"
  echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
}

log_info() { echo "[INFO] $1"; }
log_warn() { echo "[WARN] ⚠️  $1"; }
log_error() { echo "[ERROR] ✗ $1"; }
log_success() { echo "[INFO]    ✓ $1"; }
log_step() { echo "[INFO] $1"; }

service="${SERVICE:-}"
image_tag="${IMAGE_TAG:-}"
push_flag="${PUSH_FLAG:-true}"

if [[ -z "$service" ]] || [[ -z "$image_tag" ]]; then
  log_error "SERVICE and IMAGE_TAG are required"
  echo "::error::SERVICE and IMAGE_TAG are required"
  exit 1
fi

case $service in
  api)
    dockerfile="services/api/Dockerfile"
    image_name="yt-summarizer-api"
    ;;
  workers)
    dockerfile="services/workers/Dockerfile"
    image_name="yt-summarizer-workers"
    ;;
  *)
    log_error "Unknown service: $service"
    echo "::error::Unknown service: $service"
    exit 1
    ;;
esac

if [ "$push_flag" = "true" ]; then
  if [[ -z "${ACR_LOGIN_SERVER:-}" ]]; then
    log_error "ACR_LOGIN_SERVER is required for pushing"
    echo "::error::ACR_LOGIN_SERVER is required for pushing"
    exit 1
  fi
  full_image="$ACR_LOGIN_SERVER/$image_name:$image_tag"
  print_header "Build & Push Docker Image" \
    "Service: $service" \
    "Image: $full_image" \
    "Dockerfile: $dockerfile"
else
  full_image="local/$image_name:validate"
  print_header "Build Docker Image (Validation)" \
    "Service: $service" \
    "Image: $full_image" \
    "Dockerfile: $dockerfile"
fi

# Build command
build_cmd="docker buildx build --file \"$dockerfile\""

if [ "$push_flag" = "true" ]; then
  build_cmd="$build_cmd --tag \"$ACR_LOGIN_SERVER/$image_name:$image_tag\""
  build_cmd="$build_cmd --cache-from \"type=registry,ref=$ACR_LOGIN_SERVER/$image_name:cache-$service\""
  build_cmd="$build_cmd --cache-to \"type=registry,ref=$ACR_LOGIN_SERVER/$image_name:cache-$service,mode=max\""
  build_cmd="$build_cmd --push"
  log_step "⏳ Building and pushing to registry..."
else
  build_cmd="$build_cmd --tag \"local/$image_name:validate\""
  log_step "⏳ Building locally for validation..."
fi

if eval "$build_cmd ."; then
  log_success "Build completed"
  if [ "$push_flag" = "true" ]; then
    print_footer "✅ Image pushed: $full_image"
  else
    print_footer "✅ Validation build successful"
  fi
else
  log_error "Build failed"
  print_footer "❌ Build failed"
  exit 1
fi
