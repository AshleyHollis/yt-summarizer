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

service="${SERVICE:-}"
image_tag="${IMAGE_TAG:-}"
push_flag="${PUSH_FLAG:-true}"

if [[ -z "$service" ]] || [[ -z "$image_tag" ]]; then
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
    echo "::error::Unknown service: $service"
    exit 1
    ;;
esac

echo "Building $service image..."
echo "::group::Build $service image"

# Build command
build_cmd="docker buildx build --file \"$dockerfile\""

if [ "$push_flag" = "true" ]; then
  if [[ -z "${ACR_LOGIN_SERVER:-}" ]]; then
    echo "::error::ACR_LOGIN_SERVER is required for pushing"
    exit 1
  fi

  build_cmd="$build_cmd --tag \"$ACR_LOGIN_SERVER/$image_name:$image_tag\""
  build_cmd="$build_cmd --cache-from \"type=registry,ref=$ACR_LOGIN_SERVER/$image_name:cache-$service\""
  # build_cmd="$build_cmd --cache-to \"type=registry,ref=$ACR_LOGIN_SERVER/$image_name:cache-$service,mode=max\""
  build_cmd="$build_cmd --push"
  echo "Pushing to registry: $ACR_LOGIN_SERVER/$image_name:$image_tag"
else
  # For validation, just build without pushing
  build_cmd="$build_cmd --tag \"local/$image_name:validate\""
  echo "Validation build (not pushing to registry)"
fi

eval "$build_cmd ."
echo "::endgroup::"
