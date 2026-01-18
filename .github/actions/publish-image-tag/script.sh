#!/bin/bash
# =============================================================================
# Publish Image Tag
# =============================================================================
# PURPOSE:
#   Write the provided image tag to a file and upload it as an artifact
#
# INPUTS (via environment variables):
#   IMAGE_TAG           Image tag to publish
#
# OUTPUTS:
#   image-tag.txt file for artifact upload
#
# LOGIC:
#   1. Write image tag to image-tag.txt file
#   2. Display the tag for verification
#   Note: artifact upload handled by separate step using upload-artifact action
#
# =============================================================================
set -euo pipefail

echo "${IMAGE_TAG}" > image-tag.txt
echo "Wrote image tag to image-tag.txt"
cat image-tag.txt
