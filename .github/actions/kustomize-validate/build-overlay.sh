#!/bin/bash

################################################################################
# Action: kustomize-validate / build-overlay.sh
#
# Purpose: Builds Kustomize overlay and outputs manifest file. Provides
#          detailed diagnostic information if build fails, including git context
#          and patch file inspection.
#
# Inputs (Environment Variables):
#   OVERLAY_DIR       - Path to kustomize overlay directory (e.g., k8s/overlays/preview)
#   OVERLAY_NAME      - Name of the overlay for error messages (e.g., preview, prod)
#   OUTPUT_FILE       - Optional output file path for built manifests
#
# Outputs:
#   Sets GitHub Actions outputs:
#     - manifest_path=<path_to_manifest>
#     - manifest_size=<size_in_bytes>
#   Writes manifest YAML to file specified by OUTPUT_FILE or temp location
#   Reports diagnostic info via echo and GitHub Actions groups
#
# Process:
#   1. Determines output file location (explicit or temp)
#   2. Displays git context (branch, last commit)
#   3. Shows overlay file structure and contents (first 50 lines)
#   4. Lists patch files if present
#   5. Executes kustomize build with error capture
#   6. On success: reports manifest size and outputs path
#   7. On failure: shows error output, inspects patch files, exits with code 1
#
# Error Handling:
#   - Uses set -eo pipefail for strict error handling
#   - Captures stderr to error file for diagnosis
#   - Continues on git command failures (diagnostic only)
#   - Inspects patch files that appear in error messages
#   - Preserves exit code on failure
#
################################################################################

set -eo pipefail

OVERLAY_DIR="${OVERLAY_DIR:?OVERLAY_DIR not set}"
OVERLAY_NAME="${OVERLAY_NAME:?OVERLAY_NAME not set}"
OUTPUT_FILE="${OUTPUT_FILE:-}"
OVERLAY_FILE="$OVERLAY_DIR/kustomization.yaml"

# Determine output file
if [ -n "$OUTPUT_FILE" ]; then
  TMP_MANIFEST="$OUTPUT_FILE"
else
  TMP_MANIFEST="/tmp/${OVERLAY_NAME}-manifest.yaml"
fi

ERR_FILE="/tmp/kustomize-${OVERLAY_NAME}.err"

echo "::group::Building $OVERLAY_NAME overlay"

# Display git context for debugging
echo "--- Git Context ---"
git rev-parse --abbrev-ref HEAD 2>&1 || true
git log -1 --oneline 2>&1 || true

# Display overlay file for debugging
echo "--- Overlay File ---"
if [ -f "$OVERLAY_FILE" ]; then
  echo "File: $OVERLAY_FILE"
  echo "Size: $(wc -c < "$OVERLAY_FILE") bytes"
  head -n 50 "$OVERLAY_FILE" || true
else
  echo "⚠️  Overlay file not found: $OVERLAY_FILE"
fi

# Display patch files
if [ -d "$OVERLAY_DIR/patches" ]; then
  echo "--- Patch Files ---"
  ls -lh "$OVERLAY_DIR/patches" || true
fi

# Build with kustomize
echo "--- Building manifests ---"
if ! kustomize build "$OVERLAY_DIR" > "$TMP_MANIFEST" 2> "$ERR_FILE"; then
  echo "::error::kustomize build FAILED for overlay '$OVERLAY_NAME'"
  echo "--- Error Output ---"
  cat "$ERR_FILE" || true

  # Try to identify problematic patch files
  if grep -q "path:" "$ERR_FILE"; then
    echo "--- Problematic Files ---"
    grep "path:" "$ERR_FILE" | while read -r line; do
      PATCH_PATH=$(echo "$line" | sed -n 's/.*path:\s*\(.*\)/\1/p')
      if [ -n "$PATCH_PATH" ]; then
        FULL_PATH="$OVERLAY_DIR/$PATCH_PATH"
        if [ -f "$FULL_PATH" ]; then
          echo "File: $FULL_PATH"
          head -n 30 "$FULL_PATH" || true
        fi
      fi
    done
  fi

  echo "::endgroup::"
  exit 1
fi

# Get manifest size
MANIFEST_SIZE=$(wc -c < "$TMP_MANIFEST")
echo "✅ Built $OVERLAY_NAME overlay: $MANIFEST_SIZE bytes"
echo "::endgroup::"

# Output for next steps
echo "manifest_path=$TMP_MANIFEST" >> $GITHUB_OUTPUT
echo "manifest_size=$MANIFEST_SIZE" >> $GITHUB_OUTPUT
