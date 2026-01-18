#!/usr/bin/env bash
# =============================================================================
# Kustomize Build Validator
# =============================================================================
# Validates that kustomize overlays and bases build successfully
# Replaces: kustomize-validate action

set -euo pipefail

# Load common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$SCRIPT_DIR/common.sh"

# Configuration
OVERLAY_PATHS_STR="${OVERLAY_PATHS:-}"
BASE_PATHS_STR="${BASE_PATHS:-}"

log_info "Kustomize Build Validator"
echo ""

# Check if kustomize is available (kubectl kustomize or kustomize command)
if ! command_exists kubectl; then
  log_error "kubectl is required for kustomize validation"
  exit 1
fi

# Parse paths
ALL_PATHS=()
if [[ -n "$OVERLAY_PATHS_STR" ]]; then
  IFS=',' read -ra OVERLAY_PATHS <<< "$OVERLAY_PATHS_STR"
  ALL_PATHS+=("${OVERLAY_PATHS[@]}")
fi
if [[ -n "$BASE_PATHS_STR" ]]; then
  IFS=',' read -ra BASE_PATHS <<< "$BASE_PATHS_STR"
  ALL_PATHS+=("${BASE_PATHS[@]}")
fi

if [[ ${#ALL_PATHS[@]} -eq 0 ]]; then
  log_error "No overlay or base paths specified"
  log_info "Set OVERLAY_PATHS or BASE_PATHS environment variables"
  exit 1
fi

log_info "Paths to validate: ${#ALL_PATHS[@]}"
for path in "${ALL_PATHS[@]}"; do
  echo "  - $path"
done
echo ""

# Validate each path
FAILED_PATHS=()
PASSED_COUNT=0

for path in "${ALL_PATHS[@]}"; do
  # Skip empty paths
  [[ -z "$path" ]] && continue

  log_info "Validating: $path"

  # Check directory exists
  if [[ ! -d "$path" ]]; then
    log_error "Directory not found: $path"
    FAILED_PATHS+=("$path (not found)")
    echo ""
    continue
  fi

  # Check kustomization file exists
  if [[ ! -f "$path/kustomization.yaml" ]] && [[ ! -f "$path/kustomization.yml" ]]; then
    log_error "No kustomization.yaml found in: $path"
    FAILED_PATHS+=("$path (no kustomization)")
    echo ""
    continue
  fi

  # Build with kustomize
  log_verbose "  Running: kubectl kustomize $path"
  if OUTPUT=$(kubectl kustomize "$path" 2>&1); then
    # Validate the output can be parsed by kubectl
    log_verbose "  Validating generated manifests..."
    if echo "$OUTPUT" | kubectl apply --dry-run=client --validate=true -f - &>/dev/null; then
      ((PASSED_COUNT++))
      log_success "  ✓ Build successful and manifests valid"
    else
      FAILED_PATHS+=("$path (invalid manifests)")
      log_error "  ✗ Build succeeded but manifests are invalid"
      echo "  Validation error:"
      echo "$OUTPUT" | kubectl apply --dry-run=client --validate=true -f - 2>&1 | sed 's/^/    /'
    fi
  else
    FAILED_PATHS+=("$path (build failed)")
    log_error "  ✗ Kustomize build failed"
    echo "  Error details:"
    echo "$OUTPUT" | sed 's/^/    /'
  fi

  echo ""
done

# Summary
log_info "Validation complete"
log_info "Passed: $PASSED_COUNT / ${#ALL_PATHS[@]} path(s)"

if [[ ${#FAILED_PATHS[@]} -gt 0 ]]; then
  log_error "Failed: ${#FAILED_PATHS[@]} path(s)"
  log_error "Paths with errors:"
  for path in "${FAILED_PATHS[@]}"; do
    echo "  - $path"
  done
  exit 1
fi

log_success "All kustomize builds successful"
exit 0
