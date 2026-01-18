#!/usr/bin/env bash
# =============================================================================
# Argo CD Paths Validator
# =============================================================================
# Validates that Argo CD Application CRDs reference valid paths
# Replaces: validate-argocd-paths action

set -uo pipefail

# Load common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$SCRIPT_DIR/common.sh"

log_info "Argo CD Paths Validator"
echo ""

# Find all Argo CD Application and ApplicationSet manifests
log_info "Finding Argo CD Application manifests..."
ARGOCD_FILES=$(find k8s/argocd -type f \( -name "*.yaml" -o -name "*.yml" \) 2>/dev/null || true)

if [[ -z "$ARGOCD_FILES" ]]; then
  log_warning "No Argo CD manifests found in k8s/argocd"
  exit 0
fi

FILE_COUNT=$(echo "$ARGOCD_FILES" | wc -l)
log_info "Found $FILE_COUNT Argo CD manifest(s)"
echo ""

# Extract paths from Applications and validate they exist
FAILED_VALIDATIONS=()
PASSED_COUNT=0

while IFS= read -r file; do
  log_info "Checking: $file"

  # Extract spec.source.path from YAML (handles both Application and ApplicationSet templates)
  PATHS=$(grep -E '^\s+path:' "$file" | sed 's/.*path: *//' | sed 's/"//g' || true)

  if [[ -z "$PATHS" ]]; then
    log_verbose "  No paths found in manifest (may be fine for ApplicationSets using generators)"
    ((PASSED_COUNT++))
    echo ""
    continue
  fi

  # Validate each path
  PATH_VALID=true
  while IFS= read -r path; do
    # Skip empty paths
    [[ -z "$path" ]] && continue

    log_verbose "  Path: $path"

    # Check if directory exists
    if [[ ! -d "$path" ]]; then
      log_error "  ✗ Path does not exist: $path"
      FAILED_VALIDATIONS+=("$file → $path (not found)")
      PATH_VALID=false
    else
      # Check if kustomization exists
      if [[ -f "$path/kustomization.yaml" ]] || [[ -f "$path/kustomization.yml" ]]; then
        log_verbose "  ✓ Path exists with kustomization"
      else
        log_warning "  ⚠ Path exists but no kustomization.yaml found"
      fi
    fi
  done <<< "$PATHS"

  if [[ "$PATH_VALID" == "true" ]]; then
    ((PASSED_COUNT++))
    log_success "  ✓ All paths valid"
  fi

  echo ""
done <<< "$ARGOCD_FILES"

# Summary
log_info "Validation complete"
log_info "Passed: $PASSED_COUNT / $FILE_COUNT file(s)"

if [[ ${#FAILED_VALIDATIONS[@]} -gt 0 ]]; then
  log_error "Failed: ${#FAILED_VALIDATIONS[@]} validation(s)"
  log_error "Invalid paths:"
  for validation in "${FAILED_VALIDATIONS[@]}"; do
    echo "  - $validation"
  done
  exit 1
fi

log_success "All Argo CD Application paths are valid"
exit 0
