#!/usr/bin/env bash
# =============================================================================
# YAML Syntax Validator
# =============================================================================
# Validates YAML syntax for all K8s manifests in the specified directory
# Replaces: validate-k8s-yaml action

set -euo pipefail

# Load common utilities
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=./common.sh
source "$SCRIPT_DIR/common.sh"

# Configuration
K8S_DIR="${K8S_DIRECTORY:-k8s}"

log_info "YAML Syntax Validator"
log_info "Directory: $K8S_DIR"
echo ""

# Validate directory exists
if ! require_directory "$K8S_DIR"; then
  log_error "K8s directory not found: $K8S_DIR"
  exit 1
fi

# Find all YAML files
log_info "Finding YAML files in $K8S_DIR..."
YAML_FILES=$(find "$K8S_DIR" -type f \( -name "*.yaml" -o -name "*.yml" \) 2>/dev/null || true)

if [[ -z "$YAML_FILES" ]]; then
  log_warning "No YAML files found in $K8S_DIR"
  exit 0
fi

FILE_COUNT=$(echo "$YAML_FILES" | wc -l)
log_info "Found $FILE_COUNT YAML file(s)"
echo ""

# Validate each file
FAILED_FILES=()
PASSED_COUNT=0

while IFS= read -r file; do
  log_verbose "Validating: $file"

  # Check if file is empty
  if [[ ! -s "$file" ]]; then
    log_warning "Skipping empty file: $file"
    continue
  fi

  # Validate with Python YAML parser (works without live cluster)
  if python3 -c "import yaml; yaml.safe_load(open('$file', 'r'))" &>/dev/null; then
    ((PASSED_COUNT++))
    log_verbose "  ✓ Valid"
  else
    FAILED_FILES+=("$file")
    log_error "Invalid YAML syntax: $file"

    # Show detailed error
    echo "  Error details:"
    python3 -c "import yaml; yaml.safe_load(open('$file', 'r'))" 2>&1 | sed 's/^/    /'
    echo ""
  fi
done <<< "$YAML_FILES"

# Summary
echo ""
log_info "Validation complete"
log_info "Passed: $PASSED_COUNT / $FILE_COUNT files"

if [[ ${#FAILED_FILES[@]} -gt 0 ]]; then
  log_error "Failed: ${#FAILED_FILES[@]} file(s)"
  log_error "Files with errors:"
  for file in "${FAILED_FILES[@]}"; do
    echo "  - $file"
  done
  exit 1
fi

log_success "All YAML files have valid syntax"
exit 0
