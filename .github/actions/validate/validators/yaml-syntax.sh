#!/usr/bin/env bash
# =============================================================================
# YAML Syntax Validator
# =============================================================================
# Validates YAML syntax for all K8s manifests in the specified directory
# Replaces: validate-k8s-yaml action

set -uo pipefail

# Configuration
K8S_DIR="${K8S_DIRECTORY:-k8s}"
VERBOSE="${VERBOSE:-false}"

# Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}ℹ️  YAML Syntax Validator${NC}"
echo -e "${BLUE}ℹ️  Directory: $K8S_DIR${NC}"
echo ""

# Validate directory exists
if [[ ! -d "$K8S_DIR" ]]; then
  echo -e "${RED}❌ K8s directory not found: $K8S_DIR${NC}"
  exit 1
fi

# Find all YAML files
echo -e "${BLUE}ℹ️  Finding YAML files in $K8S_DIR...${NC}"
FILE_COUNT=$(find "$K8S_DIR" -type f \( -name "*.yaml" -o -name "*.yml" \) 2>/dev/null | wc -l)

if [[ $FILE_COUNT -eq 0 ]]; then
  echo -e "${BLUE}ℹ️  No YAML files found in $K8S_DIR${NC}"
  exit 0
fi

echo -e "${BLUE}ℹ️  Found $FILE_COUNT YAML file(s)${NC}"
echo ""

# Validate all files
find "$K8S_DIR" -type f \( -name "*.yaml" -o -name "*.yml" \) 2>/dev/null | sort | while read -r file; do
  # Check if file is empty
  if [[ ! -s "$file" ]]; then
    if [[ "$VERBOSE" == "true" ]]; then
      echo -e "${BLUE}ℹ️  Skipping empty file: $file${NC}"
    fi
    continue
  fi

  # Validate with Python YAML parser (handles BOM and line endings)
  if python -c "
import yaml
try:
  with open('$file', encoding='utf-8-sig') as f:
    list(yaml.safe_load_all(f))
except Exception as e:
  import sys
  sys.exit(1)
" 2>/dev/null; then
    if [[ "$VERBOSE" == "true" ]]; then
      echo -e "${GREEN}  ✓ $file${NC}"
    fi
  else
    echo -e "${RED}❌ Invalid YAML syntax: $file${NC}"
    echo "  Error details:"
    python -c "import yaml; list(yaml.safe_load_all(open('$file', encoding='utf-8-sig')))" 2>&1 | head -3 | sed 's/^/    /'
    echo ""
  fi
done

# Check final result
echo ""
echo -e "${BLUE}ℹ️  Validation complete${NC}"

# Count failures
FAILURES=$(find "$K8S_DIR" -type f \( -name "*.yaml" -o -name "*.yml" \) 2>/dev/null | while read -r file; do
  if [[ -s "$file" ]]; then
    if ! python -c "
import yaml, sys
try:
  with open('$file', encoding='utf-8-sig') as f:
    list(yaml.safe_load_all(f))
except:
  sys.exit(1)
" 2>/dev/null; then
      echo "FAIL"
    fi
  fi
done | wc -l)

if [[ $FAILURES -gt 0 ]]; then
  echo -e "${RED}❌ Failed: $FAILURES file(s)${NC}"
  exit 1
fi

echo -e "${GREEN}✅ All YAML files have valid syntax${NC}"
exit 0
