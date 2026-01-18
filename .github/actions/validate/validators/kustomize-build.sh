#!/usr/bin/env bash
# =============================================================================
# Kustomize Build Validator
# =============================================================================
# Validates that kustomize overlays and bases build successfully
# Replaces: kustomize-validate action

set -uo pipefail

# Configuration
OVERLAY_PATHS_STR="${OVERLAY_PATHS:-}"
BASE_PATHS_STR="${BASE_PATHS:-}"

# Colors
BLUE='\033[0;34m'
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BLUE}ℹ️  Kustomize Build Validator${NC}"
echo ""

# Check if kustomize is available
if ! command -v kustomize &>/dev/null; then
  echo -e "${RED}❌ kustomize is required for kustomize validation${NC}"
  exit 1
fi

# Collect all paths into a temp file
PATHS_FILE="/tmp/kustomize_paths.txt"
: > "$PATHS_FILE"

if [[ -n "$OVERLAY_PATHS_STR" ]]; then
  echo "$OVERLAY_PATHS_STR" | tr ',' '\n' >> "$PATHS_FILE"
fi
if [[ -n "$BASE_PATHS_STR" ]]; then
  echo "$BASE_PATHS_STR" | tr ',' '\n' >> "$PATHS_FILE"
fi

PATH_COUNT=$(wc -l < "$PATHS_FILE" | awk '{print $1}')

if [[ $PATH_COUNT -eq 0 ]]; then
  rm -f "$PATHS_FILE"
  echo -e "${RED}❌ No overlay or base paths specified${NC}"
  echo -e "${BLUE}ℹ️  Set OVERLAY_PATHS or BASE_PATHS environment variables${NC}"
  exit 1
fi

echo -e "${BLUE}ℹ️  Paths to validate: $PATH_COUNT${NC}"
cat "$PATHS_FILE" | sed 's/^/  - /'
echo ""

# Validate paths using while read
FAILED_COUNT=0
PASSED_COUNT=0

while read -r path; do
  # Skip empty lines
  [[ -z "$path" ]] && continue

  echo -e "${BLUE}ℹ️  Validating: $path${NC}"

  # Check directory exists
  if [[ ! -d "$path" ]]; then
    echo -e "${RED}❌ Directory not found: $path${NC}"
    ((FAILED_COUNT++))
    echo ""
    continue
  fi

  # Check kustomization file exists
  if [[ ! -f "$path/kustomization.yaml" ]] && [[ ! -f "$path/kustomization.yml" ]]; then
    echo -e "${RED}❌ No kustomization.yaml found in: $path${NC}"
    ((FAILED_COUNT++))
    echo ""
    continue
  fi

   # Build with kustomize
   OUTPUT_FILE="/tmp/kustomize_output_$$.log"
   if kustomize build "$path" > "$OUTPUT_FILE" 2>&1; then
     ((PASSED_COUNT++))
     echo -e "${GREEN}  ✓ Build successful${NC}"
   else
     echo -e "${RED}❌ Kustomize build failed${NC}"
     echo "  Error details:"
     head -5 "$OUTPUT_FILE" | sed 's/^/    /'
     ((FAILED_COUNT++))
   fi
   rm -f "$OUTPUT_FILE"

  echo ""
done < "$PATHS_FILE"

rm -f "$PATHS_FILE"

# Summary
echo -e "${BLUE}ℹ️  Validation complete${NC}"
echo -e "${BLUE}ℹ️  Passed: $PASSED_COUNT / $PATH_COUNT path(s)${NC}"

if [[ $FAILED_COUNT -gt 0 ]]; then
  echo -e "${RED}❌ Failed: $FAILED_COUNT path(s)${NC}"
  exit 1
fi

echo -e "${GREEN}✅ All kustomize builds successful${NC}"
exit 0
