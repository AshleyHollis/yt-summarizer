#!/usr/bin/env bash
# =============================================================================
# Validate Composite Actions Usage
# =============================================================================
# Ensures that workflows properly checkout code before using local composite actions.
#
# Common mistake: Trying to use a local composite action (./.github/actions/*)
# without running actions/checkout@v4 first in the job.
#
# GitHub Actions cannot load composite action definitions without the repository
# being checked out, even if the composite action itself contains a checkout step.
#
# Usage:
#   ./scripts/ci/validate-composite-actions.sh
#
# Exit codes:
#   0 - All composite actions are used correctly
#   1 - Validation errors found
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

WORKFLOWS_DIR="$REPO_ROOT/.github/workflows"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

errors=0
warnings=0

echo "=========================================================="
echo "Composite Actions Usage Validation"
echo "=========================================================="
echo ""

# Find all workflow files
workflow_files=$(find "$WORKFLOWS_DIR" -name "*.yml" -o -name "*.yaml")

for workflow_file in $workflow_files; do
    workflow_name=$(basename "$workflow_file")

    # Extract job names and their steps
    # This is a simplified check - looks for jobs using local composite actions

    # Find lines that use local composite actions (./.github/actions/*)
    local_action_lines=$(grep -n "uses: \\.\\/.github/actions/" "$workflow_file" || true)

    if [[ -z "$local_action_lines" ]]; then
        continue
    fi

    echo "Checking $workflow_name..."

    # For each local action usage, check if there's a checkout before it in the same job
    while IFS= read -r line; do
        line_number=$(echo "$line" | cut -d: -f1)
        action_path=$(echo "$line" | sed 's/.*uses: //' | sed 's/ .*//' | tr -d '"' | tr -d "'")

        # Find the job this line belongs to by looking backwards for the job name
        # A job starts with a line like "  jobname:" (2 spaces, then identifier, then colon)
        job_start_line=$(awk -v target=$line_number '
            /^  [a-z][a-z0-9-]*:$/ { job_line = NR; job_name = $0 }
            NR == target { print job_line ":" job_name; exit }
        ' "$workflow_file")

        if [[ -z "$job_start_line" ]]; then
            echo -e "${YELLOW}⚠️  WARNING${NC}: Could not determine job for line $line_number in $workflow_name"
            ((warnings++))
            continue
        fi

        job_line=$(echo "$job_start_line" | cut -d: -f1)
        job_name=$(echo "$job_start_line" | cut -d: -f2- | sed 's/^  //' | sed 's/:$//')

        # Check if there's a checkout step before this line within the same job
        # Look for "uses: actions/checkout" between job start and the action usage
        has_checkout=$(awk -v start=$job_line -v end=$line_number '
            NR >= start && NR < end && /uses: actions\/checkout/ { found=1; exit }
            END { if (found) print "yes"; else print "no" }
        ' "$workflow_file")

        if [[ "$has_checkout" == "no" ]]; then
            echo -e "${RED}❌ ERROR${NC}: Job '$job_name' uses local action without checkout"
            echo "    File: $workflow_name"
            echo "    Line: $line_number"
            echo "    Action: $action_path"
            echo "    Fix: Add 'actions/checkout@v4' step before using this local action"
            echo ""
            ((errors++))
        else
            echo -e "${GREEN}✓${NC} Job '$job_name' correctly checks out before using $action_path"
        fi

    done <<< "$local_action_lines"

    echo ""
done

echo "=========================================================="

if [[ $errors -eq 0 && $warnings -eq 0 ]]; then
    echo -e "${GREEN}✅ All composite actions are used correctly!${NC}"
    exit 0
elif [[ $errors -eq 0 ]]; then
    echo -e "${YELLOW}⚠️  Validation passed with $warnings warning(s)${NC}"
    exit 0
else
    echo -e "${RED}❌ Found $errors error(s) and $warnings warning(s)${NC}"
    echo ""
    echo "Common fix:"
    echo "  Add this step BEFORE using local composite actions:"
    echo ""
    echo "    - name: Checkout code"
    echo "      uses: actions/checkout@v4"
    echo ""
    exit 1
fi
