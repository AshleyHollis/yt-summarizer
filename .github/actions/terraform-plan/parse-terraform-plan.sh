#!/bin/bash
# Purpose: Parse terraform plan JSON and extract summary information
# Inputs: tfplan file from previous terraform plan step
# Outputs:
#   plan_summary:    JSON object with add/change/destroy counts
#   plan_json_path:  Absolute path to plan.json on disk (avoids GITHUB_OUTPUT size limits)
# Logic:
#   1. Convert binary tfplan to JSON format
#   2. Parse resource_changes array to count each action type
#   3. Create JSON summary with counts and has_changes flag
#   4. Output the path to plan.json (not the content) for downstream steps

set -eo pipefail

# Get structured JSON output from terraform
terraform show -json tfplan > plan.json

# Parse plan summary from JSON
ADD=$(jq -r '.resource_changes | map(select(.change.actions | contains(["create"]))) | length' plan.json)
CHANGE=$(jq -r '.resource_changes | map(select(.change.actions | contains(["update"]))) | length' plan.json)
DESTROY=$(jq -r '.resource_changes | map(select(.change.actions | contains(["delete"]))) | length' plan.json)

# Create JSON summary
HAS_CHANGES="false"
if [ "${ADD}" -gt 0 ] || [ "${CHANGE}" -gt 0 ] || [ "${DESTROY}" -gt 0 ]; then HAS_CHANGES="true"; fi
SUMMARY=$(cat <<EOF
{
  "add": ${ADD},
  "change": ${CHANGE},
  "destroy": ${DESTROY},
  "has_changes": ${HAS_CHANGES}
}
EOF
)

echo "plan_summary<<EOF" >> "$GITHUB_OUTPUT"
echo "$SUMMARY" >> "$GITHUB_OUTPUT"
echo "EOF" >> "$GITHUB_OUTPUT"

# Output the path to plan.json rather than its content to avoid $GITHUB_OUTPUT
# size limits (plan JSON can be many MB on non-trivial Terraform configs).
# Downstream steps that need the plan JSON read it directly from disk via this path.
echo "plan_json_path=$(pwd)/plan.json" >> "$GITHUB_OUTPUT"
