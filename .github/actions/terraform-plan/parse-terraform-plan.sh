#!/bin/bash
# Purpose: Parse terraform plan JSON and extract summary information
# Inputs: tfplan file from previous terraform plan step
# Outputs:
#   plan_summary: JSON object with add/change/destroy counts
#   formatted_plan: Full terraform JSON plan output
# Logic:
#   1. Convert binary tfplan to JSON format
#   2. Parse resource_changes array to count each action type
#   3. Create JSON summary with counts and has_changes flag
#   4. Output full JSON plan for downstream parsing

# Get structured JSON output from terraform
terraform show -json tfplan > plan.json

# Parse plan summary from JSON
ADD=$(jq -r '.resource_changes | map(select(.change.actions | \
  contains(["create"]))) | length' plan.json)
CHANGE=$(jq -r '.resource_changes | map(select(.change.actions | \
  contains(["update"]))) | length' plan.json)
DESTROY=$(jq -r '.resource_changes | map(select(.change.actions | \
  contains(["delete"]))) | length' plan.json)

# Create JSON summary
SUMMARY=$(cat <<EOF
{
  "add": $ADD,
  "change": $CHANGE,
  "destroy": $DESTROY,
  "has_changes": $([ $ADD -gt 0 ] || [ $CHANGE -gt 0 ] || [ $DESTROY -gt 0 ] \
    && echo "true" || echo "false")
}
EOF
)

echo "plan_summary<<EOF" >> "$GITHUB_OUTPUT"
echo "$SUMMARY" >> "$GITHUB_OUTPUT"
echo "EOF" >> "$GITHUB_OUTPUT"

# Output the full JSON plan for parsing
echo "formatted_plan<<EOF" >> "$GITHUB_OUTPUT"
cat plan.json >> "$GITHUB_OUTPUT"
echo "EOF" >> "$GITHUB_OUTPUT"
