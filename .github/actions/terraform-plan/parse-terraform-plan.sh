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

# Check if tfplan file exists
if [ ! -f "tfplan" ]; then
  echo "::error::tfplan file not found - terraform plan may have failed"
  echo "::error::Check the 'Run terraform plan' step output for errors"

  # Output empty summary to prevent downstream failures
  SUMMARY=$(cat <<EOF
{
  "add": 0,
  "change": 0,
  "destroy": 0,
  "has_changes": false,
  "error": "tfplan file not found"
}
EOF
)

  echo "plan_summary<<EOF" >> "$GITHUB_OUTPUT"
  echo "$SUMMARY" >> "$GITHUB_OUTPUT"
  echo "EOF" >> "$GITHUB_OUTPUT"

  echo "formatted_plan<<EOF" >> "$GITHUB_OUTPUT"
  echo "{}" >> "$GITHUB_OUTPUT"
  echo "EOF" >> "$GITHUB_OUTPUT"

  exit 1
fi

# Get structured JSON output from terraform
if ! terraform show -json tfplan > plan.json 2>&1; then
  echo "::error::Failed to convert tfplan to JSON"

  SUMMARY=$(cat <<EOF
{
  "add": 0,
  "change": 0,
  "destroy": 0,
  "has_changes": false,
  "error": "Failed to convert tfplan to JSON"
}
EOF
)

  echo "plan_summary<<EOF" >> "$GITHUB_OUTPUT"
  echo "$SUMMARY" >> "$GITHUB_OUTPUT"
  echo "EOF" >> "$GITHUB_OUTPUT"

  echo "formatted_plan<<EOF" >> "$GITHUB_OUTPUT"
  echo "{}" >> "$GITHUB_OUTPUT"
  echo "EOF" >> "$GITHUB_OUTPUT"

  exit 1
fi

# Parse plan summary from JSON
ADD=$(jq -r '.resource_changes | map(select(.change.actions | contains(["create"]))) | length' plan.json)
CHANGE=$(jq -r '.resource_changes | map(select(.change.actions | contains(["update"]))) | length' plan.json)
DESTROY=$(jq -r '.resource_changes | map(select(.change.actions | contains(["delete"]))) | length' plan.json)

# Validate jq outputs
if [ -z "$ADD" ] || [ -z "$CHANGE" ] || [ -z "$DESTROY" ]; then
  echo "::error::Failed to parse plan.json with jq"
  echo "::error::ADD=$ADD, CHANGE=$CHANGE, DESTROY=$DESTROY"

  # Default to 0 if parsing failed
  ADD=${ADD:-0}
  CHANGE=${CHANGE:-0}
  DESTROY=${DESTROY:-0}
fi

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
