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
if ! terraform show -json tfplan > plan.json.raw 2>&1; then
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

# Scrub sensitive data from plan output
# This prevents password/secret exposure even if sensitive flag is not properly set
echo "🔒 Scrubbing sensitive fields from plan output..."
cat plan.json.raw | \
  jq 'walk(
    if type == "object" then
      with_entries(
        if (.key | test("password|secret|token|key"; "i")) and (.value | type == "string") then
          .value = "(sensitive value)"
        else
          .
        end
      )
    else
      .
    end
  )' > plan.json

# Clean up raw file
rm -f plan.json.raw

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

# Write plan.json to a dedicated directory to avoid argument length limits
# DO NOT write to GITHUB_OUTPUT - the file can be too large (>2MB with 16 resources)
PLAN_DATA_DIR="${RUNNER_TEMP:-/tmp}/terraform-plan-data"
mkdir -p "$PLAN_DATA_DIR"

cp plan.json "$PLAN_DATA_DIR/formatted-plan.json"
echo "$SUMMARY" > "$PLAN_DATA_DIR/plan-summary.json"

# Export the directory path for downstream steps
echo "TERRAFORM_PLAN_DATA_DIR=$PLAN_DATA_DIR" >> "$GITHUB_ENV"

echo "✅ Plan data written to: $PLAN_DATA_DIR"
echo "  - formatted-plan.json: $(wc -c < plan.json) bytes"
echo "  - plan-summary.json: $(echo "$SUMMARY" | wc -c) bytes"

# For backward compatibility, output a small marker (NOT the full plan)
echo "formatted_plan=<file:$PLAN_DATA_DIR/formatted-plan.json>" >> "$GITHUB_OUTPUT"
