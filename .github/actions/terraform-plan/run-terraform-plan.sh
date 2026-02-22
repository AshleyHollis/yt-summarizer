#!/bin/bash
# Purpose: Runs terraform plan and captures output for PR comments
# Inputs: Passed via working directory and environment variables
#   SUBSCRIPTION_ID, SQL_ADMIN_PASSWORD, OPENAI_API_KEY, CLOUDFLARE_API_TOKEN,
#   AUTH0_DOMAIN (optional)
# Outputs:
#   plan_output: Raw terraform plan output
#   plan_summary: JSON summary of plan changes (add/change/destroy counts)
#   formatted_plan: Full JSON plan output
# Logic:
#   1. Run terraform plan with all required variables
#   2. Capture output to file and GITHUB_OUTPUT
#   3. Export plan as JSON using terraform show
#   4. Parse JSON to count resource changes (add/change/delete)
#   5. Create JSON summary object with change counts

set -eo pipefail

terraform plan -no-color -input=false -out=tfplan \
  -var="subscription_id=${SUBSCRIPTION_ID}" \
  -var="sql_admin_password=${SQL_ADMIN_PASSWORD}" \
  -var="openai_api_key=${OPENAI_API_KEY}" \
  -var="cloudflare_api_token=${CLOUDFLARE_API_TOKEN}" \
  -var="auth0_domain=${AUTH0_DOMAIN:-}" \
  2>&1 | tee plan_output.txt

PLAN_EXIT_CODE=$?

echo "plan_output<<EOF" >> "$GITHUB_OUTPUT"
cat plan_output.txt >> "$GITHUB_OUTPUT"
echo "EOF" >> "$GITHUB_OUTPUT"

exit $PLAN_EXIT_CODE
