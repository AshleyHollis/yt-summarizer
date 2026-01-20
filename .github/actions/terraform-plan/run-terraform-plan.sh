#!/bin/bash
# Purpose: Runs terraform plan and captures output for PR comments
# Inputs: Passed via working directory and environment variables
#   SUBSCRIPTION_ID, SQL_ADMIN_PASSWORD, OPENAI_API_KEY, CLOUDFLARE_API_TOKEN,
#   AUTH0_DOMAIN (optional), AUTH0_CLIENT_ID (optional)
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

set -o pipefail

terraform plan -no-color -input=false -out=tfplan \
  -var="subscription_id=${SUBSCRIPTION_ID}" \
  -var="sql_admin_password=${SQL_ADMIN_PASSWORD}" \
  -var="openai_api_key=${OPENAI_API_KEY}" \
  -var="cloudflare_api_token=${CLOUDFLARE_API_TOKEN}" \
  -var="auth0_domain=${AUTH0_DOMAIN:-}" \
  -var="auth0_terraform_client_id=${AUTH0_CLIENT_ID:-}" \
  2>&1 | tee plan_output.raw.txt

PLAN_EXIT_CODE=$?

# Scrub sensitive data from plan output
# This prevents password/secret exposure even if sensitive flag is not properly set
echo "🔒 Scrubbing sensitive fields from plan output..."
sed -E \
  -e 's/([a-zA-Z0-9_-]*password[a-zA-Z0-9_-]*\s*=\s*)"[^"]+"/\1"(sensitive value)"/gi' \
  -e 's/([a-zA-Z0-9_-]*secret[a-zA-Z0-9_-]*\s*=\s*)"[^"]+"/\1"(sensitive value)"/gi' \
  -e 's/([a-zA-Z0-9_-]*token[a-zA-Z0-9_-]*\s*=\s*)"[^"]+"/\1"(sensitive value)"/gi' \
  -e 's/([a-zA-Z0-9_-]*key[a-zA-Z0-9_-]*\s*=\s*)"[^"]+"/\1"(sensitive value)"/gi' \
  plan_output.raw.txt > plan_output.txt

# Clean up raw file
rm -f plan_output.raw.txt

# Capture plan output to GITHUB_OUTPUT
echo "plan_output<<EOF" >> "$GITHUB_OUTPUT"
cat plan_output.txt >> "$GITHUB_OUTPUT"
echo "EOF" >> "$GITHUB_OUTPUT"

# Provide clear error message if plan failed
if [ $PLAN_EXIT_CODE -ne 0 ]; then
  echo "::error::Terraform plan failed with exit code $PLAN_EXIT_CODE"
  echo "::error::Review the plan output above for detailed error messages"

  # Check if failure was due to state lock
  if grep -q "state blob is already locked" plan_output.txt; then
    LOCK_ID=$(grep "ID:" plan_output.txt | awk '{print $2}' | head -n1)
    echo "::error::State lock detected - a previous operation may not have completed"
    echo "::notice::Lock ID: $LOCK_ID"
    echo "::notice::To unlock: Run 'terraform force-unlock $LOCK_ID' in infra/terraform/environments/prod"
    echo "::notice::Or use: ./scripts/unlock-terraform-state.sh $LOCK_ID"
    echo "::notice::IMPORTANT: Only unlock if you're certain no other terraform operation is running"
  fi

  # Note: tfplan file will NOT exist if plan failed
fi

exit $PLAN_EXIT_CODE
