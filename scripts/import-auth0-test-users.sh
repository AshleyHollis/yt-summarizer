#!/bin/bash
################################################################################
# Import existing Auth0 test users into Terraform state
#
# Purpose: When test users already exist in Auth0 but aren't in Terraform state,
#          this script imports them to prevent "user already exists" errors
#
# Prerequisites:
#   - Auth0 CLI or Management API access
#   - AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET environment variables
#   - jq installed
#
# Usage:
#   1. Set Auth0 credentials:
#      export AUTH0_DOMAIN="your-tenant.auth0.com"
#      export AUTH0_CLIENT_ID="your-client-id"
#      export AUTH0_CLIENT_SECRET="your-client-secret"
#
#   2. Run: ./scripts/import-auth0-test-users.sh
#
################################################################################

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Auth0 Test User Import Script${NC}"
echo ""

# Check prerequisites
if ! command -v jq &> /dev/null; then
    echo -e "${RED}Error: jq is not installed${NC}"
    exit 1
fi

if [[ -z "${AUTH0_DOMAIN:-}" ]] || [[ -z "${AUTH0_CLIENT_ID:-}" ]] || [[ -z "${AUTH0_CLIENT_SECRET:-}" ]]; then
    echo -e "${RED}Error: AUTH0_DOMAIN, AUTH0_CLIENT_ID, and AUTH0_CLIENT_SECRET must be set${NC}"
    exit 1
fi

# Get Auth0 management API token
echo "Getting Auth0 Management API token..."
TOKEN_RESPONSE=$(curl -s --request POST \
  --url "https://${AUTH0_DOMAIN}/oauth/token" \
  --header 'content-type: application/json' \
  --data "{\"client_id\":\"${AUTH0_CLIENT_ID}\",\"client_secret\":\"${AUTH0_CLIENT_SECRET}\",\"audience\":\"https://${AUTH0_DOMAIN}/api/v2/\",\"grant_type\":\"client_credentials\"}")

ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE" | jq -r '.access_token')

if [[ "$ACCESS_TOKEN" == "null" ]] || [[ -z "$ACCESS_TOKEN" ]]; then
    echo -e "${RED}Error: Failed to get access token${NC}"
    echo "$TOKEN_RESPONSE"
    exit 1
fi

echo -e "${GREEN}✓ Got access token${NC}"

# Define test user emails
ADMIN_EMAIL="admin@test.yt-summarizer.internal"
USER_EMAIL="user@test.yt-summarizer.internal"

cd "$(dirname "$0")/../infra/terraform/environments/prod"

# Function to get user ID by email
get_user_id() {
    local email=$1
    local response=$(curl -s --request GET \
      --url "https://${AUTH0_DOMAIN}/api/v2/users-by-email?email=${email}" \
      --header "authorization: Bearer ${ACCESS_TOKEN}")

    local user_id=$(echo "$response" | jq -r '.[0].user_id // empty')
    echo "$user_id"
}

# Function to import user
import_user() {
    local email=$1
    local user_id=$(get_user_id "$email")

    if [[ -z "$user_id" ]]; then
        echo -e "${YELLOW}⚠ User $email not found in Auth0${NC}"
        return 0
    fi

    echo "Found user: $email (ID: $user_id)"

    # Import into terraform
    local tf_resource="module.auth0[0].auth0_user.test_user[\"${email}\"]"
    echo "Importing as: $tf_resource"

    if terraform import "$tf_resource" "$user_id"; then
        echo -e "${GREEN}✓ Successfully imported $email${NC}"
    else
        echo -e "${RED}✗ Failed to import $email${NC}"
        return 1
    fi
}

echo ""
echo "Importing test users..."
echo ""

import_user "$ADMIN_EMAIL"
import_user "$USER_EMAIL"

echo ""
echo -e "${GREEN}✓ Import complete!${NC}"
echo ""
echo "You can now run 'terraform plan' to verify the import."
