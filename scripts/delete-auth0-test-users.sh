#!/bin/bash
################################################################################
# Delete Auth0 test users
#
# Purpose: Remove existing test users from Auth0 so Terraform can create them
#
# Prerequisites:
#   - Auth0 Management API access
#   - AUTH0_DOMAIN, AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET environment variables
#   - jq installed
#
# Usage:
#   1. Set Auth0 credentials (same as Terraform uses):
#      export AUTH0_DOMAIN="$AUTH0_DOMAIN"
#      export AUTH0_CLIENT_ID="$AUTH0_CLIENT_ID"
#      export AUTH0_CLIENT_SECRET="$AUTH0_CLIENT_SECRET"
#
#   2. Run: ./scripts/delete-auth0-test-users.sh
#
################################################################################

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${YELLOW}Auth0 Test User Deletion Script${NC}"
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

# Function to get user ID by email
get_user_id() {
    local email=$1
    local response=$(curl -s --request GET \
      --url "https://${AUTH0_DOMAIN}/api/v2/users-by-email?email=${email}" \
      --header "authorization: Bearer ${ACCESS_TOKEN}")
    
    local user_id=$(echo "$response" | jq -r '.[0].user_id // empty')
    echo "$user_id"
}

# Function to delete user
delete_user() {
    local email=$1
    local user_id=$(get_user_id "$email")
    
    if [[ -z "$user_id" ]]; then
        echo -e "${YELLOW}⚠ User $email not found in Auth0 (already deleted or never existed)${NC}"
        return 0
    fi
    
    echo "Found user: $email (ID: $user_id)"
    echo "Deleting..."
    
    local response=$(curl -s --request DELETE \
      --url "https://${AUTH0_DOMAIN}/api/v2/users/${user_id}" \
      --header "authorization: Bearer ${ACCESS_TOKEN}")
    
    # Check if delete was successful (empty response = success)
    if [[ -z "$response" ]]; then
        echo -e "${GREEN}✓ Successfully deleted $email${NC}"
    else
        echo -e "${RED}✗ Failed to delete $email${NC}"
        echo "$response"
        return 1
    fi
}

echo ""
echo -e "${YELLOW}⚠️  WARNING: This will delete test users from Auth0${NC}"
echo "Users to delete:"
echo "  - $ADMIN_EMAIL"
echo "  - $USER_EMAIL"
echo ""
echo "Press Ctrl+C to cancel, or Enter to continue..."
read

echo ""
echo "Deleting test users..."
echo ""

delete_user "$ADMIN_EMAIL"
delete_user "$USER_EMAIL"

echo ""
echo -e "${GREEN}✓ Deletion complete!${NC}"
echo ""
echo "You can now run Terraform apply to recreate the users."
