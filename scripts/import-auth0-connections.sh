#!/usr/bin/env bash
# ==============================================================================
# Import Existing Auth0 Connections into Terraform State
# ==============================================================================
# Auth0 connections are tenant-level resources that may already exist.
# This script imports them into Terraform state if they exist and are not
# already managed, preventing "409 Conflict: connection already exists" errors.
#
# Usage:
#   ./scripts/import-auth0-connections.sh
#
# Environment Variables Required:
#   AUTH0_DOMAIN - Auth0 tenant domain
#   AUTH0_CLIENT_ID - Terraform service account client ID
#   AUTH0_CLIENT_SECRET - Terraform service account client secret
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TERRAFORM_DIR="${SCRIPT_DIR}/../infra/terraform/environments/prod"

# Validate required environment variables
if [[ -z "${AUTH0_DOMAIN:-}" || -z "${AUTH0_CLIENT_ID:-}" || -z "${AUTH0_CLIENT_SECRET:-}" ]]; then
  echo "ERROR: Missing required Auth0 environment variables"
  echo "  AUTH0_DOMAIN: ${AUTH0_DOMAIN:-<not set>}"
  echo "  AUTH0_CLIENT_ID: ${AUTH0_CLIENT_ID:-<not set>}"
  echo "  AUTH0_CLIENT_SECRET: ${AUTH0_CLIENT_SECRET:-<not set>}"
  exit 1
fi

echo "=============================================================================="
echo "Importing Auth0 Connections"
echo "=============================================================================="
echo "Auth0 Tenant: ${AUTH0_DOMAIN}"
echo "Terraform Directory: ${TERRAFORM_DIR}"
echo ""

cd "${TERRAFORM_DIR}"

# Initialize Terraform
echo "Initializing Terraform..."
terraform init -input=false

# Get Auth0 Management API token
echo "Retrieving Auth0 Management API token..."
TOKEN_RESPONSE=$(curl -s -X POST "https://${AUTH0_DOMAIN}/oauth/token" \
  -H "Content-Type: application/json" \
  -d "{\"client_id\":\"${AUTH0_CLIENT_ID}\",\"client_secret\":\"${AUTH0_CLIENT_SECRET}\",\"audience\":\"https://${AUTH0_DOMAIN}/api/v2/\",\"grant_type\":\"client_credentials\"}")

ACCESS_TOKEN=$(echo "${TOKEN_RESPONSE}" | jq -r '.access_token')

if [[ -z "${ACCESS_TOKEN}" || "${ACCESS_TOKEN}" == "null" ]]; then
  echo "ERROR: Failed to retrieve Auth0 access token"
  echo "Response: ${TOKEN_RESPONSE}"
  exit 1
fi

echo "Successfully retrieved access token"

# Fetch existing connections
echo "Fetching existing Auth0 connections..."
CONNECTIONS=$(curl -s -X GET "https://${AUTH0_DOMAIN}/api/v2/connections" \
  -H "Authorization: Bearer ${ACCESS_TOKEN}")

echo "Found connections:"
echo "${CONNECTIONS}" | jq -r '.[] | "\(.name) (\(.id)) - \(.strategy)"'
echo ""

# Define connection mappings: Terraform resource address -> connection name
declare -A CONNECTION_MAP=(
  ["module.auth0[0].auth0_connection.database[0]"]="Username-Password-Authentication"
  ["module.auth0[0].auth0_connection.google[0]"]="google-oauth2"
  ["module.auth0[0].auth0_connection.github[0]"]="github"
)

# Import each connection if it exists and is not already in state
for RESOURCE_ADDR in "${!CONNECTION_MAP[@]}"; do
  CONNECTION_NAME="${CONNECTION_MAP[$RESOURCE_ADDR]}"

  echo "Processing connection: ${CONNECTION_NAME}"

  # Check if resource already exists in state
  if terraform state show "${RESOURCE_ADDR}" &>/dev/null; then
    echo "  ✓ Already in Terraform state (skipping import)"
    continue
  fi

  # Find connection ID from Auth0
  CONNECTION_ID=$(echo "${CONNECTIONS}" | jq -r ".[] | select(.name == \"${CONNECTION_NAME}\") | .id")

  if [[ -z "${CONNECTION_ID}" || "${CONNECTION_ID}" == "null" ]]; then
    echo "  ⚠ Connection not found in Auth0 (will be created on apply)"
    continue
  fi

  echo "  Found connection ID: ${CONNECTION_ID}"
  echo "  Importing into ${RESOURCE_ADDR}..."

  if terraform import "${RESOURCE_ADDR}" "${CONNECTION_ID}"; then
    echo "  ✓ Successfully imported"
  else
    echo "  ✗ Import failed"
    exit 1
  fi
done

echo ""
echo "=============================================================================="
echo "Import Complete"
echo "=============================================================================="
echo "All existing Auth0 connections have been imported into Terraform state."
echo "You can now run 'terraform apply' without conflicts."
