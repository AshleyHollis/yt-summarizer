#!/bin/bash
################################################################################
# Unlock Terraform State - Manual Intervention Script
#
# Purpose: This script helps unlock a stuck Terraform state lock
#
# When to use:
#   - When terraform plan/apply fails with "state blob is already locked"
#   - When you've verified no other terraform operation is running
#   - When the lock is from a failed/cancelled workflow run
#
# How to use:
#   1. Get the lock ID from the error message in the failed workflow
#   2. Run: ./unlock-terraform-state.sh <LOCK_ID>
#   3. Or run: terraform force-unlock <LOCK_ID> from infra/terraform/environments/prod
#
# Safety:
#   - This removes the lock WITHOUT checking if another operation is using it
#   - ONLY use if you're certain no terraform apply/plan is actively running
#   - Check recent workflow runs to ensure no concurrent operations
#
################################################################################

set -euo pipefail

LOCK_ID="${1:-}"

if [ -z "$LOCK_ID" ]; then
  echo "Error: Lock ID required"
  echo ""
  echo "Usage: $0 <LOCK_ID>"
  echo ""
  echo "Example:"
  echo "  $0 a1dc7a4b-6bb4-cb66-d516-f143d4bda7b9"
  echo ""
  echo "Get the lock ID from the error message in the failed workflow."
  exit 1
fi

echo "⚠️  WARNING: Force unlocking Terraform state"
echo "Lock ID: $LOCK_ID"
echo ""
echo "This will remove the lock without checking if another operation is using it."
echo "Press Ctrl+C to cancel, or Enter to continue..."
read

cd "$(dirname "$0")/../../infra/terraform/environments/prod"

echo "Unlocking..."
terraform force-unlock -force "$LOCK_ID"

echo "✅ Lock removed successfully"
echo ""
echo "You can now re-run the failed terraform workflow."
