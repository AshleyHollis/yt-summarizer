#!/bin/bash

################################################################################
# Action: post-terraform-plan / save-plan-data.sh
#
# Purpose: Save plan data from inputs to temporary files for safer handling.
#          Avoids passing large JSON through environment variables.
#
# Inputs (Environment Variables):
#   PLAN_SUMMARY    - JSON summary of plan changes
#   FORMATTED_PLAN  - Formatted terraform plan output (JSON)
#   PLAN_OUTCOME    - Plan outcome (success/failure)
#
# Outputs:
#   Creates: plan-summary.json, formatted-plan.json, plan-outcome.txt
#
# Logic Flow:
#   1. Write PLAN_SUMMARY to plan-summary.json
#   2. Write FORMATTED_PLAN to formatted-plan.json
#   3. Write PLAN_OUTCOME to plan-outcome.txt
#   4. Files used by subsequent steps
#
################################################################################

set -euo pipefail

# Write data to files (safer than passing large JSON through env vars)
# Use printf to avoid issues with large content
printf '%s\n' "$PLAN_SUMMARY" > plan-summary.json
printf '%s\n' "$FORMATTED_PLAN" > formatted-plan.json
printf '%s\n' "$PLAN_OUTCOME" > plan-outcome.txt

echo "✅ Plan data files created"
echo "  - plan-summary.json: $(wc -c < plan-summary.json) bytes"
echo "  - formatted-plan.json: $(wc -c < formatted-plan.json) bytes"
echo "  - plan-outcome.txt: $(wc -c < plan-outcome.txt) bytes"
