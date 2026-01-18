#!/bin/bash

################################################################################
# Action: post-terraform-plan / generate-pr-comment.sh
#
# Purpose: Generate formatted PR comment with Terraform plan details.
#          Reads plan data files and generates markdown comment output.
#
# Inputs (Environment Variables):
#   PLAN_SUMMARY_PATH   - Path to plan-summary.json
#   FORMATTED_PLAN_PATH - Path to formatted-plan.json
#   PLAN_OUTCOME_PATH   - Path to plan-outcome.txt
#   PLAN_OUTCOME        - Plan outcome (success/failure)
#
# Outputs:
#   Creates: pr-comment.md (formatted Markdown for PR comment)
#
# Logic Flow:
#   1. Read plan summary, formatted plan, and outcome from files
#   2. Generate Markdown with Terraform Cloud-like styling
#   3. Include status badge, resource counts, and plan details
#   4. Add unique comment marker for finding/updating
#
################################################################################

set -euo pipefail

# Create pr-comment.md via Node.js script
node "$(dirname "$0")/src/action-main.js" pr-comment > pr-comment.md

echo "✅ PR comment generated: pr-comment.md"
