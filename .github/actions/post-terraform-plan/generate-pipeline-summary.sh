#!/bin/bash

################################################################################
# Action: post-terraform-plan / generate-pipeline-summary.sh
#
# Purpose: Generate pipeline summary with Terraform plan overview.
#          Creates Markdown summary for GitHub Actions job summary.
#
# Inputs (Environment Variables):
#   PLAN_SUMMARY_PATH   - Path to plan-summary.json
#   FORMATTED_PLAN_PATH - Path to formatted-plan.json
#   PLAN_OUTCOME_PATH   - Path to plan-outcome.txt
#   PLAN_OUTCOME        - Plan outcome (success/failure)
#
# Outputs:
#   Creates: pipeline-summary.md (formatted Markdown for job summary)
#
# Logic Flow:
#   1. Read plan data from files
#   2. Extract resource counts (add, change, destroy)
#   3. Generate summary status with visual indicators
#   4. Include resource breakdown table
#
################################################################################

set -euo pipefail

# Generate pipeline summary via Node.js script
node "$(dirname "$0")/src/action-main.js" pipeline-summary > \
  pipeline-summary.md

echo "✅ Pipeline summary generated: pipeline-summary.md"
