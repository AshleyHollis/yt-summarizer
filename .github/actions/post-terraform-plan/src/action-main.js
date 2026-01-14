#!/usr/bin/env node

/**
 * GitHub Action Entry Point
 *
 * This script is called by the GitHub Action to generate PR comments
 * and pipeline summaries from Terraform plan JSON.
 *
 * Inputs (from environment variables):
 *   PLAN_SUMMARY_PATH - Path to plan summary JSON file
 *   FORMATTED_PLAN_PATH - Path to formatted plan JSON file
 *   PLAN_OUTCOME_PATH - Path to plan outcome text file
 *   PLAN_OUTCOME - Fallback plan outcome from env
 *
 * Outputs:
 *   - Writes markdown to stdout for use by GitHub Actions
 */

const fs = require('fs');
const { parseJsonPlan, calculateSummary } = require('./terraform-plan-parser');
const { generatePrComment, generatePipelineSummary } = require('./markdown-generator');

function main() {
  const args = process.argv.slice(2);
  const command = args[0] || 'pr-comment';

  // Get paths from environment or command line
  const planSummaryPath = process.env.PLAN_SUMMARY_PATH || args[1];
  const formattedPlanPath = process.env.FORMATTED_PLAN_PATH || args[2];
  const planOutcomePath = process.env.PLAN_OUTCOME_PATH || args[3];

  let summary, planJson, planOutcome;

  // Read plan summary
  try {
    if (planSummaryPath && fs.existsSync(planSummaryPath)) {
      const summaryContent = fs.readFileSync(planSummaryPath, 'utf8');
      summary = JSON.parse(summaryContent);
    } else {
      console.error('Warning: Plan summary file not found, using defaults');
      summary = { add: 0, change: 0, destroy: 0, has_changes: false };
    }
  } catch (error) {
    console.error(`Warning: Failed to read plan summary file: ${error.message}`);
    summary = { add: 0, change: 0, destroy: 0, has_changes: false };
  }

  // Read formatted plan
  try {
    if (formattedPlanPath && fs.existsSync(formattedPlanPath)) {
      planJson = fs.readFileSync(formattedPlanPath, 'utf8');
    } else {
      console.error('Warning: Formatted plan file not found');
      planJson = '{}';
    }
  } catch (error) {
    console.error(`Warning: Failed to read formatted plan file: ${error.message}`);
    planJson = '{}';
  }

  // Read plan outcome
  try {
    if (planOutcomePath && fs.existsSync(planOutcomePath)) {
      planOutcome = fs.readFileSync(planOutcomePath, 'utf8').trim();
    } else {
      planOutcome = process.env.PLAN_OUTCOME || 'unknown';
    }
  } catch (error) {
    console.error(`Warning: Failed to read plan outcome file: ${error.message}`);
    planOutcome = process.env.PLAN_OUTCOME || 'unknown';
  }

  // Parse resources from JSON plan
  const resources = parseJsonPlan(planJson);

  // Recalculate summary from parsed resources for accuracy
  const calculatedSummary = calculateSummary(resources);

  // Use calculated summary to match displayed resources
  const finalSummary = calculatedSummary;

  // Get context from environment (set by GitHub Actions)
  const runNumber = process.env.GITHUB_RUN_NUMBER || '1';
  const runId = process.env.GITHUB_RUN_ID || '0';
  const repo = process.env.GITHUB_REPOSITORY || 'owner/repo';
  const actor = process.env.GITHUB_ACTOR || 'unknown';
  const runUrl = `https://github.com/${repo}/actions/runs/${runId}`;

  const options = {
    resources,
    summary: finalSummary,
    planOutcome,
    runNumber: parseInt(runNumber),
    runUrl,
    actor,
    planJson
  };

  // Generate output based on command
  if (command === 'pr-comment') {
    console.log(generatePrComment(options));
  } else if (command === 'pipeline-summary') {
    console.log(generatePipelineSummary(options));
  } else if (command === 'both') {
    // Output both, separated by a marker
    console.log('=== PR_COMMENT_START ===');
    console.log(generatePrComment(options));
    console.log('=== PR_COMMENT_END ===');
    console.log('=== PIPELINE_SUMMARY_START ===');
    console.log(generatePipelineSummary(options));
    console.log('=== PIPELINE_SUMMARY_END ===');
  } else {
    console.error(`Unknown command: ${command}`);
    console.error('Usage: node action-main.js [pr-comment|pipeline-summary|both] [paths...]');
    process.exit(1);
  }
}

main();
