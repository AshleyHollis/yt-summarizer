#!/usr/bin/env node

/**
 * Generate Preview
 *
 * CLI tool to generate HTML preview from Terraform plan JSON.
 *
 * Usage:
 *   node generate-preview.js <plan.json> [output.html]
 *   node generate-preview.js --fixture realistic
 */

const fs = require('fs');
const path = require('path');
const { parseJsonPlan, calculateSummary } = require('./terraform-plan-parser');
const { generateHtml } = require('./html-generator');
const { generatePrComment } = require('./markdown-generator');

function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
    console.log(`
Terraform Plan Preview Generator

Usage:
  node generate-preview.js <plan.json> [output.html]
  node generate-preview.js --fixture <name>

Options:
  --fixture <name>   Use a test fixture (realistic, no-changes, create-only)
  --markdown         Also generate markdown output
  --help, -h         Show this help message

Examples:
  node generate-preview.js plan.json preview.html
  node generate-preview.js --fixture realistic
  node generate-preview.js --fixture realistic --markdown
`);
    process.exit(0);
  }

  let planPath;
  let outputPath;
  let generateMarkdown = args.includes('--markdown');

  // Handle fixture mode
  const fixtureIndex = args.indexOf('--fixture');
  if (fixtureIndex !== -1) {
    const fixtureName = args[fixtureIndex + 1] || 'realistic';
    planPath = path.join(__dirname, '..', 'test-fixtures', `${fixtureName}-plan.json`);
    outputPath = path.join(__dirname, '..', 'preview', `${fixtureName}-preview.html`);
  } else {
    planPath = args[0];
    outputPath = args[1] || planPath.replace(/\.json$/, '-preview.html');
  }

  // Ensure preview directory exists
  const previewDir = path.dirname(outputPath);
  if (!fs.existsSync(previewDir)) {
    fs.mkdirSync(previewDir, { recursive: true });
  }

  // Read and parse plan
  console.log(`Reading plan from: ${planPath}`);

  if (!fs.existsSync(planPath)) {
    console.error(`Error: Plan file not found: ${planPath}`);
    process.exit(1);
  }

  const planJson = fs.readFileSync(planPath, 'utf-8');
  const resources = parseJsonPlan(planJson);
  const summary = calculateSummary(resources);

  console.log(`Parsed ${resources.length} resources:`);
  console.log(`  - ${summary.add} to add`);
  console.log(`  - ${summary.change} to change`);
  console.log(`  - ${summary.destroy} to destroy`);

  // Generate HTML
  const html = generateHtml({
    resources,
    summary,
    planOutcome: 'success',
    runNumber: 42,
    runUrl: 'https://github.com/AshleyHollis/yt-summarizer/actions/runs/12345',
    actor: 'developer',
    timestamp: new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC'
  });

  fs.writeFileSync(outputPath, html, 'utf-8');
  console.log(`\nHTML preview generated: ${outputPath}`);

  // Generate markdown if requested
  if (generateMarkdown) {
    const markdownPath = outputPath.replace(/\.html$/, '.md');
    const markdown = generatePrComment({
      resources,
      summary,
      planOutcome: 'success',
      runNumber: 42,
      runUrl: 'https://github.com/AshleyHollis/yt-summarizer/actions/runs/12345',
      actor: 'developer',
      planJson
    });

    fs.writeFileSync(markdownPath, markdown, 'utf-8');
    console.log(`Markdown output generated: ${markdownPath}`);
  }

  console.log('\nOpen the HTML file in a browser to preview the Terraform plan visualization.');
}

main();
