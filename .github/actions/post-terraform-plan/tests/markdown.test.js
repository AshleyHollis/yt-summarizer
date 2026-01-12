/**
 * Unit Tests for Markdown Generator
 *
 * Run with: node tests/markdown.test.js
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const { parseJsonPlan, calculateSummary } = require('../src/terraform-plan-parser');
const {
  COMMENT_MARKER,
  ACTION_INDICATORS,
  buildResourceItem,
  buildResourceSection,
  generatePrComment,
  generatePipelineSummary
} = require('../src/markdown-generator');

// Test utilities
let testsPassed = 0;
let testsFailed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✓ ${name}`);
    testsPassed++;
  } catch (error) {
    console.error(`  ✗ ${name}`);
    console.error(`    ${error.message}`);
    testsFailed++;
  }
}

function describe(suiteName, fn) {
  console.log(`\n${suiteName}`);
  fn();
}

// Load test fixtures
const fixturesDir = path.join(__dirname, '..', 'test-fixtures');

function loadFixture(name) {
  const filePath = path.join(fixturesDir, `${name}-plan.json`);
  return fs.readFileSync(filePath, 'utf-8');
}

// Tests
describe('COMMENT_MARKER', () => {
  test('is a valid HTML comment', () => {
    assert.ok(COMMENT_MARKER.startsWith('<!--'));
    assert.ok(COMMENT_MARKER.endsWith('-->'));
  });
});

describe('ACTION_INDICATORS', () => {
  test('has all action types', () => {
    assert.ok(ACTION_INDICATORS.create);
    assert.ok(ACTION_INDICATORS.update);
    assert.ok(ACTION_INDICATORS.replace);
    assert.ok(ACTION_INDICATORS.destroy);
  });

  test('includes emoji and code formatting', () => {
    assert.ok(ACTION_INDICATORS.create.includes('🟢'));
    assert.ok(ACTION_INDICATORS.update.includes('🟡'));
    assert.ok(ACTION_INDICATORS.replace.includes('🟣'));
    assert.ok(ACTION_INDICATORS.destroy.includes('🔴'));
  });
});

describe('buildResourceItem', () => {
  test('builds collapsible details element', () => {
    const resource = {
      address: 'aws_instance.example',
      action: 'create',
      details: '+ resource "aws_instance" "example" {\n    + ami = "ami-123"\n  }'
    };

    const markdown = buildResourceItem(resource);

    assert.ok(markdown.includes('<details>'));
    assert.ok(markdown.includes('</details>'));
    assert.ok(markdown.includes('<summary>'));
    assert.ok(markdown.includes('</summary>'));
  });

  test('includes resource address in code tags', () => {
    const resource = {
      address: 'module.vpc.aws_subnet.private',
      action: 'update',
      details: '~ resource ...'
    };

    const markdown = buildResourceItem(resource);

    assert.ok(markdown.includes('<code>module.vpc.aws_subnet.private</code>'));
  });

  test('includes terraform code block', () => {
    const resource = {
      address: 'test',
      action: 'create',
      details: '+ resource "test" {}'
    };

    const markdown = buildResourceItem(resource);

    assert.ok(markdown.includes('```terraform'));
    assert.ok(markdown.includes('```'));
  });

  test('includes resource address for each action type', () => {
    const actions = ['create', 'update', 'replace', 'destroy'];

    actions.forEach(action => {
      const resource = { address: 'test.resource', action, details: 'test' };
      const markdown = buildResourceItem(resource);
      // Resource item now just shows the address without the action indicator
      assert.ok(markdown.includes('<code>test.resource</code>'));
    });
  });
});

describe('buildResourceSection', () => {
  test('returns empty array for empty resources', () => {
    const lines = buildResourceSection('Create', '🟢', 'create', []);
    assert.strictEqual(lines.length, 0);
  });

  test('builds section with title and count', () => {
    const resources = [
      { address: 'a', action: 'create', details: 'test' },
      { address: 'b', action: 'create', details: 'test' }
    ];

    const lines = buildResourceSection('Create', '🟢', 'create', resources);
    const markdown = lines.join('\n');

    assert.ok(markdown.includes('🟢 Create (2)'));
    assert.ok(markdown.includes('<details>'));
  });
});

describe('generatePrComment', () => {
  test('includes comment marker at start', () => {
    const planJson = loadFixture('realistic');
    const resources = parseJsonPlan(planJson);
    const summary = calculateSummary(resources);

    const markdown = generatePrComment({ resources, summary });

    assert.ok(markdown.startsWith(COMMENT_MARKER));
  });

  test('includes Terraform Plan header with status icon', () => {
    const resources = [];
    const summary = { add: 0, change: 0, destroy: 0, has_changes: false };

    const successMd = generatePrComment({ resources, summary, planOutcome: 'success' });
    const failureMd = generatePrComment({ resources, summary, planOutcome: 'failure' });

    assert.ok(successMd.includes('## ✅ Terraform Plan'));
    assert.ok(failureMd.includes('## ❌ Terraform Plan'));
  });

  test('includes run info line', () => {
    const resources = [];
    const summary = { add: 0, change: 0, destroy: 0, has_changes: false };

    const markdown = generatePrComment({
      resources,
      summary,
      runNumber: 42,
      runUrl: 'https://example.com/runs/42',
      actor: 'testuser'
    });

    // New format: **Run:** [#42](url) | **Date:** ... | **By:** @actor
    assert.ok(markdown.includes('**Run:** [#42]'));
    assert.ok(markdown.includes('@testuser'));
    assert.ok(markdown.includes('**By:**'));
  });

  test('includes summary table for changes', () => {
    const planJson = loadFixture('realistic');
    const resources = parseJsonPlan(planJson);
    const summary = calculateSummary(resources);

    const markdown = generatePrComment({ resources, summary });

    // New format: Summary table with headers
    assert.ok(markdown.includes('### 📋 Resource Summary'));
    assert.ok(markdown.includes('| Action | Count |'));
    assert.ok(markdown.includes('🟢'));
  });

  test('shows no changes message with GitHub alert when no changes', () => {
    const resources = [];
    const summary = { add: 0, change: 0, destroy: 0, has_changes: false };

    const markdown = generatePrComment({ resources, summary });

    // New format: GitHub alert for no changes
    assert.ok(markdown.includes('> [!SUCCESS]'));
    assert.ok(markdown.includes('No changes'));
  });

  test('includes all resource sections', () => {
    const planJson = loadFixture('realistic');
    const resources = parseJsonPlan(planJson);
    const summary = calculateSummary(resources);

    const markdown = generatePrComment({ resources, summary });

    assert.ok(markdown.includes('🟢 Create'));
    assert.ok(markdown.includes('🟡 Update'));
    assert.ok(markdown.includes('🔴 Destroy'));
    assert.ok(markdown.includes('🟣 Replace'));
  });

  test('includes all resource addresses', () => {
    const planJson = loadFixture('realistic');
    const resources = parseJsonPlan(planJson);
    const summary = calculateSummary(resources);

    const markdown = generatePrComment({ resources, summary });

    // Check for some known resource addresses from the fixture
    assert.ok(markdown.includes('module.acr.azurerm_container_registry.acr'));
    assert.ok(markdown.includes('module.github_oidc.azuread_application.github_actions'));
    assert.ok(markdown.includes('module.key_vault.azurerm_role_assignment.secrets_officer'));
  });
});

describe('generatePipelineSummary', () => {
  test('does not include comment marker', () => {
    const resources = [];
    const summary = { add: 0, change: 0, destroy: 0, has_changes: false };

    const markdown = generatePipelineSummary({ resources, summary });

    assert.ok(!markdown.includes(COMMENT_MARKER));
  });

  test('has same content structure as PR comment', () => {
    const planJson = loadFixture('realistic');
    const resources = parseJsonPlan(planJson);
    const summary = calculateSummary(resources);

    const prComment = generatePrComment({ resources, summary });
    const pipelineSummary = generatePipelineSummary({ resources, summary });

    // Pipeline summary should have all the same content except the marker
    assert.ok(pipelineSummary.includes('## ✅ Terraform Plan'));
    assert.ok(pipelineSummary.includes('### 📋 Resource Summary'));
  });
});

// Run tests and report results
console.log('\n========================================');
console.log('Markdown Generator - Unit Tests');
console.log('========================================');

// Print summary
console.log('\n========================================');
console.log(`Results: ${testsPassed} passed, ${testsFailed} failed`);
console.log('========================================\n');

process.exit(testsFailed > 0 ? 1 : 0);
