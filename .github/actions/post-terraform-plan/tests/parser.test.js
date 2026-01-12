/**
 * Unit Tests for Terraform Plan Parser
 *
 * Run with: node tests/parser.test.js
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');

const {
  parseJsonPlan,
  calculateSummary,
  groupResourcesByAction,
  formatValue,
  findChanges
} = require('../src/terraform-plan-parser');

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
describe('formatValue', () => {
  test('formats null values', () => {
    assert.strictEqual(formatValue(null), 'null');
    assert.strictEqual(formatValue(undefined), 'null');
  });

  test('formats strings with quotes', () => {
    assert.strictEqual(formatValue('hello'), '"hello"');
    assert.strictEqual(formatValue(''), '""');
  });

  test('formats booleans', () => {
    assert.strictEqual(formatValue(true), 'true');
    assert.strictEqual(formatValue(false), 'false');
  });

  test('formats numbers', () => {
    assert.strictEqual(formatValue(42), '42');
    assert.strictEqual(formatValue(3.14), '3.14');
    assert.strictEqual(formatValue(0), '0');
  });

  test('formats empty arrays', () => {
    assert.strictEqual(formatValue([]), '[]');
  });

  test('formats arrays as JSON', () => {
    assert.strictEqual(formatValue([1, 2, 3]), '[1,2,3]');
    assert.strictEqual(formatValue(['a', 'b']), '["a","b"]');
  });

  test('formats empty objects', () => {
    assert.strictEqual(formatValue({}), '{}');
  });

  test('formats objects as JSON', () => {
    assert.strictEqual(formatValue({ a: 1 }), '{"a":1}');
  });

  test('formats unknown values', () => {
    assert.strictEqual(formatValue('anything', true), '(known after apply)');
  });
});

describe('findChanges', () => {
  test('finds added values', () => {
    const before = {};
    const after = { name: 'test' };
    const lines = findChanges(before, after, {}, '');

    assert.strictEqual(lines.length, 1);
    assert.ok(lines[0].includes('+'));
    assert.ok(lines[0].includes('name'));
    assert.ok(lines[0].includes('"test"'));
  });

  test('finds removed values', () => {
    const before = { name: 'test' };
    const after = {};
    const lines = findChanges(before, after, {}, '');

    assert.strictEqual(lines.length, 1);
    assert.ok(lines[0].includes('-'));
    assert.ok(lines[0].includes('name'));
  });

  test('finds changed values', () => {
    const before = { name: 'old' };
    const after = { name: 'new' };
    const lines = findChanges(before, after, {}, '');

    assert.strictEqual(lines.length, 1);
    assert.ok(lines[0].includes('~'));
    assert.ok(lines[0].includes('"old"'));
    assert.ok(lines[0].includes('"new"'));
  });

  test('skips identical values', () => {
    const before = { name: 'same', count: 5 };
    const after = { name: 'same', count: 5 };
    const lines = findChanges(before, after, {}, '');

    assert.strictEqual(lines.length, 0);
  });

  test('handles unknown after values', () => {
    const before = {};
    const after = { id: 'placeholder' };
    const afterUnknown = { id: true };
    const lines = findChanges(before, after, afterUnknown, '');

    assert.strictEqual(lines.length, 1);
    assert.ok(lines[0].includes('(known after apply)'));
  });
});

describe('parseJsonPlan', () => {
  test('parses empty plan', () => {
    const resources = parseJsonPlan('{}');
    assert.strictEqual(resources.length, 0);
  });

  test('parses plan with no resource changes', () => {
    const resources = parseJsonPlan(JSON.stringify({ resource_changes: [] }));
    assert.strictEqual(resources.length, 0);
  });

  test('parses no-changes plan (no-op actions)', () => {
    const planJson = loadFixture('no-changes');
    const resources = parseJsonPlan(planJson);
    assert.strictEqual(resources.length, 0);
  });

  test('parses create-only plan', () => {
    const planJson = loadFixture('create-only');
    const resources = parseJsonPlan(planJson);

    assert.strictEqual(resources.length, 3);
    assert.ok(resources.every(r => r.action === 'create'));
  });

  test('parses realistic plan with multiple action types', () => {
    const planJson = loadFixture('realistic');
    const resources = parseJsonPlan(planJson);

    assert.ok(resources.length > 0);

    const creates = resources.filter(r => r.action === 'create');
    const updates = resources.filter(r => r.action === 'update');
    const destroys = resources.filter(r => r.action === 'destroy');
    const replaces = resources.filter(r => r.action === 'replace');

    assert.ok(creates.length > 0, 'Should have create actions');
    assert.ok(updates.length > 0, 'Should have update actions');
    assert.ok(destroys.length > 0, 'Should have destroy actions');
    assert.ok(replaces.length > 0, 'Should have replace actions');
  });

  test('extracts resource address correctly', () => {
    const planJson = loadFixture('realistic');
    const resources = parseJsonPlan(planJson);

    const acrResource = resources.find(r => r.address.includes('acr'));
    assert.ok(acrResource);
    assert.strictEqual(acrResource.address, 'module.acr.azurerm_container_registry.acr');
  });

  test('extracts resource type and name', () => {
    const planJson = loadFixture('create-only');
    const resources = parseJsonPlan(planJson);

    const webInstance = resources.find(r => r.name === 'web');
    assert.ok(webInstance);
    assert.strictEqual(webInstance.type, 'aws_instance');
  });

  test('generates details for resources', () => {
    const planJson = loadFixture('realistic');
    const resources = parseJsonPlan(planJson);

    resources.forEach(r => {
      assert.ok(typeof r.details === 'string');
      assert.ok(r.details.length > 0);
      assert.ok(r.details.includes('resource'));
    });
  });
});

describe('calculateSummary', () => {
  test('calculates summary for empty resources', () => {
    const summary = calculateSummary([]);
    assert.strictEqual(summary.add, 0);
    assert.strictEqual(summary.change, 0);
    assert.strictEqual(summary.destroy, 0);
    assert.strictEqual(summary.has_changes, false);
  });

  test('calculates summary for create-only plan', () => {
    const resources = [
      { action: 'create' },
      { action: 'create' },
      { action: 'create' }
    ];
    const summary = calculateSummary(resources);

    assert.strictEqual(summary.add, 3);
    assert.strictEqual(summary.change, 0);
    assert.strictEqual(summary.destroy, 0);
    assert.strictEqual(summary.has_changes, true);
  });

  test('calculates summary for mixed actions', () => {
    const resources = [
      { action: 'create' },
      { action: 'update' },
      { action: 'update' },
      { action: 'destroy' },
      { action: 'replace' }
    ];
    const summary = calculateSummary(resources);

    assert.strictEqual(summary.add, 1);
    assert.strictEqual(summary.change, 3); // updates + replaces
    assert.strictEqual(summary.destroy, 1);
    assert.strictEqual(summary.has_changes, true);
  });

  test('calculates summary from realistic fixture', () => {
    const planJson = loadFixture('realistic');
    const resources = parseJsonPlan(planJson);
    const summary = calculateSummary(resources);

    // Based on the realistic fixture: 8 creates, many updates, 1 destroy, 1 replace
    assert.ok(summary.add > 0);
    assert.ok(summary.change > 0);
    assert.ok(summary.destroy > 0);
    assert.strictEqual(summary.has_changes, true);
  });
});

describe('groupResourcesByAction', () => {
  test('groups resources correctly', () => {
    const resources = [
      { address: 'a', action: 'create' },
      { address: 'b', action: 'update' },
      { address: 'c', action: 'destroy' },
      { address: 'd', action: 'replace' },
      { address: 'e', action: 'create' }
    ];

    const grouped = groupResourcesByAction(resources);

    assert.strictEqual(grouped.creates.length, 2);
    assert.strictEqual(grouped.updates.length, 1);
    assert.strictEqual(grouped.destroys.length, 1);
    assert.strictEqual(grouped.replaces.length, 1);
  });

  test('handles empty resources', () => {
    const grouped = groupResourcesByAction([]);

    assert.strictEqual(grouped.creates.length, 0);
    assert.strictEqual(grouped.updates.length, 0);
    assert.strictEqual(grouped.destroys.length, 0);
    assert.strictEqual(grouped.replaces.length, 0);
  });
});

// Run tests and report results
console.log('\n========================================');
console.log('Terraform Plan Parser - Unit Tests');
console.log('========================================');

// Print summary
console.log('\n========================================');
console.log(`Results: ${testsPassed} passed, ${testsFailed} failed`);
console.log('========================================\n');

process.exit(testsFailed > 0 ? 1 : 0);
