/**
 * Unit Tests for Plan Parser Module
 */

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const {
  parseJsonPlan,
  calculateSummary,
  groupResourcesByAction,
  determineActionType,
  shouldIncludeChange,
  parseResourceChange
} = require('../src/plan-parser');

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

describe('Plan Parser Module', () => {
  describe('determineActionType', () => {
    test('returns replace for delete+create actions', () => {
      assert.strictEqual(determineActionType(['delete', 'create']), 'replace');
      assert.strictEqual(determineActionType(['create', 'delete']), 'replace');
    });

    test('returns create for create action', () => {
      assert.strictEqual(determineActionType(['create']), 'create');
      assert.strictEqual(determineActionType(['create', 'no-op']), 'create');
    });

    test('returns update for update action', () => {
      assert.strictEqual(determineActionType(['update']), 'update');
      assert.strictEqual(determineActionType(['update', 'no-op']), 'update');
    });

    test('returns destroy for delete action', () => {
      assert.strictEqual(determineActionType(['delete']), 'destroy');
      assert.strictEqual(determineActionType(['delete', 'no-op']), 'destroy');
    });

    test('returns read for unknown/no-op action', () => {
      assert.strictEqual(determineActionType(['read']), 'read');
      assert.strictEqual(determineActionType(['no-op']), 'read');
    });
  });

  describe('shouldIncludeChange', () => {
    test('returns false for null change', () => {
      assert.strictEqual(shouldIncludeChange({ change: null }), false);
    });

    test('returns false for missing change', () => {
      assert.strictEqual(shouldIncludeChange({}), false);
    });

    test('returns false for missing actions', () => {
      assert.strictEqual(shouldIncludeChange({ change: {} }), false);
    });

    test('returns true for create action', () => {
      assert.strictEqual(shouldIncludeChange({ change: { actions: ['create'] } }), true);
    });

    test('returns true for update action', () => {
      assert.strictEqual(shouldIncludeChange({ change: { actions: ['update'] } }), true);
    });

    test('returns false for no-op action', () => {
      assert.strictEqual(shouldIncludeChange({ change: { actions: ['no-op'] } }), false);
    });

    test('returns false for mixed action including no-op', () => {
      // If actions include 'no-op', it should be excluded
      assert.strictEqual(shouldIncludeChange({ change: { actions: ['create', 'no-op'] } }), false);
    });
  });

  describe('parseResourceChange', () => {
    test('returns null for no-op change', () => {
      const change = {
        type: 'aws_instance',
        name: 'web',
        change: { actions: ['no-op'] }
      };
      assert.strictEqual(parseResourceChange(change), null);
    });

    test('parses create change correctly', () => {
      const change = {
        address: 'aws_instance.web',
        type: 'aws_instance',
        name: 'web',
        change: {
          actions: ['create'],
          before: null,
          after: { ami: 'ami-123' },
          after_unknown: {}
        }
      };

      const result = parseResourceChange(change);
      assert.strictEqual(result.address, 'aws_instance.web');
      assert.strictEqual(result.type, 'aws_instance');
      assert.strictEqual(result.name, 'web');
      assert.strictEqual(result.action, 'create');
      assert.ok(typeof result.details === 'string');
    });

    test('parses update change correctly', () => {
      const change = {
        address: 'aws_instance.web',
        type: 'aws_instance',
        name: 'web',
        change: {
          actions: ['update'],
          before: { instance_type: 't2.micro' },
          after: { instance_type: 't2.small' },
          after_unknown: {}
        }
      };

      const result = parseResourceChange(change);
      assert.strictEqual(result.action, 'update');
      assert.ok(result.details.includes('~ resource'));
    });

    test('parses destroy change correctly', () => {
      const change = {
        address: 'aws_instance.web',
        type: 'aws_instance',
        name: 'web',
        change: {
          actions: ['delete'],
          before: { ami: 'ami-123' },
          after: null,
          after_unknown: {}
        }
      };

      const result = parseResourceChange(change);
      assert.strictEqual(result.action, 'destroy');
      assert.ok(result.details.includes('- resource'));
    });

    test('parses replace change correctly', () => {
      const change = {
        address: 'aws_instance.web',
        type: 'aws_instance',
        name: 'web',
        change: {
          actions: ['delete', 'create'],
          before: { ami: 'mi-old' },
          after: { ami: 'ami-new' },
          after_unknown: {}
        }
      };

      const result = parseResourceChange(change);
      assert.strictEqual(result.action, 'replace');
      assert.ok(result.details.includes('-/+ resource'));
    });

    test('generates details string', () => {
      const change = {
        address: 'aws_instance.web',
        type: 'aws_instance',
        name: 'web',
        change: {
          actions: ['create'],
          before: null,
          after: { ami: 'ami-123' },
          after_unknown: {}
        }
      };

      const result = parseResourceChange(change);
      assert.ok(typeof result.details === 'string');
      assert.ok(result.details.length > 0);
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

    test('parses plan without resource_changes key', () => {
      const resources = parseJsonPlan(JSON.stringify({ format_version: '0.2' }));
      assert.strictEqual(resources.length, 0);
    });

    test('parses invalid JSON', () => {
      const resources = parseJsonPlan('invalid json');
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

      assert.ok(resources.length > 0);
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

    test('generates details for all resources', () => {
      const planJson = loadFixture('realistic');
      const resources = parseJsonPlan(planJson);

      resources.forEach(r => {
        assert.ok(typeof r.details === 'string', `Details should be string for ${r.address}`);
        assert.ok(r.details.length > 0, `Details should not be empty for ${r.address}`);
        assert.ok(r.details.includes('resource'), `Details should include 'resource' for ${r.address}`);
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

    test('calculates summary for update-only plan', () => {
      const resources = [
        { action: 'update' },
        { action: 'update' }
      ];
      const summary = calculateSummary(resources);

      assert.strictEqual(summary.add, 0);
      assert.strictEqual(summary.change, 2);
      assert.strictEqual(summary.destroy, 0);
      assert.strictEqual(summary.has_changes, true);
    });

    test('calculates summary for destroy-only plan', () => {
      const resources = [
        { action: 'destroy' },
        { action: 'destroy' }
      ];
      const summary = calculateSummary(resources);

      assert.strictEqual(summary.add, 0);
      assert.strictEqual(summary.change, 0);
      assert.strictEqual(summary.destroy, 2);
      assert.strictEqual(summary.has_changes, true);
    });

    test('calculates summary for replace-only plan', () => {
      const resources = [
        { action: 'replace' },
        { action: 'replace' }
      ];
      const summary = calculateSummary(resources);

      assert.strictEqual(summary.add, 0);
      assert.strictEqual(summary.change, 2); // replaces count as changes
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

      // Based on the realistic fixture
      assert.ok(summary.add > 0);
      assert.ok(summary.change > 0);
      assert.ok(summary.destroy > 0);
      assert.strictEqual(summary.has_changes, true);
    });

    test('includes create-only fixture correctly', () => {
      const planJson = loadFixture('create-only');
      const resources = parseJsonPlan(planJson);
      const summary = calculateSummary(resources);

      assert.ok(summary.add > 0);
      assert.strictEqual(summary.change, 0);
      assert.strictEqual(summary.destroy, 0);
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
      assert.ok(grouped.creates.some(r => r.address === 'a'));
      assert.ok(grouped.creates.some(r => r.address === 'e'));

      assert.strictEqual(grouped.updates.length, 1);
      assert.strictEqual(grouped.updates[0].address, 'b');

      assert.strictEqual(grouped.destroys.length, 1);
      assert.strictEqual(grouped.destroys[0].address, 'c');

      assert.strictEqual(grouped.replaces.length, 1);
      assert.strictEqual(grouped.replaces[0].address, 'd');
    });

    test('handles empty resources', () => {
      const grouped = groupResourcesByAction([]);

      assert.strictEqual(grouped.creates.length, 0);
      assert.strictEqual(grouped.updates.length, 0);
      assert.strictEqual(grouped.destroys.length, 0);
      assert.strictEqual(grouped.replaces.length, 0);
    });

    test('groups realistic fixture correctly', () => {
      const planJson = loadFixture('realistic');
      const resources = parseJsonPlan(planJson);
      const grouped = groupResourcesByAction(resources);

      // Verify grouping worked
      const allResources = [
        ...grouped.creates,
        ...grouped.updates,
        ...grouped.destroys,
        ...grouped.replaces
      ];

      assert.strictEqual(allResources.length, resources.length);

      // Verify resources in correct groups
      assert.ok(grouped.creates.every(r => r.action === 'create'));
      assert.ok(grouped.updates.every(r => r.action === 'update'));
      assert.ok(grouped.destroys.every(r => r.action === 'destroy'));
      assert.ok(grouped.replaces.every(r => r.action === 'replace'));
    });

    test('preserves original resource objects', () => {
      const resources = [
        {
          address: 'test',
          action: 'create',
          type: 'aws_instance',
          details: 'test details'
        }
      ];

      const grouped = groupResourcesByAction(resources);

      assert.strictEqual(grouped.creates[0].address, 'test');
      assert.strictEqual(grouped.creates[0].type, 'aws_instance');
      assert.strictEqual(grouped.creates[0].details, 'test details');
      assert.ok(typeof grouped.creates[0].details === 'string');
    });
  });
});

console.log('\n========================================');
console.log(`Results: ${testsPassed} passed, ${testsFailed} failed`);
console.log('========================================\n');

process.exit(testsFailed > 0 ? 1 : 0);
