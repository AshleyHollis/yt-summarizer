/**
 * Unit Tests for Resource Change Formatter Module
 */

const assert = require('assert');
const {
  formatResourceChange,
  getForceMarkerForAction,
  isReplaceAction
} = require('../src/resource-change-formatter');

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

describe('Resource Change Formatter Module', () => {
  describe('getForceMarkerForAction', () => {
    test('returns two spaces for create action', () => {
      assert.strictEqual(getForceMarkerForAction('create'), '  ');
    });

    test('returns two spaces for destroy action', () => {
      assert.strictEqual(getForceMarkerForAction('destroy'), '  ');
    });

    test('returns null for update action', () => {
      assert.strictEqual(getForceMarkerForAction('update'), null);
    });

    test('returns null for replace action', () => {
      assert.strictEqual(getForceMarkerForAction('replace'), null);
    });
  });

  describe('isReplaceAction', () => {
    test('returns true for replace action', () => {
      assert.strictEqual(isReplaceAction('replace'), true);
    });

    test('returns false for create action', () => {
      assert.strictEqual(isReplaceAction('create'), false);
    });

    test('returns false for update action', () => {
      assert.strictEqual(isReplaceAction('update'), false);
    });

    test('returns false for destroy action', () => {
      assert.strictEqual(isReplaceAction('destroy'), false);
    });
  });

  describe('formatResourceChange', () => {
    test('formats create action with no markers in content', () => {
      const change = {
        type: 'aws_instance',
        name: 'web',
        change: {
          before: null,
          after: { ami: 'ami-123', instance_type: 't2.micro' },
          after_unknown: {}
        }
      };

      const result = formatResourceChange(change, 'create');
      const lines = result.split('\n');

      // Resource header should have + marker
      assert.ok(lines[0].startsWith('+ resource'), 'Create header should have + marker');
      assert.ok(lines[0].includes('aws_instance'));
      assert.ok(lines[0].includes('web'));

      // Content lines should NOT use markers
      lines.slice(1, -1).forEach(line => {
        if (line.trim() !== '' && !line.includes('#')) {
          assert.ok(
            !line.startsWith('+') && !line.startsWith('-') && !line.startsWith('!'),
            `Create content line should NOT have markers: ${line}`
          );
        }
      });

      // Should end with closing brace
      assert.strictEqual(lines[lines.length - 1].trim(), '}');
    });

    test('formats destroy action with no markers in content', () => {
      const change = {
        type: 'aws_instance',
        name: 'web',
        change: {
          before: { ami: 'ami-123', instance_type: 't2.micro' },
          after: null,
          after_unknown: {}
        }
      };

      const result = formatResourceChange(change, 'destroy');
      const lines = result.split('\n');

      // Resource header should have - marker
      assert.ok(lines[0].startsWith('- resource'), 'Destroy header should have - marker');

      // Content lines should NOT use markers
      lines.slice(1, -1).forEach(line => {
        if (line.trim() !== '' && !line.includes('#')) {
          assert.ok(
            !line.startsWith('+') && !line.startsWith('-') && !line.startsWith('!'),
            `Destroy content line should NOT have markers: ${line}`
          );
        }
      });
    });

    test('formats update action with differentiated markers', () => {
      const change = {
        type: 'aws_instance',
        name: 'web',
        change: {
          before: { instance_type: 't2.micro' },
          after: { instance_type: 't2.small' },
          after_unknown: {}
        }
      };

      const result = formatResourceChange(change, 'update');
      const lines = result.split('\n');

      // Header should have ~ marker
      assert.ok(lines[0].startsWith('~ resource'), 'Update header should have ~ marker');

      // Should have ! marker for changed value
      assert.ok(result.includes('!'), 'Update should use ! marker for changed values');
      assert.ok(result.includes('->'), 'Update should show before -> after');
    });

    test('formats update with added value', () => {
      const change = {
        type: 'aws_instance',
        name: 'web',
        change: {
          before: { instance_type: 't2.micro' },
          after: { instance_type: 't2.micro', new_tag: 'added' },
          after_unknown: {}
        }
      };

      const result = formatResourceChange(change, 'update');

      // Should have + for the new value
      assert.ok(result.includes('+'), 'Update should use + for new values');
      assert.ok(result.includes('new_tag'), 'Should include the new attribute');
    });

    test('formats update with removed value', () => {
      const change = {
        type: 'aws_instance',
        name: 'web',
        change: {
          before: { instance_type: 't2.micro', old_tag: 'old' },
          after: { instance_type: 't2.micro' },
          after_unknown: {}
        }
      };

      const result = formatResourceChange(change, 'update');

      // Should have - for the removed value
      assert.ok(result.includes('-'), 'Update should use - for removed values');
      assert.ok(result.includes('old_tag'), 'Should include the removed attribute');
    });

    test('formats replace action with forces replacement comment', () => {
      const change = {
        type: 'aws_instance',
        name: 'web',
        change: {
          before: { ami: 'ami-old' },
          after: { ami: 'ami-new' },
          after_unknown: {}
        }
      };

      const result = formatResourceChange(change, 'replace');
      const lines = result.split('\n');

      // Header should have -/+ marker
      assert.ok(lines[0].startsWith('-/+ resource'), 'Replace header should have -/+ marker');
      assert.ok(
        !lines[0].startsWith('! resource'),
        'Replace header should NOT have ! marker'
      );

      // Should include forces replacement comment
      assert.ok(
        result.includes('# forces replacement'),
        'Replace should include replacement comment'
      );

      // Should use !! for changed attributes
      assert.ok(result.includes('!!'), 'Replace should use !! for changed attributes');
    });

    test('formats replace with multiple changes', () => {
      const change = {
        type: 'aws_instance',
        name: 'web',
        change: {
          before: { ami: 'ami-old', instance_type: 't2.micro' },
          after: { ami: 'ami-new', instance_type: 't2.micro' },
          after_unknown: {}
        }
      };

      const result = formatResourceChange(change, 'replace');

      // Should have # forces replacement comment
      assert.ok(result.includes('# forces replacement'));

      // Replace actions use !! for changed attributes
      assert.ok(result.includes('!!'), 'Replace should use !! for changed attributes');
      assert.ok(!result.includes('! resource'), 'Replace header should NOT have ! marker');
    });

    test('handles complex nested structures', () => {
      const change = {
        type: 'aws_instance',
        name: 'web',
        change: {
          before: {
            tags: { Environment: 'dev' }
          },
          after: {
            tags: { Environment: 'prod', Team: 'infra' }
          },
          after_unknown: {}
        }
      };

      const result = formatResourceChange(change, 'update');

      // Should include nested block
      assert.ok(result.includes('tags'), 'Should include nested tags block');
      assert.ok(result.includes('Environment'), 'Should include nested Environment attribute');
      assert.ok(result.includes('Team'), 'Should include nested Team attribute');
    });

    test('handles arrays in changes', () => {
      const change = {
        type: 'aws_instance',
        name: 'web',
        change: {
          before: {
            tags: ['env:dev']
          },
          after: {
            tags: ['env:prod', 'team:infra']
          },
          after_unknown: {}
        }
      };

      const result = formatResourceChange(change, 'update');

      // Should include array formatting
      const lines = result.split('\n');
      assert.ok(lines.some(line => line.includes('tags')), 'Should include tags array');
      // Arrays are formatted inline for updates showing diff
      assert.ok(result.includes('env:dev') || result.includes('env:prod'), 'Should include array value');
    });

    test('handles null/undefined change values', () => {
      const change = {
        type: 'aws_instance',
        name: 'web',
        change: {
          before: null,
          after: { ami: 'ami-123' },
          after_unknown: null
        }
      };

      const result = formatResourceChange(change, 'create');

      // Should handle gracefully
      assert.ok(result.includes('aws_instance'));
      assert.ok(result.includes('web'));
      assert.ok(result.includes('ami'));
    });

    test('includes all three marker types in update', () => {
      const change = {
        type: 'aws_instance',
        name: 'web',
        change: {
          before: {
            instance_type: 't2.micro',
            old_tag: 'old',
            unchanged: 'same'
          },
          after: {
            instance_type: 't2.small',
            new_tag: 'new',
            unchanged: 'same'
          },
          after_unknown: {}
        }
      };

      const result = formatResourceChange(change, 'update');

      // Should have + for new_tag
      assert.ok(result.includes('+ ') && result.includes('new_tag'), 'Should use + for new values');

      // Should have - for old_tag
      assert.ok(result.includes('- ') && result.includes('old_tag'), 'Should use - for old values');

      // Should have ! for changed instance_type
      assert.ok(result.includes('! ') && result.includes('instance_type'), 'Should use ! for changed values');

      // Should NOT show unchanged
      assert.ok(!result.includes('unchanged'), 'Should skip unchanged values');
    });

    test('properly outputs closing brace', () => {
      const change = {
        type: 'aws_instance',
        name: 'web',
        change: {
          before: null,
          after: { ami: 'ami-123' },
          after_unknown: {}
        }
      };

      const result = formatResourceChange(change, 'create');
      const lines = result.split('\n');

      // Last line should be closing brace
      assert.strictEqual(lines[lines.length - 1].trim(), '}', 'Should end with closing brace');
    });
  });
});

console.log('\n========================================');
console.log(`Results: ${testsPassed} passed, ${testsFailed} failed`);
console.log('========================================\n');

process.exit(testsFailed > 0 ? 1 : 0);
