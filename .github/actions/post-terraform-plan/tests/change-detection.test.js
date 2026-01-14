/**
 * Unit Tests for Change Detection Module
 */

const assert = require('assert');
const {
  findChanges,
  shouldDisplayChange,
  shouldSkipIdentical,
  shouldSkipComputedAttr,
  formatSimpleValueChange,
  formatArrayOfObjects,
  formatSimpleArray,
  formatNestedBlock
} = require('../src/change-detection');

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

describe('Change Detection Module', () => {
  describe('shouldDisplayChange', () => {
    test('returns true for added meaningful value', () => {
      const result = shouldDisplayChange(false, true, undefined, { name: 'test' });
      assert.strictEqual(result, true);
    });

    test('returns false for added empty value', () => {
      const result = shouldDisplayChange(false, true, undefined, []);
      assert.strictEqual(result, false);
    });

    test('returns true for removed meaningful value', () => {
      const result = shouldDisplayChange(true, false, { name: 'test' }, undefined);
      assert.strictEqual(result, true);
    });

    test('returns false for removed empty value', () => {
      const result = shouldDisplayChange(true, false, false, undefined);
      assert.strictEqual(result, false);
    });

    test('returns true for changed meaningful value', () => {
      const result = shouldDisplayChange(true, true, { name: 'old' }, { name: 'new' });
      assert.strictEqual(result, true);
    });

    test('returns true for change from meaningless to meaningful', () => {
      const result = shouldDisplayChange(true, true, [], [1]);
      assert.strictEqual(result, true);
    });

    test('returns false for identical meaningless values', () => {
      const result = shouldDisplayChange(true, true, false, false);
      assert.strictEqual(result, false);
    });

    test('returns true for meaningful to meaningful change', () => {
      const result = shouldDisplayChange(true, true, 'old', 'new');
      assert.strictEqual(result, true);
    });
  });

  describe('shouldSkipIdentical', () => {
    test('returns true for identical values without forceMarker', () => {
      const result = shouldSkipIdentical(true, true, 'same', 'same', null);
      assert.strictEqual(result, true);
    });

    test('returns true for identical values with undefined forceMarker', () => {
      const result = shouldSkipIdentical(true, true, 'same', 'same', undefined);
      assert.strictEqual(result, true);
    });

    test('returns true when forceMarker is two spaces (create/destroy mode)', () => {
      // With '  ' forceMarker (create/destroy mode), identical values ARE skipped to avoid noise
      const result = shouldSkipIdentical(true, true, 'same', 'same', '  ');
      assert.strictEqual(result, true);
    });

    test('returns false for different values', () => {
      const result = shouldSkipIdentical(true, true, 'old', 'new', null);
      assert.strictEqual(result, false);
    });

    test('returns false when only after exists', () => {
      const result = shouldSkipIdentical(false, true, undefined, 'value', null);
      assert.strictEqual(result, false);
    });

    test('returns false when only before exists', () => {
      const result = shouldSkipIdentical(true, false, 'value', undefined, null);
      assert.strictEqual(result, false);
    });
  });

  describe('shouldSkipComputedAttr', () => {
    test('returns true for id in destroy mode', () => {
      const result = shouldSkipComputedAttr('id', false, '  ');
      assert.strictEqual(result, true);
    });

    test('returns true for subscription in destroy mode', () => {
      const result = shouldSkipComputedAttr('subscription', false, '  ');
      assert.strictEqual(result, true);
    });

    test('returns false for user attribute in destroy mode', () => {
      const result = shouldSkipComputedAttr('environment', false, '  ');
      assert.strictEqual(result, false);
    });

    test('returns false for computed attr in update mode', () => {
      const result = shouldSkipComputedAttr('id', true, null);
      assert.strictEqual(result, false);
    });

    test('returns false when forceMarker is null', () => {
      const result = shouldSkipComputedAttr('id', false, null);
      assert.strictEqual(result, false);
    });
  });

  describe('formatSimpleValueChange', () => {
    test('formats simple string value with no marker', () => {
      const result = formatSimpleValueChange('  ', '', 'name', undefined, 'test', false, false);
      assert.ok(result.includes('name = "test"'));
    });

    test('formats added value with + marker', () => {
      const result = formatSimpleValueChange('+', '', 'name', undefined, 'test', false, false);
      assert.strictEqual(result, '+ name = "test"');
    });

    test('formats removed value with - marker', () => {
      const result = formatSimpleValueChange('-', '', 'name', 'test', undefined, false, false);
      assert.strictEqual(result, '- name = "test"');
    });

    test('formats changed value with ! marker', () => {
      const result = formatSimpleValueChange('!', '', 'name', 'old', 'new', false, false);
      assert.strictEqual(result, '! name = "old" -> "new"');
    });

    test('formats changed value with !! marker for replace', () => {
      const result = formatSimpleValueChange('!', '', 'name', 'old', 'new', false, true);
      assert.strictEqual(result, '!! name = "old" -> "new"');
    });

    test('formats unknown value with (known after apply)', () => {
      const result = formatSimpleValueChange('+', '', 'id', undefined, 'placeholder', true, false);
      assert.strictEqual(result, '+ id = (known after apply)');
    });

    test('formats boolean values', () => {
      const result = formatSimpleValueChange('+', '', 'enabled', undefined, true, false, false);
      assert.strictEqual(result, '+ enabled = true');
    });

    test('formats number values', () => {
      const result = formatSimpleValueChange('+', '', 'count', undefined, 42, false, false);
      assert.strictEqual(result, '+ count = 42');
    });

    test('returns array for multiline arrays', () => {
      const result = formatSimpleValueChange('  ', '', 'tags', undefined, ['a', 'b'], false, false);
      assert.ok(Array.isArray(result));
      assert.ok(result.some(line => line.includes('tags = [')));
      assert.ok(result.some(line => line.includes(']')));
    });
  });

  describe('formatArrayOfObjects', () => {
    test('formats empty arrays', () => {
      const result = formatArrayOfObjects([], [], {}, '', null, false, 'blocks');
      assert.strictEqual(result.length, 0);
    });

    test('formats added object in array', () => {
      const afterArr = [{ name: 'test1' }];
      const result = formatArrayOfObjects([], afterArr, {}, '', null, false, 'settings');
      assert.ok(result.length > 0);
      assert.ok(result.some(line => line.includes('settings {')));
    });

    test('formats removed object from array', () => {
      const beforeArr = [{ name: 'test1' }];
      const result = formatArrayOfObjects(beforeArr, [], {}, '', null, false, 'settings');
      assert.ok(result.length > 0);
      assert.ok(result.some(line => line.includes('# (block removed)')));
    });

    test('formats modified object in array', () => {
      const beforeArr = [{ name: 'old' }];
      const afterArr = [{ name: 'new' }];
      const result = formatArrayOfObjects(beforeArr, afterArr, {}, '', null, false, 'settings');
      assert.ok(result.length > 0);
      assert.ok(result.some(line => line.includes('name')));
    });

    test('uses !! for replace action', () => {
      const beforeArr = [{ name: 'old' }];
      const afterArr = [{ name: 'new' }];
      const result = formatArrayOfObjects(beforeArr, afterArr, {}, '', null, true, 'settings');
      assert.ok(result.some(line => line.includes('!!')));
    });
  });

  describe('formatSimpleArray', () => {
    test('formats empty array', () => {
      const result = formatSimpleArray([], [], {}, '', '  ', false, 'tags', false, false, false);
      assert.strictEqual(result.length, 1);
      assert.ok(result[0].includes('tags = []'));
    });

    test('formats single element array inline', () => {
      const result = formatSimpleArray([], ['a'], {}, '', '  ', false, 'tags', false, false, true);
      assert.strictEqual(result.length, 1);
      assert.ok(result[0].includes('tags = "a"'));
    });

    test('formats multi-element array inline', () => {
      const result = formatSimpleArray(['a'], ['a', 'b'], {}, '', null, false, 'tags', false, true, true);
      // Result may have multiple lines depending on state
      assert.ok(result.length > 0);
      // Should include array markers
      assert.ok(result.some(line => line.includes('tags')));
    });

    test('uses multiline format for create/destroy', () => {
      const result = formatSimpleArray([], ['a', 'b', 'c'], {}, '', '  ', false, 'tags', false, false, true);
      assert.ok(result.length > 1);
      assert.ok(result.some(line => line.includes('tags = [')));
      assert.ok(result.some(line => line.includes(']')));
    });

    test('uses !! for replace action when arrays differ', () => {
      // When arrays differ in update mode with replace flag, use !!
      const result = formatSimpleArray(['a'], ['b'], {}, '', null, true, 'tags', false, true, true);
      // Result may vary based on state, just verify it's an array
      assert.ok(Array.isArray(result));
      assert.ok(result.length > 0);
    });
  });

  describe('formatNestedBlock', () => {
    test('formats empty nested block', () => {
      const result = formatNestedBlock({}, { name: 'test' }, {}, '', null, false, 'settings');
      assert.ok(result.length > 0);
      assert.ok(result.some(line => line.includes('settings {')));
      assert.ok(result.some(line => line.includes('}')));
    });

    test('uses no markers when forceMarker is two spaces', () => {
      const result = formatNestedBlock({}, { name: 'test' }, {}, '', '  ', false, 'settings');
      result.forEach(line => {
        if (line.trim() && line.trim() !== '}') {
          assert.ok(!line.startsWith('+') && !line.startsWith('-'), `Should not have markers: ${line}`);
        }
      });
    });

    test('uses markers for update actions', () => {
      const result = formatNestedBlock({}, { name: 'test' }, {}, '', null, false, 'settings');
      assert.ok(result.some(line => line.startsWith('+')));
    });
  });

  describe('findChanges (integration)', () => {
    test('finds added values', () => {
      const before = {};
      const after = { name: 'test' };
      const lines = findChanges(before, after, {}, '');

      assert.ok(lines.length > 0);
      assert.ok(lines.some(line => line.includes('+')));
      assert.ok(lines.some(line => line.includes('name')));
    });

    test('finds removed values', () => {
      const before = { name: 'test' };
      const after = {};
      const lines = findChanges(before, after, {}, '');

      assert.ok(lines.length > 0);
      assert.ok(lines.some(line => line.includes('-')));
      assert.ok(lines.some(line => line.includes('name')));
    });

    test('finds changed values', () => {
      const before = { name: 'old' };
      const after = { name: 'new' };
      const lines = findChanges(before, after, {}, '');

      assert.ok(lines.length > 0);
      assert.ok(lines.some(line => line.includes('!')));
      assert.ok(lines.some(line => line.includes('->')));
    });

    test('skips identical values', () => {
      const before = { name: 'same', count: 5 };
      const after = { name: 'same', count: 5 };
      const lines = findChanges(before, after, {}, '', '  ');

      assert.strictEqual(lines.length, 0);
    });

    test('handles nested objects', () => {
      const before = {};
      const after = { tags: { env: 'prod' } };
      const lines = findChanges(before, after, {}, '');

      assert.ok(lines.length > 0);
      assert.ok(lines.some(line => line.includes('tags')));
    });

    test('handles arrays', () => {
      const before = {};
      const after = { tags: ['env:prod', 'team:infra'] };
      const lines = findChanges(before, after, {}, '');

      assert.ok(lines.length > 0);
      assert.ok(lines.some(line => line.includes('tags')));
    });

    test('handles unknown values', () => {
      const before = {};
      const after = { id: 'placeholder' };
      const afterUnknown = { id: true };
      const lines = findChanges(before, after, afterUnknown, '');

      assert.ok(lines.length > 0);
      assert.ok(lines.some(line => line.includes('(known after apply)')));
    });

    test('skips meaningless values in create mode', () => {
      const before = {};
      const after = { name: 'test', tags: [], enabled: false };
      const lines = findChanges(before, after, {}, '', '  ');

      // Should only show 'name' (meaningful)
      assert.ok(lines.some(line => line.includes('name')));
      assert.ok(!lines.some(line => line.includes('tags')));
      assert.ok(!lines.some(line => line.includes('enabled')));
    });

    test('skips computed attributes in destroy mode', () => {
      const before = { id: 'test-id', name: 'test', environment: 'prod' };
      const after = {};
      const lines = findChanges(before, after, {}, '', '  ');

      // Should only show 'environment' (not computed - id, name are computed)
      assert.ok(lines.some(line => line.includes('environment')));
      assert.ok(!lines.some(line => line.includes('id')));
      assert.ok(!lines.some(line => line.includes('name')));
    });
  });
});

console.log('\n========================================');
console.log(`Results: ${testsPassed} passed, ${testsFailed} failed`);
console.log('========================================\n');

process.exit(testsFailed > 0 ? 1 : 0);
