/**
 * Unit Tests for Value Formatter Module
 */

const assert = require('assert');
const { formatValue } = require('../../src/formatters/value-formatter');

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

describe('Value Formatter Module', () => {
  describe('formatValue', () => {
    test('returns (known after apply) for unknown values', () => {
      assert.strictEqual(formatValue('anything', true), '(known after apply)');
    });

    test('formats null as string "null"', () => {
      assert.strictEqual(formatValue(null), 'null');
    });

    test('formats undefined as string "null"', () => {
      assert.strictEqual(formatValue(undefined), 'null');
    });

    test('formats strings with quotes', () => {
      assert.strictEqual(formatValue('hello'), '"hello"');
      assert.strictEqual(formatValue(''), '""');
      assert.strictEqual(formatValue('test string'), '"test string"');
    });

    test('formats booleans as strings', () => {
      assert.strictEqual(formatValue(true), 'true');
      assert.strictEqual(formatValue(false), 'false');
    });

    test('formats numbers as strings', () => {
      assert.strictEqual(formatValue(42), '42');
      assert.strictEqual(formatValue(3.14), '3.14');
      assert.strictEqual(formatValue(0), '0');
      assert.strictEqual(formatValue(-1), '-1');
    });

    test('formats empty arrays', () => {
      assert.strictEqual(formatValue([]), '[]');
    });

    test('formats simple arrays as JSON', () => {
      assert.strictEqual(formatValue([1, 2, 3]), '[1,2,3]');
      assert.strictEqual(formatValue(['a', 'b']), '["a","b"]');
      assert.strictEqual(formatValue([true, false]), '[true,false]');
    });

    test('formats nested arrays as JSON', () => {
      assert.strictEqual(formatValue([[1, 2], [3, 4]]), '[[1,2],[3,4]]');
    });

    test('formats empty objects', () => {
      assert.strictEqual(formatValue({}), '{}');
    });

    test('formats simple objects as JSON', () => {
      assert.strictEqual(formatValue({ a: 1 }), '{"a":1}');
      assert.strictEqual(formatValue({ name: 'test' }), '{"name":"test"}');
    });

    test('formats nested objects as JSON', () => {
      assert.strictEqual(formatValue({ nested: { a: 1 } }), '{"nested":{"a":1}}');
    });

    test('handles complex nested structures', () => {
      const result = formatValue({ arr: [1, 2], obj: { key: 'value' } });
      assert.strictEqual(result, '{"arr":[1,2],"obj":{"key":"value"}}');
    });

    test('formats special characters in strings', () => {
      const result = formatValue('test"quote');
      assert.ok(result.includes('test'));
      assert.ok(result.includes('quote'));
      assert.strictEqual(result.charAt(0), '"');
      assert.strictEqual(result.charAt(result.length - 1), '"');
    });
  });
});

console.log('\n========================================');
console.log(`Results: ${testsPassed} passed, ${testsFailed} failed`);
console.log('========================================\n');

process.exit(testsFailed > 0 ? 1 : 0);
