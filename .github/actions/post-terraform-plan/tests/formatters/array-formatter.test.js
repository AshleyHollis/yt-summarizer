/**
 * Unit Tests for Array Formatter Module
 */

const assert = require('assert');
const { formatMultilineArray, formatInlineArray } = require('../../src/formatters/array-formatter');

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

describe('Array Formatter Module', () => {
  describe('formatMultilineArray', () => {
    test('formats empty array with marker', () => {
      const result = formatMultilineArray([], '    ', 'tags', '+');
      assert.strictEqual(result.length, 1);
      assert.strictEqual(result[0], '+     tags = []');
    });

    test('formats single element array', () => {
      const result = formatMultilineArray(['a'], '    ', 'tags', '+');
      assert.strictEqual(result.length, 3);
      assert.ok(result[0].includes('tags = ['));
      assert.ok(result[1].includes('"a",'));
      assert.ok(result[2].includes(']'));
    });

    test('formats multiple elements with proper indentation', () => {
      const result = formatMultilineArray(['a', 'b', 'c'], '    ', 'tags', '+');
      assert.strictEqual(result.length, 5);
      assert.ok(result[0].includes('tags = ['));
      assert.ok(result[1].includes('"a",'));
      assert.ok(result[2].includes('"b",'));
      assert.ok(result[3].includes('"c",'));
      assert.ok(result[4].includes(']'));
    });

    test('aligns closing bracket with opening line', () => {
      const result = formatMultilineArray(['env:prod'], '      ', 'tags', '  ');
      assert.strictEqual(result.length, 3);
      // Closing bracket should align with opening content
      const openingLine = result[0];
      const closingLine = result[2];
      assert.ok(openingLine.includes('tags = ['));
      assert.ok(closingLine.includes(']'));
      // Both should start with the same marker and prefix
      assert.ok(openingLine.startsWith('       '));
      assert.ok(closingLine.startsWith('       '));
    });

    test('uses correct marker for each line', () => {
      const result = formatMultilineArray(['a', 'b'], '    ', 'tags', '+');
      result.forEach(line => {
        // Non-empty lines should have the marker
        if (line.trim()) {
          assert.ok(line.includes('+'), 'Each line should include the marker');
        }
      });
    });

    test('formats numeric values', () => {
      const result = formatMultilineArray([1, 2, 3], '    ', 'counts', '!');
      assert.strictEqual(result.length, 5);
      assert.ok(result[1].includes('1,'));
      assert.ok(result[2].includes('2,'));
      assert.ok(result[3].includes('3,'));
    });

    test('formats boolean values', () => {
      const result = formatMultilineArray([true, false], '    ', 'flags', '!!');
      assert.strictEqual(result.length, 4);
      assert.ok(result[1].includes('true,'));
      assert.ok(result[2].includes('false,'));
    });
  });

  describe('formatInlineArray', () => {
    test('formats empty array', () => {
      const result = formatInlineArray([], '+', '    ', 'tags');
      assert.strictEqual(result, '+     tags = []');
    });

    test('formats single element array inline', () => {
      const result = formatInlineArray(['a'], '+', '    ', 'tags');
      assert.strictEqual(result, '+     tags = "a"');
    });

    test('formats single element with marker', () => {
      const result = formatInlineArray(['test'], '-', '    ', 'labels', false);
      assert.strictEqual(result, '-     labels = "test"');
    });

    test('formats single element with unknown flag', () => {
      const result = formatInlineArray(['test'], '+', '    ', 'id', true);
      assert.strictEqual(result, '+     id = (known after apply)');
    });

    test('formats multi-element array inline as JSON', () => {
      const result = formatInlineArray(['a', 'b', 'c'], '!', '    ', 'items', false);
      assert.strictEqual(result, '!     items = ["a","b","c"]');
    });

    test('uses provided marker correctly', () => {
      const addResult = formatInlineArray(['a'], '+', '  ', 'tags');
      const removeResult = formatInlineArray(['a'], '-', '  ', 'tags');
      const modResult = formatInlineArray(['a'], '!', '  ', 'tags');

      assert.ok(addResult.startsWith('+'));
      assert.ok(removeResult.startsWith('-'));
      assert.ok(modResult.startsWith('!'));
    });

    test('includes prefix indentation', () => {
      const result = formatInlineArray(['a'], '+', '    ', 'tags');
      assert.ok(result.substring(1, 5) === '    ', 'Should include 4-space indentation');
    });

    test('includes key name', () => {
      const result = formatInlineArray(['a'], '+', '    ', 'custom_key');
      assert.ok(result.includes('custom_key'), 'Should include the key name');
    });
  });
});

console.log('\n========================================');
console.log(`Results: ${testsPassed} passed, ${testsFailed} failed`);
console.log('========================================\n');

process.exit(testsFailed > 0 ? 1 : 0);
