/**
 * Unit Tests for Value Validator Module
 */

const assert = require('assert');
const {
  isMeaningfulValue,
  areValuesEquivalent,
  isEmpty,
  isArrayofObjects,
  isComputedAttribute
} = require('../src/utils/value-validator');

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

describe('Value Validator Module', () => {
  describe('isMeaningfulValue', () => {
    test('returns false for null', () => {
      assert.strictEqual(isMeaningfulValue(null), false);
    });

    test('returns false for undefined', () => {
      assert.strictEqual(isMeaningfulValue(undefined), false);
    });

    test('returns false for empty arrays', () => {
      assert.strictEqual(isMeaningfulValue([]), false);
    });

    test('returns false for empty objects', () => {
      assert.strictEqual(isMeaningfulValue({}), false);
    });

    test('returns false for false boolean', () => {
      assert.strictEqual(isMeaningfulValue(false), false);
    });

    test('returns true for true boolean', () => {
      assert.strictEqual(isMeaningfulValue(true), true);
    });

    test('returns false for empty string', () => {
      assert.strictEqual(isMeaningfulValue(''), false);
    });

    test('returns true for non-empty string', () => {
      assert.strictEqual(isMeaningfulValue('test'), true);
    });

    test('returns true for non-empty array', () => {
      assert.strictEqual(isMeaningfulValue([1, 2, 3]), true);
    });

    test('returns true for non-empty object', () => {
      assert.strictEqual(isMeaningfulValue({ a: 1 }), true);
    });

    test('returns true for numbers', () => {
      assert.strictEqual(isMeaningfulValue(0), true);
      assert.strictEqual(isMeaningfulValue(42), true);
      assert.strictEqual(isMeaningfulValue(-1), true);
    });
  });

  describe('areValuesEquivalent', () => {
    test('returns true for identical primitives', () => {
      assert.strictEqual(areValuesEquivalent('test', 'test'), true);
      assert.strictEqual(areValuesEquivalent(42, 42), true);
      assert.strictEqual(areValuesEquivalent(true, true), true);
      assert.strictEqual(areValuesEquivalent(null, null), true);
    });

    test('returns false for different primitives', () => {
      assert.strictEqual(areValuesEquivalent('test', 'other'), false);
      assert.strictEqual(areValuesEquivalent(42, 43), false);
      assert.strictEqual(areValuesEquivalent(true, false), false);
    });

    test('returns true for identical arrays', () => {
      assert.strictEqual(areValuesEquivalent([1, 2, 3], [1, 2, 3]), true);
    });

    test('returns false for different arrays', () => {
      assert.strictEqual(areValuesEquivalent([1, 2, 3], [1, 2, 4]), false);
    });

    test('returns true for identical objects', () => {
      assert.strictEqual(areValuesEquivalent({ a: 1, b: 2 }, { a: 1, b: 2 }), true);
    });

    test('returns false for different objects', () => {
      assert.strictEqual(areValuesEquivalent({ a: 1 }, { b: 1 }), false);
    });

    test('handles nested objects', () => {
      assert.strictEqual(
        areValuesEquivalent({ nested: { a: 1 } }, { nested: { a: 1 } }),
        true
      );
    });
  });

  describe('isEmpty', () => {
    test('returns true for null', () => {
      assert.strictEqual(isEmpty(null), true);
    });

    test('returns true for undefined', () => {
      assert.strictEqual(isEmpty(undefined), true);
    });

    test('returns true for empty array', () => {
      assert.strictEqual(isEmpty([]), true);
    });

    test('returns true for empty object', () => {
      assert.strictEqual(isEmpty({}), true);
    });

    test('returns false for non-empty array', () => {
      assert.strictEqual(isEmpty([1]), false);
    });

    test('returns false for non-empty object', () => {
      assert.strictEqual(isEmpty({ a: 1 }), false);
    });

    test('returns false for primitives', () => {
      assert.strictEqual(isEmpty(0), false);
      assert.strictEqual(isEmpty('test'), false);
      assert.strictEqual(isEmpty(true), false);
    });
  });

  describe('isArrayofObjects', () => {
    test('returns false for non-array', () => {
      assert.strictEqual(isArrayofObjects({}), false);
      assert.strictEqual(isArrayofObjects('not an array'), false);
      assert.strictEqual(isArrayofObjects(null), false);
    });

    test('returns false for empty array', () => {
      assert.strictEqual(isArrayofObjects([]), false);
    });

    test('returns false for array of primitives', () => {
      assert.strictEqual(isArrayofObjects([1, 2, 3]), false);
      assert.strictEqual(isArrayofObjects(['a', 'b']), false);
    });

    test('returns true for array of objects', () => {
      assert.strictEqual(isArrayofObjects([{ a: 1 }]), true);
      assert.strictEqual(isArrayofObjects([{ a: 1 }, { b: 2 }]), true);
    });

    test('returns true for array with first element as object', () => {
      assert.strictEqual(isArrayofObjects([{ a: 1 }, 2, 3]), true);
    });
  });

  describe('isComputedAttribute', () => {
    test('returns true for id', () => {
      assert.strictEqual(isComputedAttribute('id'), true);
    });

    test('returns true for subscription', () => {
      assert.strictEqual(isComputedAttribute('subscription'), true);
    });

    test('returns true for tenant', () => {
      assert.strictEqual(isComputedAttribute('tenant'), true);
    });

    test('returns true for principal_id', () => {
      assert.strictEqual(isComputedAttribute('principal_id'), true);
    });

    test('returns true for client_id', () => {
      assert.strictEqual(isComputedAttribute('client_id'), true);
    });

    test('returns true for object_id', () => {
      assert.strictEqual(isComputedAttribute('object_id'), true);
    });

    test('returns true for name', () => {
      assert.strictEqual(isComputedAttribute('name'), true);
    });

    test('returns true for type', () => {
      assert.strictEqual(isComputedAttribute('type'), true);
    });

    test('returns true for keys containing patterns', () => {
      assert.strictEqual(isComputedAttribute('subscription_id'), true);
      assert.strictEqual(isComputedAttribute('tenant_name'), true);
    });

    test('returns false for user attributes', () => {
      assert.strictEqual(isComputedAttribute('environment'), false);
      assert.strictEqual(isComputedAttribute('cost_center'), false);
      assert.strictEqual(isComputedAttribute('tags'), false);
    });
  });
});

console.log('\n========================================');
console.log(`Results: ${testsPassed} passed, ${testsFailed} failed`);
console.log('========================================\n');

process.exit(testsFailed > 0 ? 1 : 0);
