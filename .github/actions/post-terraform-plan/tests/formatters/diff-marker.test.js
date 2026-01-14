/**
 * Unit Tests for Diff Marker Module
 */

const assert = require('assert');
const {
  determineMarker,
  getResourceHeaderMarker,
  shouldUseMarkersForBlocks
} = require('../../src/formatters/diff-marker');

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

describe('Diff Marker Module', () => {
  describe('determineMarker', () => {
    test('returns "  " when forceMarker is two spaces', () => {
      assert.strictEqual(determineMarker(true, true, '  ', false), '  ');
      assert.strictEqual(determineMarker(false, true, '  ', false), '  ');
    });

    test('returns "  " when forceMarker is empty string', () => {
      assert.strictEqual(determineMarker(true, true, '', false), '  ');
    });

    test('returns + when forceMarker is +', () => {
      assert.strictEqual(determineMarker(false, true, '+', false), '+');
    });

    test('returns - when forceMarker is -', () => {
      assert.strictEqual(determineMarker(true, false, '-', false), '-');
    });

    test('returns !! for replace action', () => {
      assert.strictEqual(determineMarker(true, true, null, true), '!!');
      assert.strictEqual(determineMarker(false, true, null, true), '!!');
    });

    test('returns + when value is added (no force, not replace)', () => {
      assert.strictEqual(determineMarker(false, true, null, false), '+');
    });

    test('returns - when value is removed (no force, not replace)', () => {
      assert.strictEqual(determineMarker(true, false, null, false), '-');
    });

    test('returns ! when value is modified (no force, not replace)', () => {
      assert.strictEqual(determineMarker(true, true, null, false), '!');
    });

    test('handles undefined forceMarker', () => {
      assert.strictEqual(determineMarker(false, true, undefined, false), '+');
      assert.strictEqual(determineMarker(true, false, undefined, false), '-');
      assert.strictEqual(determineMarker(true, true, undefined, false), '!');
    });
  });

  describe('getResourceHeaderMarker', () => {
    test('returns + for create action', () => {
      assert.strictEqual(getResourceHeaderMarker('create'), '+');
    });

    test('returns - for destroy action', () => {
      assert.strictEqual(getResourceHeaderMarker('destroy'), '-');
    });

    test('returns ~ for update action', () => {
      assert.strictEqual(getResourceHeaderMarker('update'), '~');
    });

    test('returns -/+ for replace action', () => {
      assert.strictEqual(getResourceHeaderMarker('replace'), '-/+');
    });

    test('returns ~ for unknown action (default)', () => {
      assert.strictEqual(getResourceHeaderMarker('unknown'), '~');
    });
  });

  describe('shouldUseMarkersForBlocks', () => {
    test('returns true when forceMarker is null', () => {
      assert.strictEqual(shouldUseMarkersForBlocks(null), true);
    });

    test('returns true when forceMarker is undefined', () => {
      assert.strictEqual(shouldUseMarkersForBlocks(undefined), true);
    });

    test('returns true when forceMarker is +', () => {
      assert.strictEqual(shouldUseMarkersForBlocks('+'), true);
    });

    test('returns true when forceMarker is -', () => {
      assert.strictEqual(shouldUseMarkersForBlocks('-'), true);
    });

    test('returns false when forceMarker is two spaces', () => {
      assert.strictEqual(shouldUseMarkersForBlocks('  '), false);
    });

    test('returns true when forceMarker is empty string (falsy, use markers)', () => {
      // Empty string is falsy, so returns true (use markers) per original logic
      assert.strictEqual(shouldUseMarkersForBlocks(''), true);
    });
  });
});

console.log('\n========================================');
console.log(`Results: ${testsPassed} passed, ${testsFailed} failed`);
console.log('========================================\n');

process.exit(testsFailed > 0 ? 1 : 0);
