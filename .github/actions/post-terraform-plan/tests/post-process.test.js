#!/usr/bin/env node

/**
 * Post-Process Module Tests
 */

const assert = require('assert');
const { applyIndentation } = require('../src/post-process');

let testsPassed = 0;
let testsFailed = 0;

function test(description, fn) {
  try {
    fn();
    testsPassed++;
    console.log(`✓ ${description}`);
  } catch (error) {
    testsFailed++;
    console.error(`✗ ${description}`);
    console.error(`  ${error.message}`);
  }
}

// Test: Simple create resource
test('Simple create resource', () => {
  const lines = [
    '+ resource "test_resource" "example" {',
    '+ display_name = "test"',
    '+ }'
  ];

  const result = applyIndentation(lines);

  assert.strictEqual(result.length, 3);
  assert.strictEqual(result[0], '+ resource "test_resource" "example" {');
  assert.strictEqual(result[1], '+     display_name = "test"');
  assert.strictEqual(result[2], '+ }');
});

// Test: Multi-line array
test('Multi-line array', () => {
  const lines = [
    '+ resource "test_resource" "example" {',
    '+ tags = [',
    '+ "key1",',
    '+ "key2",',
    '+ ]',
    '+ }'
  ];

  const result = applyIndentation(lines);

  assert.strictEqual(result.length, 6);
  assert.strictEqual(result[0], '+ resource "test_resource" "example" {');
  assert.strictEqual(result[1], '+     tags = [');
  assert.strictEqual(result[2], '+         "key1",');
  assert.strictEqual(result[3], '+         "key2",');
  assert.strictEqual(result[4], '+     ]');
  assert.strictEqual(result[5], '+ }');
});

// Test: Nested block
test('Nested block', () => {
  const lines = [
    '+ resource "test_resource" "example" {',
    '+ settings {',
    '+ enabled = true',
    '+ }',
    '+ }'
  ];

  const result = applyIndentation(lines);

  assert.strictEqual(result.length, 5);
  assert.strictEqual(result[0], '+ resource "test_resource" "example" {');
  assert.strictEqual(result[1], '+     settings {');
  assert.strictEqual(result[2], '+         enabled = true');
  assert.strictEqual(result[3], '+     }');
  assert.strictEqual(result[4], '+ }');
});

// Test: Update with diff markers
test('Update with diff markers', () => {
  const lines = [
    '! resource "test_resource" "example" {',
    '! display_name = "old" -> "new"',
    '+ new_field = "value"',
    '- old_field = "value"',
    '! }'
  ];

  const result = applyIndentation(lines);

  assert.strictEqual(result.length, 5);
  assert.strictEqual(result[0], '! resource "test_resource" "example" {');
  assert.strictEqual(result[1], '!     display_name = "old" -> "new"');
  assert.strictEqual(result[2], '+     new_field = "value"');
  assert.strictEqual(result[3], '-     old_field = "value"');
  assert.strictEqual(result[4], '! }');
});

// Test: Replace with !! marker
test('Replace with force markers', () => {
  const lines = [
    '!! resource "test_resource" "example" {',
    '!! force_field = "value"',
    '!! }'
  ];

  const result = applyIndentation(lines);

  assert.strictEqual(result.length, 3);
  assert.strictEqual(result[0], '!! resource "test_resource" "example" {');
  assert.strictEqual(result[1], '!!     force_field = "value"');
  assert.strictEqual(result[2], '!! }');
});

// Test: Preserve comments
test('Preserve comments', () => {
  const lines = [
    '+ resource "test_resource" "example" {',
    '+ # This is a comment',
    '+ display_name = "test"',
    '+ }'
  ];

  const result = applyIndentation(lines);

  assert.strictEqual(result.length, 4);
  assert.strictEqual(result[0], '+ resource "test_resource" "example" {');
  assert.strictEqual(result[1], '    # This is a comment');
  assert.strictEqual(result[2], '+     display_name = "test"');
  assert.strictEqual(result[3], '+ }');
});

// Test: Destroy with resource marker inheritance
test('Destroy inherits marker for nested lines', () => {
  const lines = [
    '- resource "test_resource" "example" {',
    'display_name = "test"',
    '}'
  ];

  const result = applyIndentation(lines);

  assert.strictEqual(result.length, 3);
  assert.strictEqual(result[0], '- resource "test_resource" "example" {');
  assert.strictEqual(result[1], '-     display_name = "test"');
  assert.strictEqual(result[2], '  }');
});

// Test: Complex nesting
test('Complex nesting (3 levels)', () => {
  const lines = [
    '+ resource "test_resource" "example" {',
    '+ outer {',
    '+ inner {',
    '+ value = "test"',
    '+ }',
    '+ }',
    '+ }'
  ];

  const result = applyIndentation(lines);

  assert.strictEqual(result.length, 7);
  assert.strictEqual(result[0], '+ resource "test_resource" "example" {');
  assert.strictEqual(result[1], '+     outer {');
  assert.strictEqual(result[2], '+         inner {');
  assert.strictEqual(result[3], '+             value = "test"');
  assert.strictEqual(result[4], '+         }');
  assert.strictEqual(result[5], '+     }');
  assert.strictEqual(result[6], '+ }');
});

// Test: Empty array
test('Empty array', () => {
  const lines = [
    '+ resource "test_resource" "example" {',
    '+ tags = []',
    '+ }'
  ];

  const result = applyIndentation(lines);

  assert.strictEqual(result.length, 3);
  assert.strictEqual(result[0], '+ resource "test_resource" "example" {');
  assert.strictEqual(result[1], '+     tags = []');
  assert.strictEqual(result[2], '+ }');
});

// Test: Array of blocks
test('Array of blocks', () => {
  const lines = [
    '+ resource "test_resource" "example" {',
    '+ tags {',
    '+ key = "value"',
    '+ }',
    '+ }'
  ];

  const result = applyIndentation(lines);

  assert.strictEqual(result.length, 5);
  assert.strictEqual(result[0], '+ resource "test_resource" "example" {');
  assert.strictEqual(result[1], '+     tags {');
  assert.strictEqual(result[2], '+         key = "value"');
  assert.strictEqual(result[3], '+     }');
  assert.strictEqual(result[4], '+ }');
});

// Summary
console.log(`\n=== Post-Process Tests ===`);
console.log(`Passed: ${testsPassed}`);
console.log(`Failed: ${testsFailed}`);
console.log(`Total:  ${testsPassed + testsFailed}`);

if (testsFailed > 0) {
  process.exit(1);
}
