#!/usr/bin/env node

/**
 * Test script to verify indentation fixes
 */

const { formatMultilineArray, formatInlineArray } = require('./src/formatters/array-formatter');
const { formatSimpleValueChange } = require('./src/change-detection');

console.log('=== Testing Array Formatting ===\n');

// Test 1: formatMultilineArray with '  ' marker (create/destroy)
console.log('Test 1: formatMultilineArray with marker="  " (create/destroy)');
console.log('Expected: 4 spaces before key, 6 spaces before values');
const result1 = formatMultilineArray(
  ['Environment:prod', 'ManagedBy:terraform', 'Project:yt-summarizer'],
  '    ',
  'tags',
  '  '
);
console.log('Result:');
result1.forEach(line => console.log(`  "${line}"`));
console.log();

// Test 2: formatMultilineArray with '+' marker (update)
console.log('Test 2: formatMultilineArray with marker="+" (update)');
console.log('Expected: "+ " + 4 spaces before key, "+ " + 6 spaces before values');
const result2 = formatMultilineArray(
  ['value1', 'value2'],
  '    ',
  'tags',
  '+'
);
console.log('Result:');
result2.forEach(line => console.log(`  "${line}"`));
console.log();

// Test 3: formatSimpleValueChange with '  ' marker
console.log('Test 3: formatSimpleValueChange with marker="  " (create)');
console.log('Expected: 4 spaces before key (no marker displayed)');
const result3 = formatSimpleValueChange('  ', '    ', 'display_name', undefined, 'github-actions', false, false);
console.log('Result:');
console.log(`  "${result3}"`);
console.log();

// Test 4: formatSimpleValueChange with '+' marker
console.log('Test 4: formatSimpleValueChange with marker="+" (update: value added)');
console.log('Expected: "+ " + 4 spaces before key');
const result4 = formatSimpleValueChange('+', '    ', 'display_name', undefined, 'github-actions', false, false);
console.log('Result:');
console.log(`  "${result4}"`);
console.log();

console.log('=== Expected Terraform Output Example ===\n');
console.log('Create action (attributes have 4 spaces, NO marker):');
console.log('  + resource "azuread_application" "github_actions" {');
console.log('      display_name = "github-actions-yt-summarizer"');
console.log('      owners = (known after apply)');
console.log('      sign_in_audience = "AzureADMyOrg"');
console.log('      tags = [');
console.log('          "Environment:prod",');
console.log('          "ManagedBy:terraform",');
console.log('          "Project:yt-summarizer",');
console.log('          "TestPipelineDate:2026-01-13-v2",');
console.log('      ]');
console.log('  }');
console.log();
console.log('Update action (attributes have "+ " + 4 spaces):');
console.log('  ~ resource "azuread_application" "github_actions" {');
console.log('+     tags = [');
console.log('+         "value1",');
console.log('+         "value2"');
console.log('+     ]');
console.log('  }');
