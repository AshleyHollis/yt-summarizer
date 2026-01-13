/**
 * Array Formatter Module
 *
 * Handles formatting of array values with proper multi-line indentation
 */

const { formatValue } = require('./value-formatter');

/**
 * Format an array value with multi-line Terraform-style output
 * Declarative approach: define structure once, then template lines
 * @param {Array} arr - The array to format
 * @param {string} prefix - Prefix indentation (e.g., '    ')
 * @param {string} key - Attribute name
 * @param {string} marker - The marker to use (+, -, !, etc.)
 * @returns {Array<string>} Array of formatted lines
 */
function formatMultilineArray(arr, prefix, key, marker = '  ') {
  if (arr.length === 0) {
    return [`${marker} ${prefix}${key} = []`];
  }

  // Define indentation structure - all relative to content start
  // Pattern: marker + space + prefix + [content]
  const contentIndent = `${marker} ${prefix}`;
  const valueIndent = `${contentIndent}    `;
  const closingIndent = `${contentIndent}`;

  // Build lines declaratively
  return [
    `${contentIndent}${key} = [`,
    ...arr.map(item => `${valueIndent}${formatValue(item, false)},`),
    `${closingIndent}]`
  ];
}

/**
 * Format a simple array value (inline format for single elements or empty arrays)
 * @param {Array} arr - The array to format
 * @param {string} marker - The marker to use
 * @param {string} prefix - Prefix indentation
 * @param {string} key - Attribute name
 * @param {boolean} isUnknown - Whether the array contains unknown values
 * @returns {string} Formatted line
 */
function formatInlineArray(arr, marker, prefix, key, isUnknown = false) {
  if (arr.length === 0) {
    return `${marker} ${prefix}${key} = []`;
  }
  if (arr.length === 1) {
    return `${marker} ${prefix}${key} = ${formatValue(arr[0], isUnknown)}`;
  }
  return `${marker} ${prefix}${key} = ${formatValue(arr, isUnknown)}`;
}

module.exports = {
  formatMultilineArray,
  formatInlineArray
};
