/**
 * Array Formatter Module
 *
 * Handles formatting of array values with proper multi-line indentation
 */

const { formatValue } = require('./value-formatter');

/**
 * Format an array value with multi-line Terraform-style
 *
 * Generates canonical output - indentation will be applied by post-processor
 *
 * Format: marker + key + = + [
 *            marker + value
 *            marker + ]
 * For create/destroy, marker is '  ' (placeholder)
 * For updates, marker is +, -, !, !!
 *
 * @param {Array} arr - The array to format
 * @param {string} prefix - Original prefix (e.g., '    ')
 * @param {string} key - Attribute name
 * @param {string} marker - The marker to use (+, -, !, !!, '  ')
 * @returns {Array<string>} Array of formatted lines
 */
function formatMultilineArray(arr, prefix, key, marker = '  ') {
  if (arr.length === 0) {
    return [`${marker} ${key} = []`];
  }

  // Canonical format: marker + key + = + [
  //                marker + value
  //                marker + ]
  // Post-processor will handle proper indentation
  return [
    `${marker} ${key} = [`,
    ...arr.map(item => `    ${marker} ${formatValue(item, false)},`),
    `    ${marker} ]`
  ];
}

/**
 * Format a simple array value (inline format for single elements or empty arrays)
 *
 * Generates canonical output - indentation will be applied by post-processor
 *
 * @param {Array} arr - The array to format
 * @param {string} marker - The marker to use
 * @param {string} prefix - Base indentation (e.g., '    ')
 * @param {string} key - Attribute name
 * @param {boolean} isUnknown - Whether the array contains unknown values
 * @returns {string} Formatted line
 */
function formatInlineArray(arr, marker, prefix, key, isUnknown = false) {
  const baseIndent = `${marker} ${key} = `;

  if (arr.length === 0) {
    return `${baseIndent}[]`;
  }
  if (arr.length === 1) {
    return `${baseIndent}${formatValue(arr[0], isUnknown)}`;
  }
  return `${baseIndent}${formatValue(arr, isUnknown)}`;
}

module.exports = {
  formatMultilineArray,
  formatInlineArray
};
