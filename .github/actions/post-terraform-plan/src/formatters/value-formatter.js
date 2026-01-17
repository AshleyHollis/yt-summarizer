/**
 * Value Formatter Module
 *
 * Handles formatting of individual values for Terraform-style display.
 */

/**
 * Format a sensitive value for display
 * @param {*} value - The value to format (will be redacted)
 * @returns {string} Redacted value string
 */
function formatSensitiveValue(value) {
  // Show null/undefined/empty string as-is for clarity
  if (value === null || value === undefined) {
    return formatValue(value);
  }
  if (value === '') {
    return '""';
  }
  // Redact all other values
  return '(sensitive value)';
}

/**
 * Format a value for display (Terraform-style)
 * @param {*} value - The value to format
 * @param {boolean} unknown - Whether the value is unknown (known after apply)
 * @returns {string} Formatted value string
 */
function formatValue(value, unknown = false) {
  if (unknown) return '(known after apply)';
  if (value === null) return 'null';
  if (value === undefined) return 'null';
  if (typeof value === 'string') return `"${value}"`;
  if (typeof value === 'boolean') return value.toString();
  if (typeof value === 'number') return value.toString();

  if (Array.isArray(value)) {
    if (value.length === 0) return '[]';
    return JSON.stringify(value);
  }
  if (typeof value === 'object') {
    const keys = Object.keys(value);
    if (keys.length === 0) return '{}';
    return JSON.stringify(value);
  }

  return JSON.stringify(value);
}

module.exports = {
  formatValue,
  formatSensitiveValue
};
