/**
 * Value Validator Module
 *
 * Provides utilities to determine if a value is meaningful for display.
 * Follows Single Responsibility Principle - one concern: meaningful value validation.
 */

/**
 * Check if a value is meaningful (not null, empty, or default-like)
 * @param {*} value - The value to check
 * @returns {boolean} True if the value should be displayed
 */
function isMeaningfulValue(value) {
  // Skip null values
  if (value === null || value === undefined) {
    return false;
  }

  // Skip empty arrays
  if (Array.isArray(value) && value.length === 0) {
    return false;
  }

  // Skip empty objects
  if (typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === 0) {
    return false;
  }

  // Skip false booleans that are likely defaults
  if (typeof value === 'boolean' && value === false) {
    return false;
  }

  // Skip empty strings (common default/placeholder)
  if (typeof value === 'string' && value === '') {
    return false;
  }

  return true;
}

/**
 * Check if two values are equivalent (useful for change detection)
 * @param {*} value1 - First value
 * @param {*} value2 - Second value
 * @returns {boolean} True if values are equivalent
 */
function areValuesEquivalent(value1, value2) {
  return JSON.stringify(value1) === JSON.stringify(value2);
}

/**
 * Check if an object/array is empty
 * @param {*} value - Value to check
 * @returns {boolean} True if empty
 */
function isEmpty(value) {
  if (value === null || value === undefined) {
    return true;
  }
  if (Array.isArray(value)) {
    return value.length === 0;
  }
  if (typeof value === 'object') {
    return Object.keys(value).length === 0;
  }
  return false;
}

/**
 * Check if value is an array of objects (blocks)
 * @param {*} value - Value to check
 * @returns {boolean} True if array of objects
 */
function isArrayofObjects(value) {
  if (!Array.isArray(value) || value.length === 0) {
    return false;
  }
  return typeof value[0] === 'object';
}

/**
 * Check if an attribute key is computed/read-only (should be skipped for destroy)
 * @param {string} key - Attribute key to check
 * @returns {boolean} True if computed attribute
 */
function isComputedAttribute(key) {
  const computedPatterns = [
    'id',
    'subscription',
    'tenant',
    'principal_id',
    'client_id',
    'object_id',
    'name',
    'type',
  ];
  return computedPatterns.some(pattern => key.includes(pattern));
}

module.exports = {
  isMeaningfulValue,
  areValuesEquivalent,
  isEmpty,
  isArrayofObjects,
  isComputedAttribute
};
