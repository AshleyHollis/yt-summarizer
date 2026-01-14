/**
 * Change Detection Module
 *
 * Handles recursive comparison and formatting of Terraform resource changes.
 * Broken down into smaller, single-purpose functions for better testability.
 */

const {
  isMeaningfulValue,
  areValuesEquivalent,
  isEmpty,
  isArrayofObjects,
  isComputedAttribute
} = require('./utils/value-validator');

const { formatValue } = require('./formatters/value-formatter');
const { formatMultilineArray, formatInlineArray } = require('./formatters/array-formatter');
const { determineMarker, shouldUseMarkersForBlocks } = require('./formatters/diff-marker');

/**
 * Check if a change should be displayed based on meaningful value rules
 * @param {boolean} beforeExists - Whether attribute exists in before
 * @param {boolean} afterExists - Whether attribute exists in after
 * @param {*} beforeVal - Before value
 * @param {*} afterVal - After value
 * @returns {boolean} True if change should be displayed
 */
function shouldDisplayChange(beforeExists, afterExists, beforeVal, afterVal) {
  // For create: skip meaningless values in after
  if (afterExists && !beforeExists) {
    return isMeaningfulValue(afterVal);
  }

  // For update: skip if both are meaningless and identical
  if (afterExists && beforeExists) {
    if (!isMeaningfulValue(beforeVal) && !isMeaningfulValue(afterVal) &&
        areValuesEquivalent(beforeVal, afterVal)) {
      return false;
    }
    return true;
  }

  // For destroy: skip meaningless values
  if (beforeExists && !afterExists) {
    return isMeaningfulValue(beforeVal);
  }

  return false;
}

/**
 * Check if identical values should be displayed
 * @param {boolean} beforeExists - Whether attribute exists in before
 * @param {boolean} afterExists - Whether attribute exists in after
 * @param {*} beforeVal - Before value
 * @param {*} afterVal - After value
 * @param {string} forceMarker - Forced marker setting
 * @returns {boolean} True if identical values should be skipped
 */
function shouldSkipIdentical(beforeExists, afterExists, beforeVal, afterVal, forceMarker) {
  // Skip if values are identical AND we're not forcing explicit markers
  if (beforeExists && afterExists && areValuesEquivalent(beforeVal, afterVal) &&
      (forceMarker === '  ' || forceMarker === undefined || forceMarker === null)) {
    return true;
  }
  return false;
}

/**
 * Check if a computed attribute should be skipped for destroy
 * @param {string} key - Attribute key
 * @param {boolean} afterExists - Whether attribute exists in after
 * @param {string} forceMarker - Forced marker setting
 * @returns {boolean} True if computed attribute should be skipped
 */
function shouldSkipComputedAttr(key, afterExists, forceMarker) {
  // For destroy actions, only show key identifying attributes
  if (forceMarker === '  ' && !afterExists) {
    return isComputedAttribute(key);
  }
  return false;
}

/**
 * Format a simple value change
 *
 * Generates canonical output - indentation will be applied by post-processor
 *
 * Format: marker + key + = + value
 *
 * @param {string} marker - Diff marker (+, -, !, !!, '  ')
 * @param {string} prefix - Indentation prefix (not used, kept for compat)
 * @param {string} key - Attribute key
 * @param {*} beforeVal - Before value
 * @param {*} afterVal - After value
 * @param {boolean} isUnknown - Whether value is unknown
 * @param {boolean} isReplace - Whether this is replace action
 * @returns {string} Formatted change line
 */
function formatSimpleValueChange(marker, prefix, key, beforeVal, afterVal, isUnknown, isReplace) {
  const changeMarker = isReplace ? '!!' : marker;

  // No marker case (create/destroy) - show multi-line arrays or single-line values
  if (marker === '  ') {
    const val = beforeVal !== undefined ? beforeVal : afterVal;
    if (Array.isArray(val) && val.length > 1) {
      const arrayLines = formatMultilineArray(val, prefix, key, '  ');
      return arrayLines.join('\n').split('\n');
    }
    return `${marker} ${key} = ${formatValue(val, isUnknown)}`;
  }

  // Value added
  if (beforeVal === undefined && afterVal !== undefined) {
    if (Array.isArray(afterVal) && afterVal.length > 1) {
      const arrayLines = formatMultilineArray(afterVal, prefix, key, '+');
      return arrayLines.join('\n').split('\n');
    }
    return `${marker} ${key} = ${formatValue(afterVal, isUnknown)}`;
  }

  // Value removed
  if (beforeVal !== undefined && afterVal === undefined) {
    if (Array.isArray(beforeVal) && beforeVal.length > 1) {
      const arrayLines = formatMultilineArray(beforeVal, prefix, key, '-');
      return arrayLines.join('\n').split('\n');
    }
    return `${marker} ${key} = ${formatValue(beforeVal, false)}`;
  }

  // Value changed
  const beforeFormatted = formatValue(beforeVal, false);
  const afterFormatted = formatValue(afterVal, isUnknown);
  return `${changeMarker} ${key} = ${beforeFormatted} -> ${afterFormatted}`;
}

/**
 * Format array of objects (blocks) changes
 *
 * Generates canonical output - indentation will be applied by post-processor
 *
 * @param {Array} beforeArr - Before array
 * @param {Array} afterArr - After array
 * @param {Object} afterUnknown - Unknown values
 * @param {string} prefix - Indentation prefix
 * @param {string|null} forceMarker - Forced marker
 * @param {boolean} isReplace - Whether this is replace action
 * @param {string} key - Attribute key
 * @returns {Array<string>} Array of formatted lines
 */
function formatArrayOfObjects(beforeArr, afterArr, afterUnknown, prefix, forceMarker, isReplace, key) {
  const lines = [];
  const maxLen = Math.max(beforeArr.length, afterArr.length);
  const useMarkers = shouldUseMarkersForBlocks(forceMarker);

  for (let i = 0; i < maxLen; i++) {
    const bItem = beforeArr[i];
    const aItem = afterArr[i];
    const unknownItem = Array.isArray(afterUnknown) ? afterUnknown[i] : afterUnknown;

    if (bItem && aItem) {
      const nestedLines = findChanges(bItem, aItem, unknownItem || {}, prefix + '    ', forceMarker, isReplace);
      if (nestedLines.length > 0) {
        const useMarker = useMarkers ? (isReplace ? '!!' : '!') : '  ';
        lines.push(`${useMarker} ${key} {`);
        nestedLines.forEach(l => lines.push(l));
        lines.push(`  }`);
      }
    } else if (aItem && !bItem) {
      const itemMarker = !forceMarker || (forceMarker !== '  ' && forceMarker !== '') ? '+' : '  ';
      lines.push(`${itemMarker} ${key} {`);
      const itemForceMarker = useMarkers ? undefined : '  ';
      const nestedLines = findChanges({}, aItem, unknownItem || {}, prefix + '    ', itemForceMarker, false);
      nestedLines.forEach(l => lines.push(l));
      lines.push(`  }`);
    } else if (bItem && !aItem) {
      const itemMarker = !forceMarker || (forceMarker !== '  ' && forceMarker !== '') ? '-' : '  ';
      lines.push(`${itemMarker} ${key} {`);
      lines.push(`${itemMarker} # (block removed)`);
      lines.push(`  }`);
    }
  }

  return lines;
}

/**
 * Format simple array changes
 *
 * Generates canonical output - indentation will be applied by post-processor
 *
 * @param {Array} beforeArr - Before array
 * @param {Array} afterArr - After array
 * @param {Object} afterUnknown - Unknown values
 * @param {string} prefix - Indentation prefix
 * @param {string|null} forceMarker - Forced marker
 * @param {boolean} isReplace - Whether this is replace action
 * @param {string} key - Attribute key
 * @param {boolean} isUnknown - Whether value is unknown
 * @param {boolean} beforeExists - Whether before exists
 * @param {boolean} afterExists - Whether after exists
 * @returns {Array<string>} Array of formatted lines
 */
function formatSimpleArray(beforeArr, afterArr, afterUnknown, prefix, forceMarker, isReplace, key, isUnknown, beforeExists, afterExists) {
  const lines = [];
  const useMarkers = shouldUseMarkersForBlocks(forceMarker);

  if (useMarkers || forceMarker === '  ') {
    // For create/destroy, show array with multi-line formatting
    const val = beforeExists ? beforeArr : afterArr;
    const marker = forceMarker || '  ';
    if (val.length > 1) {
      const arrayLines = formatMultilineArray(val, prefix, key, marker);
      lines.push(...arrayLines);
    } else if (val.length === 1) {
      lines.push(`${marker} ${key} = ${formatValue(val[0], isUnknown)}`);
    } else {
      lines.push(`${marker} ${key} = []`);
    }
  } else if (!areValuesEquivalent(beforeArr, afterArr)) {
    // Array comparison: show before -> after on the line
    const beforeFormatted = formatValue(beforeArr, false);
    const afterFormatted = formatValue(afterArr, isUnknown);
    const arrayMarker = isReplace ? '!!' : '!';
    lines.push(`${arrayMarker} ${key} = ${beforeFormatted} -> ${afterFormatted}`);
  }

  return lines;
}

/**
 * Format nested block/object changes
 *
 * Generates canonical output - indentation will be applied by post-processor
 *
 * @param {*} beforeVal - Before value
 * @param {*} afterVal - After value
 * @param {Object} afterUnknown - Unknown values
 * @param {string} prefix - Indentation prefix
 * @param {string|null} forceMarker - Forced marker
 * @param {boolean} isReplace - Whether this is replace action
 * @param {string} key - Attribute key
 * @returns {Array<string>} Array of formatted lines or empty array
 */
function formatNestedBlock(beforeVal, afterVal, afterUnknown, prefix, forceMarker, isReplace, key) {
  const lines = [];
  const useMarkers = shouldUseMarkersForBlocks(forceMarker);

  const nestedBefore = (typeof beforeVal === 'object' && beforeVal !== null) ? beforeVal : {};
  const nestedLines = findChanges(nestedBefore, afterVal, afterUnknown || {}, prefix + '    ', forceMarker, isReplace);

  if (nestedLines.length > 0 || useMarkers) {
    const blockMarker = useMarkers ? determineMarker(
      beforeVal !== undefined && beforeVal !== null,
      afterVal !== undefined && afterVal !== null,
      forceMarker,
      isReplace
    ) : '  ';
    lines.push(`${blockMarker} ${key} {`);
    nestedLines.forEach(l => lines.push(l));
    lines.push(`  }`);
  }

  return lines;
}

/**
 * Recursively find all changes between before and after states
 * Format optimized for GitHub diff syntax highlighting (markers at column 0)
 *
 * Markers used:
 *   '+' - Added lines (green, only for updates)
 *   '-' - Removed lines (red, only for updates)
 *   '!' - Modified lines (yellow/orange, only for updates)
 *   '!!' - Force replacement lines (bright red, only for replaces)
 *   '  ' - No marker (create/destroy actions)
 *
 * @param {Object} before - Before state
 * @param {Object} after - After state
 * @param {Object} afterUnknown - Unknown values in after state
 * @param {string} prefix - Indentation prefix (spaces only, no markers)
 * @param {string|null} forceMarker - Force all lines to use this marker
 * @param {boolean} isReplace - Whether this change is part of a force replacement action
 * @returns {string[]} Array of formatted change lines
 */
function findChanges(before, after, afterUnknown, prefix = '  ', forceMarker = null, isReplace = false) {
  const lines = [];
  before = before || {};
  after = after || {};
  afterUnknown = afterUnknown || {};

  const allKeys = new Set([
    ...Object.keys(before),
    ...Object.keys(after)
  ]);

  for (const key of Array.from(allKeys).sort()) {
    const beforeVal = before[key];
    const afterVal = after[key];
    const isUnknown = afterUnknown[key];

    const beforeExists = key in before;
    const afterExists = key in after;

    // Check if this change should be displayed
    if (!shouldDisplayChange(beforeExists, afterExists, beforeVal, afterVal)) {
      continue;
    }

    // Skip identical values if not forcing markers
    if (shouldSkipIdentical(beforeExists, afterExists, beforeVal, afterVal, forceMarker)) {
      continue;
    }

    // Skip computed attributes for destroy
    if (shouldSkipComputedAttr(key, afterExists, forceMarker)) {
      continue;
    }

    // Determine marker
    const marker = determineMarker(beforeExists, afterExists, forceMarker, isReplace);

    // Handle nested objects/blocks
    if (typeof afterVal === 'object' && afterVal !== null && !Array.isArray(afterVal) &&
        (typeof beforeVal === 'object' || beforeVal === undefined || beforeVal === null) &&
        (!beforeVal || !Array.isArray(beforeVal))) {
      const nestedLines = formatNestedBlock(beforeVal, afterVal, isUnknown || {}, prefix, forceMarker, isReplace, key);
      lines.push(...nestedLines);
      continue;
    }

    // Handle arrays
    if (Array.isArray(afterVal) || Array.isArray(beforeVal)) {
      const beforeArr = Array.isArray(beforeVal) ? beforeVal : [];
      const afterArr = Array.isArray(afterVal) ? afterVal : [];

      if (isArrayofObjects(beforeArr) || isArrayofObjects(afterArr)) {
        const arrayLines = formatArrayOfObjects(beforeArr, afterArr, isUnknown || {}, prefix, forceMarker, isReplace, key);
        lines.push(...arrayLines);
      } else {
        const arrayLines = formatSimpleArray(beforeArr, afterArr, isUnknown || {}, prefix, forceMarker, isReplace, key, isUnknown, beforeExists, afterExists);
        lines.push(...arrayLines);
      }
      continue;
    }

    // Handle simple values
    const simpleValueResult = formatSimpleValueChange(marker, prefix, key, beforeVal, afterVal, isUnknown, isReplace);
    if (Array.isArray(simpleValueResult)) {
      lines.push(...simpleValueResult);
    } else {
      lines.push(simpleValueResult);
    }
  }

  return lines;
}

module.exports = {
  findChanges,
  shouldDisplayChange,
  shouldSkipIdentical,
  shouldSkipComputedAttr,
  formatSimpleValueChange,
  formatArrayOfObjects,
  formatSimpleArray,
  formatNestedBlock
};
