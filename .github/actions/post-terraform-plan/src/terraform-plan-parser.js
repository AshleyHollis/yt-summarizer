/**
 * Terraform Plan Parser
 *
 * Parses Terraform JSON plan output and generates formatted markdown/HTML.
 * This module is designed to work both in GitHub Actions and for local development.
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

/**
 * Format an array value with multi-line Terraform-style output
 * @param {Array} arr - The array to format
 * @param {string} attributeName - The attribute name (e.g., 'tags')
 * @param {string} marker - The marker to use (+, -, !, etc.)
 * @returns {Array<string>} Array of formatted lines
 */
function formatMultilineArray(arr, attributeName, marker = '  ') {
  if (arr.length === 0) {
    return [`  ${attributeName} = []`];
  }

  const lines = [`${marker} ${attributeName} = [`];

  // Inner lines: 4 spaces indentation + formatted value + comma
  arr.forEach(item => {
    const formatted = formatValue(item, false);
    lines.push(`    ${formatted},`);
  });

  // Closing line: 2 spaces (no marker) to align with opening line's content
  lines.push('  ]');
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
 *
 * Note: Create and destroy actions use NO markers since the entire resource
 * block is already visually indicated in a collapsible section.
 *
 * @param {Object} before - Before state
 * @param {Object} after - After state
 * @param {Object} afterUnknown - Unknown values in after state
 * @param {string} prefix - Indentation prefix (spaces only, no markers)
 * @param {string} forceMarker - Force all lines to use this marker (null for create/destroy to skip markers)
 * @param {boolean} isReplace - Whether this change is part of a force replacement action (affects non-forced markers)
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

    // Skip meaningless values (null, empty arrays, false) when not changing
    // For create: skip meaningless values in after
    // For destroy: skip meaningless values in before
    // For update: show if changing from meaningful to meaningless or vice versa
    if (afterExists) {
      if (!beforeExists) {
        // Create: skip meaningless values
        if (!isMeaningfulValue(afterVal)) {
          continue;
        }
      } else {
        // Update: skip if both are meaningless and identical
        if (!isMeaningfulValue(beforeVal) && !isMeaningfulValue(afterVal) &&
            JSON.stringify(beforeVal) === JSON.stringify(afterVal)) {
          continue;
        }
      }
    } else if (beforeExists && !afterExists) {
      // Destroy: skip meaningless values
      if (!isMeaningfulValue(beforeVal)) {
        continue;
      }
    }

    // Skip if values are identical AND we're not forcing explicit markers
    // Explicit markers: '+', '-', etc. (excluding implicit '  ' for create/destroy)
    if (beforeExists && afterExists && JSON.stringify(beforeVal) === JSON.stringify(afterVal) &&
        (forceMarker === '  ' || forceMarker === undefined || forceMarker === null)) {
      continue;
    }

    // For destroy actions, only show key identifying attributes
    // Skip computed/read-only attributes that aren't useful
    if (forceMarker === '  ' && !afterExists) {
      // These are computed/generated attributes, not useful for display
      const computedIdPatterns = [
        'id',
        'subscription',
        'tenant',
        'principal_id',
        'client_id',
        'object_id',
        'name',  // Already in resource header
        'type',  // Already in resource header
      ];
      if (computedIdPatterns.some(pattern => key.includes(pattern))) {
        continue;
      }
    }

    // Determine marker: use forced marker or compute based on change type
    // For create/destroy: forceMarker='  ' (two spaces) to skip markers
    // For updates/replaces: forceMarker=undefined to compute markers dynamically
    let marker;

    if (forceMarker === '  ' || forceMarker === '') {
      // Create/destroy mode - use no markers
      marker = '  ';
    } else if (forceMarker === '+' || forceMarker === '-') {
      // Explicit forced marker
      marker = forceMarker;
    } else {
      // Update/replace mode - compute markers dynamically
      if (isReplace) {
        marker = '!!'; // Force replacement - bright red
      } else if (!beforeExists && afterExists) {
        marker = '+'; // Added
      } else if (beforeExists && !afterExists) {
        marker = '-'; // Removed
      } else {
        marker = '!'; // Modified
      }
    }

    // For arrays/objects, use marker instead of '  ' when in mode that uses markers
    const shouldUseMarkerForBlocks = !forceMarker || (forceMarker !== '  ' && forceMarker !== '');

  // Handle nested objects/blocks
  if (typeof afterVal === 'object' && afterVal !== null && !Array.isArray(afterVal) &&
      (typeof beforeVal === 'object' || beforeVal === undefined || beforeVal === null) &&
      (!beforeVal || !Array.isArray(beforeVal))) {
    const nestedBefore = (typeof beforeVal === 'object' && beforeVal !== null) ? beforeVal : {};
    const nestedLines = findChanges(nestedBefore, afterVal, isUnknown || {}, prefix + '    ', forceMarker, isReplace);

    // Only add block header if there are nested changes or if we're forcing a marker (non-null)
    if (nestedLines.length > 0 || shouldUseMarkerForBlocks) {
      // Use computed marker (or '  ' for no marker)
      const blockMarker = shouldUseMarkerForBlocks ? marker : '  ';
      lines.push(`${blockMarker} ${prefix}${key} {`);
      nestedLines.forEach(l => lines.push(l));
      lines.push(`  ${prefix}}`);
    }
    continue;
  }
    if (Array.isArray(afterVal) || Array.isArray(beforeVal)) {
      const beforeArr = Array.isArray(beforeVal) ? beforeVal : [];
      const afterArr = Array.isArray(afterVal) ? afterVal : [];

      // Check if arrays of objects (blocks)
      if ((beforeArr.length > 0 && typeof beforeArr[0] === 'object') ||
          (afterArr.length > 0 && typeof afterArr[0] === 'object')) {
        // Compare each element
        const maxLen = Math.max(beforeArr.length, afterArr.length);
        for (let i = 0; i < maxLen; i++) {
          const bItem = beforeArr[i];
          const aItem = afterArr[i];
          const unknownItem = Array.isArray(isUnknown) ? isUnknown[i] : isUnknown;

          if (bItem && aItem) {
            const nestedLines = findChanges(bItem, aItem, unknownItem || {}, prefix + '    ', forceMarker, isReplace);
            if (nestedLines.length > 0) {
              const arrayMarker = shouldUseMarkerForBlocks ? (isReplace ? '!!' : '!') : marker;
              lines.push(`${arrayMarker} ${prefix}${key} {`);
              nestedLines.forEach(l => lines.push(l));
              lines.push(`  ${prefix}}`);
            }
          } else if (aItem && !bItem) {
            const itemMarker = marker;
            lines.push(`${itemMarker} ${prefix}${key} {`);
            const itemForceMarker = shouldUseMarkerForBlocks ? undefined : '  ';
            const nestedLines = findChanges({}, aItem, unknownItem || {}, prefix + '    ', itemForceMarker, false);
            nestedLines.forEach(l => lines.push(l));
            lines.push(`  ${prefix}}`);
          } else if (bItem && !aItem) {
            const itemMarker = marker;
            lines.push(`${itemMarker} ${prefix}${key} {`);
            lines.push(`${itemMarker} ${prefix}    # (block removed)`);
            lines.push(`  ${prefix}}`);
          }
        }
      } else {
        // Simple array comparison with multi-line formatting
        if (shouldUseMarkerForBlocks || marker === '  ') {
          // For create/destroy, show array with multi-line formatting
          const val = beforeExists ? beforeVal : afterVal;
          const arrayLines = formatMultilineArray(val, key, marker);
          lines.push(...arrayLines);
        } else if (JSON.stringify(beforeArr) !== JSON.stringify(afterArr)) {
          // Array comparison: show before -> after on the line
          const beforeFormatted = formatValue(beforeVal, false);
          const afterFormatted = formatValue(afterVal, isUnknown);
          const arrayMarker = isReplace ? '!!' : '!';
          lines.push(`${arrayMarker} ${prefix}${key} = ${beforeFormatted} -> ${afterFormatted}`);
        }
      }
      continue;
    }

    // Simple value handling with multi-line array formatting
    if (marker === '  ') {
      // No marker case (create/destroy) - show multi-line arrays or single-line values
      const val = beforeExists ? beforeVal : afterVal;
      if (Array.isArray(val) && val.length > 1) {
        const arrayLines = formatMultilineArray(val, key, '  ');
        lines.push(...arrayLines);
      } else {
        lines.push(`  ${prefix}${key} = ${formatValue(val, isUnknown)}`);
      }
    } else if (!beforeExists && afterExists) {
      // Value added
      if (Array.isArray(afterVal) && afterVal.length > 1) {
        const arrayLines = formatMultilineArray(afterVal, key, '+');
        lines.push(...arrayLines);
      } else {
        lines.push(`+ ${prefix}${key} = ${formatValue(afterVal, isUnknown)}`);
      }
    } else if (beforeExists && !afterExists) {
      // Value removed
      if (Array.isArray(beforeVal) && beforeVal.length > 1) {
        const arrayLines = formatMultilineArray(beforeVal, key, '-');
        lines.push(...arrayLines);
      } else {
        lines.push(`- ${prefix}${key} = ${formatValue(beforeVal, false)}`);
      }
    } else if (beforeExists && afterExists) {
      // Value changed - arrays show inline, not multi-line for diff
      const beforeFormatted = formatValue(beforeVal, false);
      const afterFormatted = formatValue(afterVal, isUnknown);
      const changeMarker = isReplace ? '!!' : '!';
      lines.push(`${changeMarker} ${prefix}${key} = ${beforeFormatted} -> ${afterFormatted}`);
    }
  }

  return lines;
}

/**
 * Format resource change details
 * @param {Object} change - Resource change object from Terraform plan
 * @param {string} action - Action type (create, update, destroy, replace)
 * @returns {string} Formatted diff output with markers at column 0 for syntax highlighting
 */
function formatResourceChange(change, action) {
  const lines = [];
  const before = change.change.before || {};
  const after = change.change.after || {};
  const afterUnknown = change.change.after_unknown || {};

  const isReplaceAction = action === 'replace';

  // Resource header with marker (like real Terraform output)
  // Create: +
  // Destroy: -
  // Update: ~
  // Replace: -/+ (Terraform shows both)
  let resourceMarker;
  if (action === 'create') {
    resourceMarker = '+';
  } else if (action === 'destroy') {
    resourceMarker = '-';
  } else if (isReplaceAction) {
    resourceMarker = '-/+'; // Replace shows -/+
  } else {
    resourceMarker = '~';
  }

  lines.push(`${resourceMarker} resource "${change.type}" "${change.name}" {`);

  if (isReplaceAction) {
    lines.push(`    # forces replacement`);
  }

    // Get attribute changes with proper indentation (marker at column 0)
  // For create/destroy: NO markers (resource block already indicates action) - use '  '
  // For replace: use '!!' markers to highlight critical nature
  // For update: use differentiated markers (+, -, !)
  let changeLines;
  if (action === 'create') {
    // Create: no markers needed, entire block shows new resource
    changeLines = findChanges({}, after, afterUnknown, '    ', '  ', false);
  } else if (action === 'destroy') {
    // Destroy: no markers needed, entire block shows deleted resource
    changeLines = findChanges(before, {}, {}, '    ', '  ', false);
  } else if (isReplaceAction) {
    // Replace shows changes with '!!' markers for force replacement attributes
    changeLines = findChanges(before, after, afterUnknown, '    ', undefined, true);
  } else {
    // update uses '!' for modifications, '+' for adds, '-' for removes
    changeLines = findChanges(before, after, afterUnknown, '    ', undefined, false);
  }

  changeLines.forEach(l => lines.push(l));
  lines.push('}');

  return lines.join('\n');
}

/**
 * Parse Terraform JSON plan to extract resource changes
 * @param {string} jsonString - JSON plan content
 * @returns {Array} Array of parsed resource changes
 */
function parseJsonPlan(jsonString) {
  try {
    const plan = JSON.parse(jsonString);
    const resources = [];

    if (!plan.resource_changes) {
      console.warn('No resource_changes in plan JSON');
      return resources;
    }

    for (const change of plan.resource_changes) {
      if (!change.change || !change.change.actions || change.change.actions.includes('no-op')) {
        continue;
      }

      const actions = change.change.actions;
      let action = 'read';
      // Check replace first (delete + create)
      if (actions.includes('delete') && actions.includes('create')) action = 'replace';
      else if (actions.includes('create')) action = 'create';
      else if (actions.includes('update')) action = 'update';
      else if (actions.includes('delete')) action = 'destroy';

      const address = change.address;
      const resourceType = change.type;
      const resourceName = change.name;
      const details = formatResourceChange(change, action);

      resources.push({ address, action, type: resourceType, name: resourceName, details });
    }

    return resources;
  } catch (error) {
    console.error(`Failed to parse JSON plan: ${error.message}`);
    return [];
  }
}

/**
 * Calculate plan summary from parsed resources
 * @param {Array} resources - Parsed resources
 * @returns {Object} Summary object with add, change, destroy counts
 */
function calculateSummary(resources) {
  return {
    add: resources.filter(r => r.action === 'create').length,
    change: resources.filter(r => r.action === 'update' || r.action === 'replace').length,
    destroy: resources.filter(r => r.action === 'destroy').length,
    has_changes: resources.length > 0
  };
}

/**
 * Group resources by action type
 * @param {Array} resources - Parsed resources
 * @returns {Object} Grouped resources
 */
function groupResourcesByAction(resources) {
  return {
    creates: resources.filter(r => r.action === 'create'),
    updates: resources.filter(r => r.action === 'update'),
    replaces: resources.filter(r => r.action === 'replace'),
    destroys: resources.filter(r => r.action === 'destroy')
  };
}

// Export for both Node.js and browser
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    formatValue,
    findChanges,
    formatResourceChange,
    parseJsonPlan,
    calculateSummary,
    groupResourcesByAction
  };
}
