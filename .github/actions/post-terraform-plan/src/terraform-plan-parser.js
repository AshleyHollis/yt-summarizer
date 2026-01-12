/**
 * Terraform Plan Parser
 *
 * Parses Terraform JSON plan output and generates formatted markdown/HTML.
 * This module is designed to work both in GitHub Actions and for local development.
 */

/**
 * Format a value for display (Terraform-style)
 * @param {*} value - The value to format
 * @param {boolean} unknown - Whether the value is unknown (known after apply)
 * @returns {string} Formatted value string
 */
function formatValue(value, unknown) {
  if (unknown === true) return '(known after apply)';
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
 * Recursively find all changes between before and after states
 * Format optimized for GitHub diff syntax highlighting (markers at column 0)
 * @param {Object} before - Before state
 * @param {Object} after - After state
 * @param {Object} afterUnknown - Unknown values in after state
 * @param {string} prefix - Indentation prefix (spaces only, no markers)
 * @returns {string[]} Array of formatted change lines
 */
function findChanges(before, after, afterUnknown, prefix = '  ') {
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

    // Skip if values are identical
    if (beforeExists && afterExists && JSON.stringify(beforeVal) === JSON.stringify(afterVal)) {
      continue;
    }

    // Handle nested objects/blocks
    if (typeof afterVal === 'object' && afterVal !== null && !Array.isArray(afterVal) &&
        typeof beforeVal === 'object' && beforeVal !== null && !Array.isArray(beforeVal)) {
      const nestedLines = findChanges(beforeVal, afterVal, isUnknown || {}, prefix + '    ');
      if (nestedLines.length > 0) {
        lines.push(`~ ${prefix}${key} {`);
        nestedLines.forEach(l => lines.push(l));
        lines.push(`  ${prefix}}`);
      }
      continue;
    }

    // Handle arrays (blocks in Terraform)
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
            const nestedLines = findChanges(bItem, aItem, unknownItem || {}, prefix + '    ');
            if (nestedLines.length > 0) {
              lines.push(`~ ${prefix}${key} {`);
              nestedLines.forEach(l => lines.push(l));
              lines.push(`  ${prefix}}`);
            }
          } else if (aItem && !bItem) {
            lines.push(`+ ${prefix}${key} {`);
            const nestedLines = findChanges({}, aItem, unknownItem || {}, prefix + '    ');
            nestedLines.forEach(l => lines.push(l));
            lines.push(`  ${prefix}}`);
          } else if (bItem && !aItem) {
            lines.push(`- ${prefix}${key} {`);
            lines.push(`- ${prefix}    # (block removed)`);
            lines.push(`  ${prefix}}`);
          }
        }
      } else {
        // Simple array comparison
        if (JSON.stringify(beforeArr) !== JSON.stringify(afterArr)) {
          lines.push(`~ ${prefix}${key} = ${formatValue(beforeVal, false)} -> ${formatValue(afterVal, isUnknown)}`);
        }
      }
      continue;
    }

    // Value added
    if (!beforeExists && afterExists) {
      lines.push(`+ ${prefix}${key} = ${formatValue(afterVal, isUnknown)}`);
      continue;
    }

    // Value removed
    if (beforeExists && !afterExists) {
      lines.push(`- ${prefix}${key} = ${formatValue(beforeVal, false)}`);
      continue;
    }

    // Value changed (including null transitions)
    if (beforeExists && afterExists) {
      const beforeFormatted = formatValue(beforeVal, false);
      const afterFormatted = formatValue(afterVal, isUnknown);
      lines.push(`~ ${prefix}${key} = ${beforeFormatted} -> ${afterFormatted}`);
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

  // Use diff-compatible prefixes at column 0
  const symbol = action === 'create' ? '+' : action === 'update' ? '~' : action === 'replace' ? '!' : '-';

  // Resource header with marker at column 0 for diff highlighting
  lines.push(`${symbol} resource "${change.type}" "${change.name}" {`);

  if (action === 'replace') {
    lines.push(`! # forces replacement`);
  }

  // Get attribute changes with proper indentation (marker at column 0)
  let changeLines;
  if (action === 'create') {
    changeLines = findChanges({}, after, afterUnknown, '    ');
  } else if (action === 'update' || action === 'replace') {
    changeLines = findChanges(before, after, afterUnknown, '    ');
  } else if (action === 'destroy') {
    changeLines = findChanges(before, {}, {}, '    ');
  }

  changeLines.forEach(l => lines.push(l));
  lines.push(`  }`);

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
