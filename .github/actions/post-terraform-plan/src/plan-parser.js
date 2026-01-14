/**
 * Terraform Plan Parser Module
 *
 * Parses Terraform JSON plan output and generates structured resource change data.
 */

const { formatResourceChange } = require('./resource-change-formatter');

/**
 * Determine the action type from Terraform actions array
 * @param {Array<string>} actions - Action array from Terraform plan
 * @returns {string} Action type (create, update, destroy, replace)
 */
function determineActionType(actions) {
  // Check replace first (delete + create)
  if (actions.includes('delete') && actions.includes('create')) {
    return 'replace';
  }
  if (actions.includes('create')) {
    return 'create';
  }
  if (actions.includes('update')) {
    return 'update';
  }
  if (actions.includes('delete')) {
    return 'destroy';
  }
  return 'read';
}

/**
 * Check if a change should be included (exclude no-op actions)
 * @param {Object} change - Resource change object
 * @returns {boolean} True if change should be included
 */
function shouldIncludeChange(change) {
  if (!change.change || !change.change.actions) {
    return false;
  }
  return !change.change.actions.includes('no-op');
}

/**
 * Parse a single resource change
 * @param {Object} change - Resource change from Terraform plan
 * @returns {Object|null} Parsed resource or null if should be excluded
 */
function parseResourceChange(change) {
  if (!shouldIncludeChange(change)) {
    return null;
  }

  const actions = change.change.actions;
  const action = determineActionType(actions);

  const details = formatResourceChange(change, action);

  if (!details) {
    return null;
  }

  return {
    address: change.address,
    action,
    type: change.type,
    name: change.name,
    details
  };
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
      const parsed = parseResourceChange(change);
      if (parsed) {
        resources.push(parsed);
      }
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

module.exports = {
  parseJsonPlan,
  calculateSummary,
  groupResourcesByAction,
  determineActionType,
  shouldIncludeChange,
  parseResourceChange
};
