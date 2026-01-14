/**
 * Resource Change Formatter Module
 *
 * Formats individual resource changes into Terraform-style output.
 * Uses post-processor to apply consistent indentation.
 */

const { findChanges } = require('./change-detection');
const { getResourceHeaderMarker } = require('./formatters/diff-marker');
const { applyIndentation } = require('./post-process');

/**
 * Determine the force marker for a given action type
 * @param {string} action - Action type (create, update, destroy, replace)
 * @returns {string|null} Force marker or null
 */
function getForceMarkerForAction(action) {
  if (action === 'create') {
    return '  ';
  }
  if (action === 'destroy') {
    return '  ';
  }
  return null;
}

/**
 * Determine if an action is a replace action
 * @param {string} action - Action type
 * @returns {boolean} True if replace action
 */
function isReplaceAction(action) {
  return action === 'replace';
}

/**
 * Format resource change details
 * @param {Object} change - Resource change object from Terraform plan
 * @param {string} action - Action type (create, update, destroy, replace)
 * @returns {string} Formatted diff output with proper indentation
 */
function formatResourceChange(change, action) {
  const lines = [];
  const before = change.change.before || {};
  const after = change.change.after || {};
  const afterUnknown = change.change.after_unknown || {};

  const isReplace = isReplaceAction(action);
  const forceMarker = getForceMarkerForAction(action);

  // Resource header with marker (like real Terraform output)
  const resourceMarker = getResourceHeaderMarker(action);
  lines.push(`${resourceMarker} resource "${change.type}" "${change.name}" {`);

  if (isReplace) {
    lines.push(`    # forces replacement`);
  }

  // Get attribute changes with canonical format (no indentation logic)
  const changeLines = findChanges(before, after, afterUnknown, '    ', forceMarker, isReplace);

  if (changeLines.length === 0 && action === 'update') {
    return null;
  }

  changeLines.forEach(l => lines.push(l));
  lines.push('}');

  // Apply post-processing for consistent 4-space indentation
  const fixedLines = applyIndentation(lines);

  return fixedLines.join('\n');
}

module.exports = {
  formatResourceChange,
  getForceMarkerForAction,
  isReplaceAction
};
