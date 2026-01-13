/**
 * Terraform Plan Parser - Main Entry Point
 *
 * Refactored version with modular, testable architecture following clean code principles.
 * This module is designed to work both in GitHub Actions and for local development.
 *
 * Architecture:
 * - utils/value-validator.js: Value validation utilities
 * - formatters/value-formatter.js: Value formatting
 * - formatters/array-formatter.js: Array formatting (multi-line, inline)
 * - formatters/diff-marker.js: Diff marker determination
 * - change-detection.js: Recursive change detection and formatting
 * - resource-change-formatter.js: Resource-level change formatting
 * - plan-parser.js: Plan parsing and resource grouping
 */

// Core modules
const { parseJsonPlan, calculateSummary, groupResourcesByAction } = require('./plan-parser');
const { findChanges } = require('./change-detection');
const { formatResourceChange } = require('./resource-change-formatter');
const { formatValue } = require('./formatters/value-formatter');
const { formatMultilineArray } = require('./formatters/array-formatter');

// For backward compatibility with original API
const {
  isMeaningfulValue
} = require('./utils/value-validator');

// Export for both Node.js and browser (backward compatible with original API)
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    // Public API (backward compatible)
    parseJsonPlan,
    calculateSummary,
    groupResourcesByAction,
    formatValue,
    formatMultilineArray,
    findChanges,
    formatResourceChange,
    // Legacy export for compatibility
    isMeaningfulValue
  };
}
