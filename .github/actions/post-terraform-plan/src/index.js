/**
 * Post Terraform Plan - Main Entry Point
 *
 * This module re-exports all functionality and provides CLI tools
 * for local development and testing.
 */

const {
  parseJsonPlan,
  calculateSummary,
  groupResourcesByAction,
  formatValue,
  findChanges,
  formatResourceChange
} = require('./terraform-plan-parser');

const {
  generatePrComment,
  generatePipelineSummary,
  COMMENT_MARKER,
  ACTION_INDICATORS
} = require('./markdown-generator');

const {
  generateHtml,
  COLORS,
  ACTION_STYLES
} = require('./html-generator');

module.exports = {
  // Parser exports
  parseJsonPlan,
  calculateSummary,
  groupResourcesByAction,
  formatValue,
  findChanges,
  formatResourceChange,

  // Markdown exports
  generatePrComment,
  generatePipelineSummary,
  COMMENT_MARKER,
  ACTION_INDICATORS,

  // HTML exports
  generateHtml,
  COLORS,
  ACTION_STYLES
};
