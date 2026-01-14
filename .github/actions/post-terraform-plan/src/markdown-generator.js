/**
 * Markdown Generator for Terraform Plan
 *
 * Generates GitHub-flavored markdown for Terraform plan output.
 * Optimized for visual appeal within GitHub's markdown constraints.
 */

const { groupResourcesByAction } = require('./terraform-plan-parser');

// Unique marker for finding this comment - MUST be at the start
const COMMENT_MARKER = '<!-- terraform-plan-comment -->';

/**
 * Action indicators for resource items
 */
const ACTION_INDICATORS = {
  create: '🟢 `+`',
  update: '🟡 `~`',
  replace: '🟣 `-/+`',
  destroy: '🔴 `-`'
};

/**
 * Action styling for sections
 */
const ACTION_STYLES = {
  create: { emoji: '🟢', icon: '➕', badge: '2eb039', label: 'CREATE' },
  update: { emoji: '🟡', icon: '✏️', badge: 'd4a017', label: 'UPDATE' },
  replace: { emoji: '🟣', icon: '🔄', badge: '5c4ee5', label: 'REPLACE' },
  destroy: { emoji: '🔴', icon: '🗑️', badge: 'c62b2b', label: 'DESTROY' }
};

/**
 * Generate a badge image URL
 */
function badge(label, value, color) {
  return `![${label}](https://img.shields.io/badge/${encodeURIComponent(label)}-${value}-${color}?style=flat-square)`;
}

/**
 * Build resource item with clean formatting
 * @param {Object} resource - Resource object
 * @returns {string} Markdown for resource item
 */
function buildResourceItem(resource) {
  const style = ACTION_STYLES[resource.action] || ACTION_STYLES.update;

  // Keep original formatting - the parser now generates proper indentation
  const details = resource.details || '# (no changes detected)';

  return `
<details>
<summary>${style.emoji} <code>${resource.address}</code></summary>

\`\`\`diff
${details}
\`\`\`

</details>`;
}

/**
 * Build section for a group of resources with enhanced formatting
 * @param {string} title - Section title
 * @param {string} action - Action type (create, update, replace, destroy)
 * @param {Array} resources - Resources in this group
 * @returns {string[]} Markdown lines
 */
function buildResourceSection(title, action, resources) {
  if (resources.length === 0) return [];

  const style = ACTION_STYLES[action] || ACTION_STYLES.update;
  const lines = [];

  lines.push('');
  lines.push(`### ${style.icon} ${title} · ${resources.length}`);
  lines.push('');

  resources.forEach(r => lines.push(buildResourceItem(r)));

  lines.push('');
  return lines;
}

/**
 * Generate PR comment markdown
 * @param {Object} options - Generation options
 * @param {Array} options.resources - Parsed resources
 * @param {Object} options.summary - Plan summary
 * @param {string} options.planOutcome - Plan outcome (success/failure)
 * @param {number} options.runNumber - GitHub Actions run number
 * @param {string} options.runUrl - URL to GitHub Actions run
 * @param {string} options.actor - GitHub actor (username)
 * @param {string} options.planJson - Raw plan JSON for fallback
 * @returns {string} Complete markdown content
 */
function generatePrComment(options) {
  const {
    resources,
    summary,
    planOutcome = 'success',
    runNumber = 1,
    runUrl = '#',
    actor = 'unknown',
    planJson = '{}'
  } = options;

  const { creates, updates, replaces, destroys } = groupResourcesByAction(resources);
  const hasChanges = summary.has_changes;
  const timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC';

  const sections = [];

  // Hidden marker for comment detection
  sections.push(COMMENT_MARKER);
  sections.push('');

  // Header with Terraform branding
  const statusIcon = planOutcome === 'success' ? '✅' : '❌';
  sections.push(`# ${statusIcon} Terraform Plan`);
  sections.push('');

  // Run info as a subtle line
  sections.push(`> 📋 **Run [#${runNumber}](${runUrl})** · ${timestamp} · @${actor}`);
  sections.push('');

  // Summary badges for visual impact
  if (hasChanges) {
    const badges = [];
    if (summary.add > 0) badges.push(badge('add', summary.add, '2eb039'));
    if (summary.change > 0) badges.push(badge('change', summary.change, 'd4a017'));
    if (summary.destroy > 0) badges.push(badge('destroy', summary.destroy, 'c62b2b'));

    sections.push(badges.join(' '));
    sections.push('');

    // Visual summary bar
    const total = summary.add + summary.change + summary.destroy;
    sections.push('```diff');
    if (summary.add > 0) sections.push(`+ ${summary.add} to add`);
    if (summary.change > 0) sections.push(`! ${summary.change} to change`);
    if (summary.destroy > 0) sections.push(`- ${summary.destroy} to destroy`);
    sections.push('```');
    sections.push('');
  }

  // No changes - success message
  if (!hasChanges) {
    sections.push('```');
    sections.push('✨ No changes. Your infrastructure matches the configuration.');
    sections.push('```');
    sections.push('');
  }

  // Resource sections
  if (creates.length > 0) {
    sections.push(...buildResourceSection('Resources to Create', 'create', creates));
  }

  if (replaces.length > 0) {
    sections.push(...buildResourceSection('Resources to Replace', 'replace', replaces));
  }

  if (updates.length > 0) {
    sections.push(...buildResourceSection('Resources to Update', 'update', updates));
  }

  if (destroys.length > 0) {
    sections.push(...buildResourceSection('Resources to Destroy', 'destroy', destroys));
  }

  // Fallback: show raw plan if no resources parsed but has changes
  if (resources.length === 0 && hasChanges) {
    sections.push('');
    sections.push('<details>');
    sections.push('<summary>📋 <strong>Raw Plan Output</strong></summary>');
    sections.push('');
    sections.push('```json');
    sections.push(planJson.length > 60000 ? planJson.substring(0, 60000) + '\n...(truncated)' : planJson);
    sections.push('```');
    sections.push('</details>');
    sections.push('');
  }

  // Footer
  sections.push('---');
  sections.push(`<sub>🔗 [View full workflow run](${runUrl})</sub>`);
  sections.push('');

  return sections.join('\n');
}

/**
 * Generate pipeline summary markdown (same format as PR comment but without marker)
 * @param {Object} options - Same as generatePrComment
 * @returns {string} Complete markdown content
 */
function generatePipelineSummary(options) {
  // Same as PR comment but without the hidden marker
  const content = generatePrComment(options);
  return content.replace(COMMENT_MARKER + '\n\n', '');
}

// Export for Node.js
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    COMMENT_MARKER,
    ACTION_INDICATORS,
    buildResourceItem,
    buildResourceSection,
    generatePrComment,
    generatePipelineSummary
  };
}
