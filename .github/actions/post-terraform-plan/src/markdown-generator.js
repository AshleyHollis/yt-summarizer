/**
 * Markdown Generator for Terraform Plan
 *
 * Generates GitHub-flavored markdown for Terraform plan output.
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
 * Build resource item with emoji indicators and task list styling
 * @param {Object} resource - Resource object
 * @returns {string} Markdown for resource item
 */
function buildResourceItem(resource) {
  const indicator = ACTION_INDICATORS[resource.action] || '⚪ `?`';
  const cleanDetails = resource.details
    .split('\n')
    .filter(l => l.trim())
    .map(l => l.replace(/^\s{4}/, ''))
    .join('\n');

  return `<details>
<summary><code>${resource.address}</code></summary>

\`\`\`terraform
${cleanDetails || '(no details)'}
\`\`\`

</details>`;
}

/**
 * Build section for a group of resources with enhanced formatting
 * @param {string} title - Section title
 * @param {string} emoji - Emoji for section header
 * @param {string} icon - Icon for task list items
 * @param {Array} resources - Resources in this group
 * @returns {string[]} Markdown lines
 */
function buildResourceSection(title, emoji, icon, resources) {
  if (resources.length === 0) return [];

  const lines = [];
  lines.push('---');
  lines.push('');
  lines.push(`### ${emoji} ${title} (${resources.length})`);
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

  // Header - "Terraform Plan" with status icon
  const statusIcon = planOutcome === 'success' ? '✅' : '❌';
  sections.push(`## ${statusIcon} Terraform Plan`);
  sections.push('');

  // GitHub Info banner
  sections.push(`**Run:** [#${runNumber}](${runUrl}) | **Date:** ${timestamp} | **By:** @${actor}`);
  sections.push('');

  // GitHub Alert for action (note/success/warning)
  if (planOutcome === 'success' && !hasChanges) {
    sections.push('> [!SUCCESS]');
    sections.push('> ✨ No changes. Your infrastructure matches the configuration.');
    sections.push('');
  } else if (planOutcome === 'success' && hasChanges) {
    sections.push('> [!NOTE]');
    sections.push('> 📊 Infrastructure changes detected. Review the changes below.');
    sections.push('');
  } else {
    sections.push('> [!ERROR]');
    sections.push('> ❌ Terraform plan failed. Check the logs for details.');
    sections.push('');
  }

  // Resource summary as a clean table
  if (hasChanges) {
    sections.push('### 📋 Resource Summary');
    sections.push('');
    const tableRow = (emoji, action, count) => count > 0 ? `| ${emoji} ${action} | **${count}** |` : '';
    sections.push('| Action | Count |');
    sections.push('|---------|-------|');
    sections.push(tableRow('🟢', 'Create', summary.add));
    sections.push(tableRow('🟣', 'Replace', summary.add + summary.destroy));
    sections.push(tableRow('🟡', 'Update', summary.change));
    sections.push(tableRow('🔴', 'Destroy', summary.destroy));
    sections.push('');
  }

  // Resource sections with horizontal separators
  sections.push(...buildResourceSection('Create', '🟢', 'create', creates));
  sections.push(...buildResourceSection('Replace', '🟣', 'replace', replaces));
  sections.push(...buildResourceSection('Update', '🟡', 'update', updates));
  sections.push(...buildResourceSection('Destroy', '🔴', 'destroy', destroys));

  // Fallback: show raw plan if no resources parsed but has changes
  if (resources.length === 0 && hasChanges) {
    sections.push('---');
    sections.push('');
    sections.push('<details>');
    sections.push('<summary><strong>📋 Raw Plan Output</strong></summary>');
    sections.push('');
    sections.push('```json');
    sections.push(planJson.length > 60000 ? planJson.substring(0, 60000) + '\n...(truncated)' : planJson);
    sections.push('```');
    sections.push('</details>');
    sections.push('');
  }

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
