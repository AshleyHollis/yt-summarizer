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
 * Extract relevant error information from terraform plan output
 * @param {string} planOutput - Raw terraform plan output
 * @returns {object} Extracted error details { type, message, details }
 */
function extractErrorDetails(planOutput) {
  if (!planOutput || planOutput.trim() === '') {
    return null;
  }

  const lines = planOutput.split('\n');
  
  // Detect state lock error
  if (planOutput.includes('state blob is already locked')) {
    const lockIdMatch = planOutput.match(/ID:\s+([a-f0-9-]+)/);
    const lockId = lockIdMatch ? lockIdMatch[1] : 'unknown';
    
    return {
      type: 'state_lock',
      message: 'Terraform state is locked',
      lockId,
      details: [
        `Lock ID: \`${lockId}\``,
        '',
        '**To unlock manually:**',
        '```bash',
        `terraform force-unlock ${lockId}`,
        '# OR',
        `./scripts/unlock-terraform-state.sh ${lockId}`,
        '```',
        '',
        '⚠️ **WARNING:** Only unlock if you\'re certain no other terraform operation is running.'
      ].join('\n')
    };
  }

  // Detect validation errors (Error: Invalid...)
  const errorLines = lines.filter(line => line.trim().startsWith('Error:'));
  if (errorLines.length > 0) {
    // Take first 10 error lines to avoid huge messages
    const errorSnippet = errorLines.slice(0, 10).join('\n');
    
    return {
      type: 'validation',
      message: 'Terraform validation failed',
      details: [
        '**Error details:**',
        '```',
        errorSnippet,
        errorLines.length > 10 ? `\n... and ${errorLines.length - 10} more errors` : '',
        '```'
      ].filter(Boolean).join('\n')
    };
  }

  // Detect provider/auth errors
  if (planOutput.includes('Error: reading') || planOutput.includes('Error: retrieving')) {
    return {
      type: 'provider',
      message: 'Provider authentication or connection error',
      details: [
        '**Possible causes:**',
        '- Azure credentials expired or invalid',
        '- Network connectivity issues',
        '- Provider API unavailable',
        '',
        'Check the workflow logs for detailed error messages.'
      ].join('\n')
    };
  }

  // Generic error fallback - extract first error block
  const firstErrorIdx = planOutput.indexOf('Error:');
  if (firstErrorIdx !== -1) {
    const errorBlock = planOutput.substring(firstErrorIdx, firstErrorIdx + 500);
    return {
      type: 'generic',
      message: 'Terraform plan failed',
      details: [
        '**Error snippet:**',
        '```',
        errorBlock,
        '```',
        '',
        'Check the workflow logs for complete error output.'
      ].join('\n')
    };
  }

  return null;
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
    planOutput = '',
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
  // Show failure icon if plan failed OR if there's an error in the summary
  const hasPlanError = planOutcome === 'failure' || planOutcome === 'skipped' || summary.error;
  const statusIcon = hasPlanError ? '❌' : '✅';
  sections.push(`# ${statusIcon} Terraform Plan`);
  sections.push('');

  // Run info as a subtle line
  sections.push(`> 📋 **Run [#${runNumber}](${runUrl})** · ${timestamp} · @${actor}`);
  sections.push('');

  // Check for errors first
  if (summary.error) {
    sections.push('```diff');
    sections.push(`- ❌ Terraform Plan Failed`);
    sections.push('');
    sections.push(`Error: ${summary.error}`);
    sections.push('```');
    sections.push('');
    sections.push('> ⚠️ **The plan failed to execute.** Check the workflow logs for detailed error messages.');
    sections.push('');
  } else if (planOutcome === 'failure' || planOutcome === 'skipped') {
    const errorDetails = extractErrorDetails(planOutput);
    
    sections.push('```diff');
    sections.push(`- ❌ ${planOutcome === 'skipped' ? 'Could not produce Terraform Plan' : 'Terraform Plan Failed'}`);
    sections.push('```');
    sections.push('');
    
    // Display extracted error details if available
    if (errorDetails) {
      sections.push(`### ${errorDetails.message}`);
      sections.push('');
      sections.push(errorDetails.details);
      sections.push('');
    } else {
      sections.push('> ⚠️ **Could not determine infrastructure changes.**');
      sections.push('');
      sections.push(`Check the [workflow logs](${runUrl}) for detailed error messages.`);
      sections.push('');
    }
  } else if (hasChanges) {
    // Summary badges for visual impact
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
  } else {
    // No changes - success message
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
