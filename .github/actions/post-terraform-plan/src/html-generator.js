/**
 * HTML Generator for Terraform Plan
 *
 * Generates a beautiful HTML preview styled like Terraform Cloud.
 */

const { groupResourcesByAction } = require('./terraform-plan-parser');

/**
 * Terraform Cloud color palette
 */
const COLORS = {
  purple: '#5c4ee5',
  purpleDark: '#4040b2',
  green: '#2eb039',
  greenBg: '#e5f5e7',
  yellow: '#d4a017',
  yellowBg: '#fef9e5',
  red: '#c62b2b',
  redBg: '#fce8e8',
  blue: '#1563c0',
  blueBg: '#e8f1fc',
  gray: '#6b7280',
  grayLight: '#f3f4f6',
  grayDark: '#374151',
  white: '#ffffff',
  black: '#1f2937'
};

/**
 * Get Terraform logo SVG
 */
function getTerraformLogo() {
  return `<svg viewBox="0 0 64 64" xmlns="http://www.w3.org/2000/svg" width="40" height="40">
    <g fill="${COLORS.purple}">
      <path d="M22.4 0v20.2L40 30.4V10.2L22.4 0z"/>
      <path d="M42.2 21.3v20.2l17.6-10.2V11.1L42.2 21.3z"/>
      <path d="M4.2 11.1v20.2L22 41.5V21.3L4.2 11.1z"/>
      <path d="M22.4 43.7V64l17.6-10.2V33.6l-17.6 10.1z"/>
    </g>
  </svg>`;
}

/**
 * Action icons and colors
 */
const ACTION_STYLES = {
  create: {
    icon: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/></svg>`,
    color: COLORS.green,
    bgColor: COLORS.greenBg,
    label: 'create',
    symbol: '+'
  },
  update: {
    icon: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"/></svg>`,
    color: COLORS.yellow,
    bgColor: COLORS.yellowBg,
    label: 'update',
    symbol: '~'
  },
  replace: {
    icon: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="17 1 21 5 17 9"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><polyline points="7 23 3 19 7 15"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/></svg>`,
    color: COLORS.purple,
    bgColor: COLORS.blueBg,
    label: 'replace',
    symbol: '-/+'
  },
  destroy: {
    icon: `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="8" y1="12" x2="16" y2="12"/></svg>`,
    color: COLORS.red,
    bgColor: COLORS.redBg,
    label: 'destroy',
    symbol: '-'
  }
};

/**
 * Generate HTML styles
 */
function generateStyles() {
  return `
    <style>
      * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
      }

      body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
        background-color: #f8f9fa;
        color: ${COLORS.black};
        line-height: 1.5;
        padding: 20px;
      }

      .container {
        max-width: 1200px;
        margin: 0 auto;
      }

      /* Header with Terraform branding */
      .header {
        background: linear-gradient(135deg, ${COLORS.purple} 0%, ${COLORS.purpleDark} 100%);
        color: white;
        padding: 24px 32px;
        border-radius: 12px 12px 0 0;
        display: flex;
        align-items: center;
        gap: 16px;
      }

      .header-logo {
        display: flex;
        align-items: center;
        gap: 12px;
      }

      .header-logo svg {
        filter: brightness(0) invert(1);
      }

      .header-title {
        font-size: 24px;
        font-weight: 600;
        display: flex;
        align-items: center;
        gap: 8px;
      }

      .header-subtitle {
        font-size: 14px;
        opacity: 0.8;
        margin-top: 4px;
      }

      .status-badge {
        margin-left: auto;
        padding: 8px 16px;
        border-radius: 20px;
        font-weight: 600;
        font-size: 14px;
        display: flex;
        align-items: center;
        gap: 6px;
      }

      .status-badge.success {
        background: rgba(46, 176, 57, 0.2);
        color: #7cff8d;
      }

      .status-badge.failure {
        background: rgba(198, 43, 43, 0.2);
        color: #ff8d8d;
      }

      /* Main content */
      .content {
        background: white;
        border: 1px solid #e5e7eb;
        border-top: none;
        border-radius: 0 0 12px 12px;
        padding: 24px 32px;
      }

      /* Run info bar */
      .run-info {
        display: flex;
        align-items: center;
        gap: 16px;
        padding: 12px 16px;
        background: ${COLORS.grayLight};
        border-radius: 8px;
        margin-bottom: 24px;
        font-size: 14px;
        color: ${COLORS.gray};
        flex-wrap: wrap;
      }

      .run-info a {
        color: ${COLORS.purple};
        text-decoration: none;
        font-weight: 500;
      }

      .run-info a:hover {
        text-decoration: underline;
      }

      .run-info-divider {
        width: 1px;
        height: 16px;
        background: #d1d5db;
      }

      /* Summary stats */
      .summary {
        display: flex;
        gap: 16px;
        margin-bottom: 24px;
        flex-wrap: wrap;
      }

      .summary-item {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 12px 20px;
        border-radius: 8px;
        font-weight: 600;
        font-size: 15px;
      }

      .summary-item.add {
        background: ${COLORS.greenBg};
        color: ${COLORS.green};
      }

      .summary-item.change {
        background: ${COLORS.yellowBg};
        color: ${COLORS.yellow};
      }

      .summary-item.destroy {
        background: ${COLORS.redBg};
        color: ${COLORS.red};
      }

      .summary-count {
        font-size: 24px;
        font-weight: 700;
      }

      /* Resource sections */
      .section {
        margin-bottom: 16px;
        border: 1px solid #e5e7eb;
        border-radius: 8px;
        overflow: hidden;
      }

      .section-header {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 16px 20px;
        background: ${COLORS.grayLight};
        cursor: pointer;
        user-select: none;
        transition: background-color 0.2s;
      }

      .section-header:hover {
        background: #e5e7eb;
      }

      .section-icon {
        display: flex;
        align-items: center;
        justify-content: center;
        width: 28px;
        height: 28px;
        border-radius: 50%;
      }

      .section-title {
        font-weight: 600;
        font-size: 15px;
        flex: 1;
      }

      .section-count {
        padding: 4px 12px;
        border-radius: 12px;
        font-size: 13px;
        font-weight: 600;
      }

      .section-chevron {
        color: ${COLORS.gray};
        transition: transform 0.2s;
      }

      .section.open .section-chevron {
        transform: rotate(90deg);
      }

      .section-content {
        display: none;
        border-top: 1px solid #e5e7eb;
      }

      .section.open .section-content {
        display: block;
      }

      /* Resource items */
      .resource {
        border-bottom: 1px solid #f3f4f6;
      }

      .resource:last-child {
        border-bottom: none;
      }

      .resource-header {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 14px 20px;
        cursor: pointer;
        transition: background-color 0.2s;
      }

      .resource-header:hover {
        background: #fafafa;
      }

      .resource-symbol {
        font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
        font-size: 14px;
        font-weight: 700;
        width: 32px;
        text-align: center;
      }

      .resource-address {
        font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
        font-size: 13px;
        color: ${COLORS.grayDark};
        flex: 1;
        word-break: break-all;
      }

      .resource-chevron {
        color: ${COLORS.gray};
        transition: transform 0.2s;
      }

      .resource.open .resource-chevron {
        transform: rotate(90deg);
      }

      .resource-details {
        display: none;
        padding: 0 20px 16px 64px;
      }

      .resource.open .resource-details {
        display: block;
      }

      /* Code block for resource details */
      pre {
        background: #1e1e1e;
        color: #d4d4d4;
        padding: 16px;
        border-radius: 8px;
        overflow-x: auto;
        font-family: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
        font-size: 13px;
        line-height: 1.6;
        white-space: pre-wrap;
        word-break: break-word;
      }

      /* Syntax highlighting in code blocks */
      .hl-add { color: #73c990; }
      .hl-remove { color: #e06c75; }
      .hl-change { color: #e5c07b; }
      .hl-replace { color: #c678dd; }
      .hl-comment { color: #7f848e; font-style: italic; }
      .hl-string { color: #98c379; }
      .hl-keyword { color: #61afef; }
      .hl-value { color: #d19a66; }

      /* No changes message */
      .no-changes {
        text-align: center;
        padding: 48px;
        color: ${COLORS.gray};
      }

      .no-changes-icon {
        font-size: 48px;
        margin-bottom: 16px;
      }

      .no-changes-text {
        font-size: 16px;
        font-weight: 500;
        color: ${COLORS.green};
      }

      /* Footer */
      .footer {
        text-align: center;
        padding: 16px;
        color: ${COLORS.gray};
        font-size: 12px;
      }

      .footer a {
        color: ${COLORS.purple};
        text-decoration: none;
      }

      .footer a:hover {
        text-decoration: underline;
      }

      /* Responsive */
      @media (max-width: 768px) {
        body {
          padding: 10px;
        }

        .header {
          flex-direction: column;
          align-items: flex-start;
          padding: 16px 20px;
        }

        .status-badge {
          margin-left: 0;
          margin-top: 12px;
        }

        .summary {
          flex-direction: column;
        }

        .run-info {
          flex-direction: column;
          align-items: flex-start;
          gap: 8px;
        }

        .run-info-divider {
          display: none;
        }
      }
    </style>
  `;
}

/**
 * Generate JavaScript for interactivity
 */
function generateScript() {
  return `
    <script>
      document.addEventListener('DOMContentLoaded', function() {
        // Toggle sections
        document.querySelectorAll('.section-header').forEach(function(header) {
          header.addEventListener('click', function() {
            this.parentElement.classList.toggle('open');
          });
        });

        // Toggle resources
        document.querySelectorAll('.resource-header').forEach(function(header) {
          header.addEventListener('click', function() {
            this.parentElement.classList.toggle('open');
          });
        });

        // Open first section and first resource by default
        var firstSection = document.querySelector('.section');
        if (firstSection) {
          firstSection.classList.add('open');
          var firstResource = firstSection.querySelector('.resource');
          if (firstResource) {
            firstResource.classList.add('open');
          }
        }
      });
    </script>
  `;
}

/**
 * Escape HTML special characters
 */
function escapeHtml(text) {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/**
 * Highlight syntax in code
 * First escapes HTML, then applies highlighting to avoid nested tags
 */
function highlightCode(code) {
  // First escape HTML to prevent injection
  let escaped = escapeHtml(code);

  // Process line by line for cleaner highlighting
  const lines = escaped.split('\n');
  const highlighted = lines.map(line => {
    // Detect line type by first non-whitespace character
    const trimmed = line.trimStart();
    const indent = line.match(/^(\s*)/)[0];

    if (trimmed.startsWith('+ ')) {
      return `<span class="hl-add">${line}</span>`;
    } else if (trimmed.startsWith('- ')) {
      return `<span class="hl-remove">${line}</span>`;
    } else if (trimmed.startsWith('~ ')) {
      return `<span class="hl-change">${line}</span>`;
    } else if (trimmed.startsWith('#')) {
      return `<span class="hl-comment">${line}</span>`;
    } else if (trimmed.startsWith('-/+ ')) {
      return `<span class="hl-replace">${line}</span>`;
    }
    return line;
  });

  return highlighted.join('\n');
}

/**
 * Build resource item HTML
 */
function buildResourceItemHtml(resource) {
  const style = ACTION_STYLES[resource.action];
  const cleanDetails = resource.details
    .split('\n')
    .filter(l => l.trim())
    .map(l => l.replace(/^\s{4}/, ''))
    .join('\n');

  const highlightedCode = highlightCode(cleanDetails);

  return `
    <div class="resource">
      <div class="resource-header">
        <span class="resource-symbol" style="color: ${style.color}">${style.symbol}</span>
        <span class="resource-address">${resource.address}</span>
        <svg class="resource-chevron" xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
      </div>
      <div class="resource-details">
        <pre>${highlightedCode || '(no details)'}</pre>
      </div>
    </div>
  `;
}

/**
 * Build section HTML
 */
function buildSectionHtml(title, action, resources) {
  if (resources.length === 0) return '';

  const style = ACTION_STYLES[action];
  const resourcesHtml = resources.map(r => buildResourceItemHtml(r)).join('');

  return `
    <div class="section">
      <div class="section-header">
        <div class="section-icon" style="background: ${style.bgColor}; color: ${style.color}">
          ${style.icon}
        </div>
        <span class="section-title">${title}</span>
        <span class="section-count" style="background: ${style.bgColor}; color: ${style.color}">${resources.length}</span>
        <svg class="section-chevron" xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
      </div>
      <div class="section-content">
        ${resourcesHtml}
      </div>
    </div>
  `;
}

/**
 * Generate complete HTML page
 */
function generateHtml(options) {
  const {
    resources,
    summary,
    planOutcome = 'success',
    runNumber = 1,
    runUrl = '#',
    actor = 'developer',
    timestamp = new Date().toISOString().replace('T', ' ').substring(0, 19) + ' UTC'
  } = options;

  const { creates, updates, replaces, destroys } = groupResourcesByAction(resources);
  const hasChanges = summary.has_changes;

  const statusBadge = planOutcome === 'success'
    ? `<span class="status-badge success">✓ Plan Succeeded</span>`
    : `<span class="status-badge failure">✗ Plan Failed</span>`;

  let summaryHtml = '';
  if (hasChanges) {
    summaryHtml = `
      <div class="summary">
        ${summary.add > 0 ? `<div class="summary-item add"><span class="summary-count">${summary.add}</span> to add</div>` : ''}
        ${summary.change > 0 ? `<div class="summary-item change"><span class="summary-count">${summary.change}</span> to change</div>` : ''}
        ${summary.destroy > 0 ? `<div class="summary-item destroy"><span class="summary-count">${summary.destroy}</span> to destroy</div>` : ''}
      </div>
    `;
  }

  let contentHtml = '';
  if (hasChanges) {
    contentHtml = `
      ${buildSectionHtml('Resources to Add', 'create', creates)}
      ${buildSectionHtml('Resources to Replace', 'replace', replaces)}
      ${buildSectionHtml('Resources to Update', 'update', updates)}
      ${buildSectionHtml('Resources to Destroy', 'destroy', destroys)}
    `;
  } else {
    contentHtml = `
      <div class="no-changes">
        <div class="no-changes-icon">✨</div>
        <div class="no-changes-text">No changes. Your infrastructure matches the configuration.</div>
      </div>
    `;
  }

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Terraform Plan - Run #${runNumber}</title>
  ${generateStyles()}
</head>
<body>
  <div class="container">
    <header class="header">
      <div class="header-logo">
        ${getTerraformLogo()}
        <div>
          <div class="header-title">Terraform Plan</div>
          <div class="header-subtitle">Infrastructure as Code</div>
        </div>
      </div>
      ${statusBadge}
    </header>

    <main class="content">
      <div class="run-info">
        <a href="${runUrl}">Run #${runNumber}</a>
        <div class="run-info-divider"></div>
        <span>${timestamp}</span>
        <div class="run-info-divider"></div>
        <span>by @${actor}</span>
        <div class="run-info-divider"></div>
        <a href="${runUrl}">View Workflow →</a>
      </div>

      ${summaryHtml}
      ${contentHtml}
    </main>

    <footer class="footer">
      <p>Generated by <a href="https://github.com/hashicorp/terraform">Terraform</a> Plan Visualizer</p>
    </footer>
  </div>
  ${generateScript()}
</body>
</html>`;
}

// Export for Node.js
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    COLORS,
    ACTION_STYLES,
    generateHtml,
    generateStyles,
    generateScript,
    highlightCode,
    buildResourceItemHtml,
    buildSectionHtml
  };
}
