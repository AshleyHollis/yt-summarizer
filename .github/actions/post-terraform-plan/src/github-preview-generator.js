/**
 * GitHub Preview Generator for Terraform Plan
 *
 * Generates an HTML preview that renders markdown EXACTLY as GitHub does.
 * Uses:
 * - marked: GitHub Flavored Markdown parser
 * - GitHub Primer CSS: The actual styles GitHub uses
 *
 * This ensures what you see locally IS what you get on GitHub.
 */

const { generatePrComment } = require('./markdown-generator');

/**
 * Generate HTML that renders markdown exactly like GitHub
 * @param {string} markdown - The markdown content to render
 * @param {Object} options - Options for the preview
 * @returns {string} Complete HTML page
 */
function generateGitHubPreview(markdown, options = {}) {
  const { title = 'GitHub Preview', darkMode = false } = options;

  // GitHub's Primer CSS CDN - this is the actual CSS GitHub uses
  const primerCss = darkMode
    ? 'https://cdnjs.cloudflare.com/ajax/libs/github-markdown-css/5.5.1/github-markdown-dark.min.css'
    : 'https://cdnjs.cloudflare.com/ajax/libs/github-markdown-css/5.5.1/github-markdown-light.min.css';

  // Escape the markdown for safe embedding in JavaScript
  const escapedMarkdown = markdown
    .replace(/\\/g, '\\\\')
    .replace(/`/g, '\\`')
    .replace(/\$/g, '\\$');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title}</title>

  <!-- GitHub Primer CSS - the actual styles GitHub uses -->
  <link rel="stylesheet" href="${primerCss}">

  <!-- marked.js for GitHub Flavored Markdown parsing -->
  <script src="https://cdn.jsdelivr.net/npm/marked/marked.min.js"></script>

  <style>
    /* Match GitHub's PR comment container */
    body {
      background: ${darkMode ? '#0d1117' : '#ffffff'};
      padding: 0;
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Noto Sans', Helvetica, Arial, sans-serif;
    }

    .github-container {
      max-width: 1012px;
      margin: 0 auto;
      padding: 32px 16px;
    }

    /* Mode toggle */
    .mode-toggle {
      position: fixed;
      top: 16px;
      right: 16px;
      display: flex;
      gap: 8px;
      z-index: 100;
    }

    .mode-toggle button {
      padding: 8px 16px;
      border: 1px solid ${darkMode ? '#30363d' : '#d0d7de'};
      background: ${darkMode ? '#21262d' : '#f6f8fa'};
      color: ${darkMode ? '#c9d1d9' : '#24292f'};
      border-radius: 6px;
      cursor: pointer;
      font-size: 14px;
    }

    .mode-toggle button:hover {
      background: ${darkMode ? '#30363d' : '#eaeef2'};
    }

    .mode-toggle button.active {
      background: #0969da;
      color: white;
      border-color: #0969da;
    }

    /* GitHub PR comment styling */
    .pr-comment {
      border: 1px solid ${darkMode ? '#30363d' : '#d0d7de'};
      border-radius: 6px;
      background: ${darkMode ? '#0d1117' : '#ffffff'};
    }

    .pr-comment-header {
      padding: 8px 16px;
      background: ${darkMode ? '#161b22' : '#f6f8fa'};
      border-bottom: 1px solid ${darkMode ? '#30363d' : '#d0d7de'};
      border-radius: 6px 6px 0 0;
      display: flex;
      align-items: center;
      gap: 8px;
      font-size: 14px;
      color: ${darkMode ? '#8b949e' : '#57606a'};
    }

    .pr-comment-header img {
      width: 32px;
      height: 32px;
      border-radius: 50%;
    }

    .pr-comment-header strong {
      color: ${darkMode ? '#c9d1d9' : '#24292f'};
    }

    .pr-comment-body {
      padding: 16px;
    }

    /* Apply GitHub markdown styles */
    .markdown-body {
      box-sizing: border-box;
      min-width: 200px;
      max-width: 980px;
      margin: 0 auto;
    }

    /* Fix for GitHub alerts/callouts */
    .markdown-body blockquote {
      margin: 16px 0;
      padding: 0 1em;
      color: ${darkMode ? '#8b949e' : '#57606a'};
      border-left: 0.25em solid ${darkMode ? '#30363d' : '#d0d7de'};
    }

    /* GitHub-style note/warning/caution boxes */
    .markdown-body blockquote p:first-child {
      margin-top: 0;
    }

    /* GitHub alerts styling */
    .markdown-body > blockquote:has(p:first-child:contains("[!NOTE]")),
    .markdown-body > blockquote:has(p:first-child:contains("[!WARNING]")),
    .markdown-body > blockquote:has(p:first-child:contains("[!IMPORTANT]")),
    .markdown-body > blockquote:has(p:first-child:contains("[!CAUTION]")) {
      padding: 8px 16px;
      border-radius: 6px;
    }

    /* Info box for preview mode */
    .preview-info {
      background: ${darkMode ? '#161b22' : '#f6f8fa'};
      border: 1px solid ${darkMode ? '#30363d' : '#d0d7de'};
      border-radius: 6px;
      padding: 16px;
      margin-bottom: 24px;
      display: flex;
      align-items: center;
      gap: 12px;
    }

    .preview-info-icon {
      font-size: 24px;
    }

    .preview-info-text {
      flex: 1;
    }

    .preview-info-title {
      font-weight: 600;
      color: ${darkMode ? '#c9d1d9' : '#24292f'};
      margin-bottom: 4px;
    }

    .preview-info-desc {
      font-size: 14px;
      color: ${darkMode ? '#8b949e' : '#57606a'};
    }
  </style>
</head>
<body>
  <div class="mode-toggle">
    <button onclick="location.href='?mode=light'" class="${!darkMode ? 'active' : ''}">☀️ Light</button>
    <button onclick="location.href='?mode=dark'" class="${darkMode ? 'active' : ''}">🌙 Dark</button>
  </div>

  <div class="github-container">
    <div class="preview-info">
      <div class="preview-info-icon">🔍</div>
      <div class="preview-info-text">
        <div class="preview-info-title">GitHub Preview Mode</div>
        <div class="preview-info-desc">This preview uses GitHub's actual Primer CSS and marked.js GFM renderer. What you see here is exactly what will appear on GitHub.</div>
      </div>
    </div>

    <div class="pr-comment">
      <div class="pr-comment-header">
        <img src="https://avatars.githubusercontent.com/in/15368?s=64&v=4" alt="github-actions[bot]">
        <span><strong>github-actions</strong> bot commented just now</span>
      </div>
      <div class="pr-comment-body">
        <article class="markdown-body" id="content">
          <!-- Markdown will be rendered here -->
        </article>
      </div>
    </div>
  </div>

  <script>
    // Configure marked for GitHub Flavored Markdown
    marked.setOptions({
      gfm: true,           // GitHub Flavored Markdown
      breaks: false,       // GitHub doesn't convert \\n to <br>
      headerIds: true,     // Add IDs to headers
      mangle: false,       // Don't mangle email addresses
      pedantic: false,
      sanitize: false,     // Allow HTML (GitHub allows it in comments)
      smartLists: true,
      smartypants: false,
      xhtml: false
    });

    // The markdown content
    const markdown = \`${escapedMarkdown}\`;

    // Render markdown
    document.getElementById('content').innerHTML = marked.parse(markdown);

    // Handle dark/light mode from URL
    const urlParams = new URLSearchParams(window.location.search);
    const mode = urlParams.get('mode');
    if (mode === 'dark' && !${darkMode}) {
      location.href = '?mode=dark';
    } else if (mode === 'light' && ${darkMode}) {
      location.href = '?mode=light';
    }
  </script>
</body>
</html>`;
}

/**
 * Generate a complete GitHub preview from plan data
 * @param {Object} options - Same options as generatePrComment
 * @returns {string} Complete HTML page that renders like GitHub
 */
function generateGitHubPreviewFromPlan(options) {
  // Generate the markdown using our existing generator
  const markdown = generatePrComment(options);

  // Wrap it in GitHub-accurate HTML
  return generateGitHubPreview(markdown, {
    title: `Terraform Plan - Run #${options.runNumber || 1}`,
    darkMode: false
  });
}

// Export for Node.js
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    generateGitHubPreview,
    generateGitHubPreviewFromPlan
  };
}
