// =============================================================================
// Post preview queue status to PR comment
// =============================================================================
// Used by: .github/workflows/preview.yml (check-concurrency job, lines 523-540)
// Purpose: When max previews reached, post a comment informing user of queue
//
// Inputs (via GitHub Actions context):
//   - github.context.issue.number: PR number
//   - MAX_PREVIEWS: Maximum concurrent preview limit
//
// Outputs:
//   - Posts comment to PR via GitHub API
//
// Message indicates:
//   - Maximum preview limit reached
//   - Preview will deploy when slot becomes available
//   - How to free up slots (close other PRs)
//
// Exit: Always succeeds (GitHub API error is logged but doesn't fail workflow)
// =============================================================================

const reasonLines = [
  `Maximum concurrent previews (${{ env.MAX_PREVIEWS }}) reached.`,
  'Your preview will deploy when a slot becomes available.',
  'Close another PR or wait for an existing preview to be cleaned up.'
];
const reason = reasonLines.join('\n\n');

github.rest.issues.createComment({
  issue_number: context.issue.number,
  owner: context.repo.owner,
  repo: context.repo.repo,
  body: `⏳ **Preview Queued**\n\n${reason}`
});
