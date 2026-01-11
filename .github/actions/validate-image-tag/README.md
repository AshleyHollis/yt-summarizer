Validate Image Tag action

Recomputes the expected image tag for a PR (using `generate-image-tag` with `pr-number` + `commit-sha`) and compares it to the canonical tag provided by CI (`ci-image-tag`). Fails the action (and workflow) if tags are empty or do not match.

Inputs:
- `ci-image-tag` (required): the canonical image tag from CI
- `pr-number`: PR number (used to compute expected tag)
- `commit-sha`: commit sha to compute deterministic short sha

Usage:

```yaml
- uses: ./.github/actions/validate-image-tag
  with:
    ci-image-tag: ${{ needs.check-concurrency.outputs.image_tag }}
    pr-number: ${{ needs.detect-changes.outputs.pr_number }}
    commit-sha: ${{ needs.detect-changes.outputs.pr_head_sha }}
```
