# Preview Overlays Directory
This directory contains ephemeral preview environments generated per PR.

## Structure
- `_template/` - Template files copied by preview.yml workflow
- `pr-<number>/` - Generated overlay for each PR (created/deleted by GitHub Actions)

## How it works
1. When a PR is opened/updated, `.github/workflows/preview.yml` copies `_template/` to `pr-<number>/`
2. Placeholders ({{PR_NUMBER}}, {{IMAGE_TAG}}, etc.) are replaced with actual values
3. The commit triggers Argo CD ApplicationSet to create a preview Application
4. When the PR is closed, `.github/workflows/preview-cleanup.yml` deletes the `pr-<number>/` directory
5. Argo CD prunes the preview namespace automatically

## Concurrency Limit
Maximum 3 concurrent previews to protect production on single-node AKS.
