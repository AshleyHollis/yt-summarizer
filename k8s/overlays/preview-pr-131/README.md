# Preview Overlay - Auto-Generated

⚠️ **DO NOT MANUALLY EDIT `kustomization.yaml`** ⚠️

## How It Works

This overlay is **dynamically generated** by the GitHub Actions preview workflow from the template at:

```
scripts/ci/templates/preview-kustomization-template.yaml
```

### Making Changes

**To update the preview overlay:**

1. Edit the **template file** at `scripts/ci/templates/preview-kustomization-template.yaml`
2. The preview workflow will automatically regenerate `kustomization.yaml` on the next PR build
3. Changes are committed back to the PR branch by `github-actions[bot]`

### Template Variables

The template supports these placeholders (substituted by `scripts/ci/generate_preview_kustomization.py`):

- `__PR_NUMBER__` - Pull request number (e.g., `6`)
- `__IMAGE_TAG__` - Docker image tag (e.g., `pr-6-abc1234` or `latest`)
- `__ACR_SERVER__` - Azure Container Registry URL (e.g., `acrytsummprd.azurecr.io`)
- `__PREVIEW_HOST__` - Preview hostname (e.g., `api-pr-6.yt-summarizer.apps.ashleyhollis.com`)
- `__TLS_SECRET__` - TLS certificate secret name (e.g., `wildcard-yt-summarizer-apps-tls`)

### Workflow Integration

The preview overlay is generated and committed by these workflow steps:

1. **Update Overlay** (`update-preview-overlay` action)
   - Loads template
   - Substitutes variables
   - Writes to `k8s/overlays/preview/kustomization.yaml`

2. **Validate** (`kustomize-validate` action)
   - Runs `kustomize build` to check syntax
   - Performs dry-run against AKS cluster

3. **Commit** (`commit-overlay-changes` action)
   - Commits generated overlay to PR branch
   - Pushes with `[skip ci]` to avoid infinite loops

4. **ArgoCD Sync**
   - ArgoCD watches the PR branch
   - Detects changes to overlay
   - Deploys to `preview-pr-{NUMBER}` namespace

### Why It's Generated

Dynamic generation ensures:

✅ **No manual updates required** - PR number, image tags, and hostnames are set automatically  
✅ **Consistency** - All previews follow the same structure from the template  
✅ **Auditability** - Git history shows exactly what was deployed and when  
✅ **No merge conflicts** - Each PR branch has its own generated overlay

### Troubleshooting

**Q: My changes to `kustomization.yaml` were overwritten!**  
A: Edit the **template** instead: `scripts/ci/templates/preview-kustomization-template.yaml`

**Q: The overlay has the wrong PR number**  
A: The workflow sets this automatically. Check the PR number in the GitHub Actions run.

**Q: ArgoCD isn't syncing my changes**  
A: Ensure the overlay was committed to the PR branch. Check the `commit-overlay-changes` step logs.

**Q: I want to add a new patch**  
A: Add it to the `patches:` section in the **template file**, then trigger a new workflow run.

---

**Last Updated:** 2026-01-12  
**Related Spec:** [003-preview-dns-cloudflare](../../../specs/003-preview-dns-cloudflare/)
