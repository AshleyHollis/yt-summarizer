# Production Image Build Strategy

## Overview

The production deployment pipeline uses a **two-path image strategy** to optimize build efficiency while maintaining deterministic, auditable deployments.

## Decision Tree

```
┌────────────────────────────────────────────────────────────┐
│  PR Merged to Main                                         │
└────────────────────────────────────────────────────────────┘
                          │
                          ↓
            ┌─────────────────────────┐
            │  Detect Changes         │
            │  (git diff origin/main) │
            └─────────────────────────┘
                          │
          ┌───────────────┴───────────────┐
          │                               │
          ↓                               ↓
    CODE CHANGES?                   K8S/INFRA ONLY?
    (services/*, apps/web,          (k8s/*, infra/*)
     docker/*)                      
          │                               │
          ↓                               ↓
  ┌─────────────────────┐       ┌─────────────────────┐
  │ BUILD NEW IMAGES    │       │ USE EXISTING IMAGE  │
  │ • Generate sha-abc  │       │ • Read prod kust.   │
  │ • Build API image   │       │ • Validate ACR      │
  │ • Build Workers img │       │ • Use existing tag  │
  │ • Tag as sha-abc    │       │ • Update k8s only   │
  │ • Tag as latest     │       │                     │
  └─────────────────────┘       └─────────────────────┘
          │                               │
          └───────────────┬───────────────┘
                          ↓
            ┌─────────────────────────┐
            │  Update Kustomization   │
            │  • Use determined tag   │
            │  • Commit to main       │
            └─────────────────────────┘
                          │
                          ↓
            ┌─────────────────────────┐
            │  ArgoCD Auto-Sync       │
            │  • Detects kust change  │
            │  • Pulls image from ACR │
            │  • Deploys to AKS       │
            └─────────────────────────┘
```

## Image Tagging

### Format

**Production images use SHA-based tags:**
- Format: `sha-{7-char-commit}`
- Example: `sha-e43f28a`
- Corresponds to git commit: `e43f28a`

**Additional tags:**
- `latest` - Always points to most recent production deployment
- Used for: Local development, debugging
- **NEVER** used in: Production kustomization.yaml

### Why SHA Tags?

| Benefit | Description |
|---------|-------------|
| **Deterministic** | Each tag maps to exactly one git commit |
| **Immutable** | Tags never change once created |
| **Auditable** | Can trace production issues to specific code |
| **Rollback** | Easy to revert to previous SHA |
| **GitOps** | Deployment history = git history |

## Path 1: Code Changes (Build New Images)

### Triggers
Changes to any of:
- `services/api/**` - FastAPI application code
- `services/workers/**` - Background workers
- `services/shared/**` - Shared Python libraries
- `apps/web/**` - Next.js frontend
- `docker/**` or `**/Dockerfile*` - Container definitions

### Workflow
1. **meta** job generates tag: `sha-{current-commit}`
2. **build-api** job builds and pushes API image
3. **build-workers** job builds and pushes workers image
4. Both images tagged as:
   - `acrytsummprd.azurecr.io/yt-summarizer-api:sha-abc1234`
   - `acrytsummprd.azurecr.io/yt-summarizer-api:latest`
5. **update-overlay** job updates `k8s/overlays/prod/kustomization.yaml`
6. Kustomization committed to main → ArgoCD syncs

### Example
```yaml
# Commit e43f28a changes services/api/main.py
# → Builds sha-e43f28a
# → Updates kustomization:

images:
  - name: yt-summarizer-api
    newName: acrytsummprd.azurecr.io/yt-summarizer-api
    newTag: sha-e43f28a  # ← NEW TAG
```

## Path 2: K8s/Infra Only (Use Existing Image)

### Triggers
Changes to:
- `k8s/**` - Kubernetes manifests (resource limits, env vars, ingress)
- `infra/terraform/**` - Infrastructure definitions

**AND** no changes to code paths (services/*, apps/web, docker)

### Workflow
1. **get-last-prod-image** job reads current production kustomization
2. Extracts existing SHA tag (e.g., `sha-e43f28a`)
3. Validates image exists in ACR
4. **update-overlay** job updates kustomization with **same image tag**
5. Kustomization committed to main → ArgoCD syncs **config only**

### Example
```yaml
# Commit f123456 changes k8s/overlays/prod/patches/configmap-patch.yaml
# → No image build
# → Reads current tag: sha-e43f28a
# → Updates kustomization:

images:
  - name: yt-summarizer-api
    newName: acrytsummprd.azurecr.io/yt-summarizer-api
    newTag: sha-e43f28a  # ← SAME TAG, new config applied
```

### Why This Matters
- **Faster**: Skips 5-10 minute image build
- **Efficient**: No duplicate images in ACR
- **Safe**: Config changes deployed with proven images
- **Resource-friendly**: Reduces CI time and storage costs

## Comparison with Preview Workflow

| Aspect | Production | Preview |
|--------|------------|---------|
| **Tag format** | `sha-{commit}` | `pr-{number}-{sha}` |
| **Code changes** | Build new sha-tagged image | Wait for CI, use pr-tagged image |
| **No code changes** | Read current prod kustomization | Search PR history backwards |
| **Fallback** | None needed (prod is source) | Use prod kustomization tag |
| **Update target** | `k8s/overlays/prod/` (main branch) | `k8s/overlays/preview/` (PR branch) |
| **ArgoCD source** | Watches `main` branch | Watches PR branches |

## Image Lifecycle

```
┌─────────────────────────────────────────────────────────────┐
│  1. CODE MERGED TO MAIN                                     │
│     Commit: e43f28a                                         │
│     Changes: services/api/routes.py                         │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  2. CI BUILDS IMAGE (if triggered)                          │
│     Tag: sha-e43f28a                                        │
│     Also tagged: latest                                     │
│     Pushed to: acrytsummprd.azurecr.io                      │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  3. KUSTOMIZATION UPDATED                                   │
│     File: k8s/overlays/prod/kustomization.yaml              │
│     newTag: sha-e43f28a                                     │
│     Committed to main with [skip ci]                        │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  4. ARGOCD AUTO-SYNC                                        │
│     Detects: kustomization.yaml change                      │
│     Pulls: acrytsummprd.azurecr.io/.../sha-e43f28a         │
│     Deploys: To namespace yt-summarizer                     │
└─────────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────────┐
│  5. PRODUCTION RUNNING                                      │
│     API: yt-summarizer-api:sha-e43f28a                     │
│     Workers: yt-summarizer-workers:sha-e43f28a             │
│     Traceable to: git commit e43f28a                        │
└─────────────────────────────────────────────────────────────┘
```

## When Images Are Built

| Change Type | Example Files | Builds Image? | Tag Used |
|-------------|---------------|---------------|----------|
| API code | `services/api/main.py` | ✅ Yes | `sha-{new-commit}` |
| Worker code | `services/workers/transcribe.py` | ✅ Yes | `sha-{new-commit}` |
| Shared lib | `services/shared/db/models.py` | ✅ Yes | `sha-{new-commit}` |
| Frontend | `apps/web/src/App.tsx` | ✅ Yes | `sha-{new-commit}` |
| Dockerfile | `services/api/Dockerfile` | ✅ Yes | `sha-{new-commit}` |
| K8s config | `k8s/base/deployment.yaml` | ❌ No | `sha-{last-prod}` |
| Resource limits | `k8s/overlays/prod/patches/` | ❌ No | `sha-{last-prod}` |
| Terraform | `infra/terraform/main.tf` | ❌ No | N/A (infra only) |
| Docs | `docs/api.md`, `README.md` | ❌ No | N/A (skipped) |
| CI workflows | `.github/workflows/*.yml` | ❌ No | N/A (skipped) |

## Secrets and Configuration

**Important:** Secrets are **NEVER** baked into images.

### Runtime Injection (Correct)
- Azure Key Vault → K8s ExternalSecrets → Pod environment
- Updated via: Key Vault rotation + pod restart
- No image rebuild needed

### Baked into Image (Incorrect)
- ❌ Don't: Build images on secret changes
- ❌ Don't: Include secrets in Dockerfile
- ❌ Don't: Use build args for sensitive data

## Rollback Strategy

### To Previous SHA
```bash
# 1. Find previous production tag
git log --oneline k8s/overlays/prod/kustomization.yaml

# 2. Manually update kustomization.yaml
# Change newTag to previous SHA

# 3. Commit and push
git commit -am "rollback: revert to sha-abc1234"
git push origin main

# 4. ArgoCD auto-syncs the rollback
```

### To Specific Commit
```bash
# 1. Check ACR for available tags
az acr repository show-tags --name acrytsummprd --repository yt-summarizer-api

# 2. Update kustomization with desired SHA
newTag: sha-abc1234

# 3. Commit and push
```

## Troubleshooting

### "Image not found in ACR"
- **Cause**: Kustomization references SHA that was never built
- **Fix**: Check if image exists in ACR, rebuild if needed
- **Prevention**: get-last-prod-image job validates before deployment

### "Production using 'latest' tag"
- **Cause**: Manual edit to kustomization outside workflow
- **Fix**: Update to specific SHA tag from ACR
- **Prevention**: Always use workflow to update kustomization

### "K8s changes not deploying"
- **Cause**: get-last-prod-image job may be failing
- **Fix**: Check workflow logs, ensure prod kustomization has valid SHA
- **Prevention**: Monitor workflow execution for all merges

## Best Practices

1. ✅ **Always use SHA tags in kustomization**
   - `newTag: sha-e43f28a` ← Good
   - `newTag: latest` ← Bad

2. ✅ **Let workflow update kustomization**
   - Don't manually edit tags
   - Workflow ensures consistency

3. ✅ **Trace deployments to commits**
   - `sha-e43f28a` → `git show e43f28a`
   - Full code history available

4. ✅ **Monitor ACR for old images**
   - Retention policy cleans up old tags
   - Keep recent SHAs for rollback

5. ✅ **Use 'latest' only for debugging**
   - Local testing: `docker pull .../:latest`
   - Production: Always use SHA tags

## Related Documentation

- [Preview Workflow Strategy](./.github/workflows/preview.yml) - PR-scoped image builds
- [Change Detection](./scripts/ci/detect-changes.ps1) - What triggers builds
- [Kustomize Templates](./scripts/ci/templates/) - Production overlay generation
- [ArgoCD Setup](./docs/argocd-setup.md) - GitOps deployment configuration

## Questions?

**Q: Why not use digests instead of tags?**
A: Digests are great but harder to read/audit. SHA tags provide both immutability and human readability.

**Q: Can we manually trigger an image rebuild?**
A: Yes, use workflow_dispatch with `run_deploy: true` input.

**Q: What if we need to deploy a hotfix?**
A: Merge to main → workflow detects code change → builds new SHA → deploys automatically.

**Q: How do we handle database migrations?**
A: Alembic migrations run via init containers in K8s, referenced by same SHA tag.
