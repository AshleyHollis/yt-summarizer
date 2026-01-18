# Workflow Differences: Preview vs Production

This document explains the intentional differences between the preview and production deployment workflows.

## Overview

The preview (`preview.yml`) and production (`deploy-prod.yml`) workflows share similar structure but have intentional differences based on their deployment contexts.

## Intentional Differences

### 1. Image Tag Strategy

**Preview (PR-scoped):**
- Format: `pr-{PR_NUMBER}-{SHORT_SHA}` (e.g., `pr-123-abc1234`)
- Scope: Isolated per pull request
- Purpose: Multiple PRs can deploy simultaneously without conflicts
- Cleanup: Images cleaned up when PR is closed/merged

**Production (commit-based):**
- Format: `sha-{SHORT_SHA}` (e.g., `sha-abc1234`)
- Scope: Global, shared across all deployments
- Purpose: Deterministic, immutable tags tied to git commits
- Retention: Images retained for rollback capability

**Why Different:**
- Preview needs PR isolation to avoid conflicts between concurrent deployments
- Production needs deterministic tags for reliable rollbacks and audit trails

---

### 2. Concurrency Control

**Preview:**
```yaml
concurrency:
  group: preview-pr-${{ needs.detect-changes.outputs.pr_number }}
  cancel-in-progress: true
```
- Per-PR concurrency groups
- Cancels in-progress deployments when new commits pushed
- Prevents resource waste on outdated preview builds

**Production:**
```yaml
concurrency:
  group: deploy-prod
  cancel-in-progress: false
```
- Single global concurrency group
- Never cancels in-progress deployments
- Queues deployments to ensure every main commit deploys

**Why Different:**
- Preview optimizes for developer speed (cancel old builds)
- Production optimizes for safety (never cancel mid-deployment)

---

### 3. PR Comments and URLs

**Preview Only Features:**
- `post-preview-comment` job: Posts deployment URLs to PR
- Dynamic preview URL generation: `pr-{number}.preview.yt-summarizer.example.com`
- Frontend Static Web App (SWA) preview environments
- Stale SWA environment cleanup

**Production:**
- No PR comments (deploys from main branch)
- Static production URL: `api.yt-summarizer.example.com`
- Production SWA environment (no ephemeral environments)

**Why Different:**
- Preview needs to communicate deployment status back to PR authors
- Production has fixed URLs that don't change per deployment

---

### 4. Terraform Environment Gates

**Preview:**
- No GitHub Environment protection
- Auto-applies terraform after plan succeeds
- Relies on PR review process for safety

**Production:**
- Uses `environment: production` on `terraform-apply` job
- Optional: Can require manual approval before apply
- Additional safety gate for production infrastructure changes

**Why Different:**
- Preview changes are tested in isolated namespaces
- Production changes affect live infrastructure and need extra protection

---

### 5. Change Detection

**Both workflows now use enhanced `detect-pipeline-changes` action:**

Common outputs:
- `changed_areas`: Space-separated list of changed paths
- `has_code_changes`: Boolean (excludes docs-only)
- `needs_image_build`: Whether new Docker images are required
- `needs_deployment`: Whether any deployment is needed

**Preview-specific (future):**
- Can support force-preview labels via `detect-pr-code-changes` action if needed
- Force-deploy capability for manual workflow triggers

**Why Similar Now:**
- Unified change detection reduces duplication
- Both workflows benefit from consistent logic
- Optional force-deploy is workflow-level, not detection-level

---

### 6. Deployment Verification

**Preview:**
- Comprehensive verification in `verify-deployment` job:
  - ArgoCD sync wait
  - Image verification (API + workers)
  - Health checks (internal + external)
  - TLS certificate verification
- Runs after every preview deployment

**Production:**
- Same comprehensive verification in `verify-deployment` job (added in Phase 4):
  - ArgoCD sync wait
  - Image verification (API + workers)
  - Health checks
  - No TLS verification (production cert is static)

**Why Now Aligned:**
- Production deployments need same safety checks as preview
- Catches deployment issues before they affect users
- Verifies actual running image matches expected tag

---

### 7. E2E Tests

**Preview:**
- Runs Playwright E2E tests against preview environment
- Uses dynamic preview URLs
- Optional based on workflow input (`run_e2e`)

**Production:**
- No E2E tests in deployment workflow
- E2E tests run in CI workflow before merge
- Assumes main branch is already tested

**Why Different:**
- Preview needs to verify the specific PR changes
- Production trusts CI tests that already passed

---

### 8. Frontend Deployment

**Preview:**
- Deploys to SWA staging environment (per-PR)
- Cleanup of stale SWA environments before deploy
- Dynamic environment URLs

**Production:**
- Deploys to SWA production environment
- No cleanup (production is permanent)
- Static production URL

**Why Different:**
- Preview needs ephemeral environments
- Production needs stable, permanent deployment

---

## Shared Components

Both workflows share these composite actions:
- `detect-pipeline-changes` - Change detection
- `wait-for-ci` - CI workflow completion gate
- `validate-terraform-config` - Terraform validation
- `terraform-plan` - Terraform planning
- `update-{preview|prod}-kustomization` - K8s manifest updates
- `commit-kustomization` - Git commit and push
- `wait-for-argocd-sync` - ArgoCD deployment wait
- `verify-deployment-image` - Image tag verification
- `verify-worker-deployments` - Worker image verification
- `health-check` - Health endpoint checks

## Future Considerations

### Potential Alignments

1. **Terraform Structure**: Both now split into plan + apply jobs (aligned in Phase 4)
2. **Deployment Verification**: Both now use comprehensive verification (aligned in Phase 4)
3. **Change Detection**: Both now use same detection action with consistent outputs (aligned in Phase 4)

### Keep Different

1. **Image Tags**: PR-scoped vs commit-based (necessary for isolation)
2. **Concurrency**: Per-PR vs global (different safety trade-offs)
3. **PR Comments**: Preview-only (no PRs in production flow)
4. **Environment Gates**: Optional for production, not needed for preview

## Summary

Most differences between preview and production workflows are **intentional and necessary** due to:
- Different deployment contexts (PR vs main branch)
- Different safety requirements (testing vs production)
- Different isolation needs (concurrent PRs vs sequential deploys)

Phase 4 refactoring aligned the workflows where it makes sense (terraform structure, deployment verification, change detection) while preserving intentional differences where needed.
