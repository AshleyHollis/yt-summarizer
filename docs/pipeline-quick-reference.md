# Pipeline Optimization Quick Reference

## 🎯 Overview

Your GitHub Actions workflows have been optimized with **smart change detection** and **reusable components**. This guide helps you understand what changed and how to work with the new system.

---

## 🚀 What's New?

### 1. **Intelligent Job Execution**
- Pipelines now detect what code changed
- Only run jobs needed for those changes
- **Docs-only PRs**: Complete in < 1 minute
- **Frontend-only PRs**: Skip Python tests and backend builds
- **API-only PRs**: Skip frontend tests

### 2. **Reusable Components**
- Common patterns extracted into composite actions
- Scripts for complex operations
- Less code duplication = easier maintenance

---

## 📦 New Composite Actions

| Action | When to Use | Example |
|--------|-------------|---------|
| `setup-python-uv` | Python projects with uv | Test jobs |
| `azure-acr-login` | Azure + ACR auth | Build jobs |
| `docker-build-push` | Building Docker images | Image builds |
| `setup-kustomize` | K8s validation | Manifest checks |
| `kustomize-validate` | Validate overlays | K8s deployments |
| `health-check` | Wait for service | Deployments |
| `generate-image-tag` | Create image tags | All builds |

### Usage Example:
```yaml
- name: Build API image
  uses: ./.github/actions/docker-build-push
  with:
    dockerfile: services/api/Dockerfile
    image-name: yt-summarizer-api
    image-tag: ${{ needs.meta.outputs.image_tag }}
    registry: ${{ env.ACR_LOGIN_SERVER }}
    cache-name: api
```

---

## 🔍 Change Detection

### How It Works:
1. First job in CI analyzes git diff
2. Determines which components changed
3. Sets outputs for downstream jobs
4. Jobs run conditionally based on changes

### Change Categories:
- **api**: `services/api/**`
- **workers**: `services/workers/**`
- **shared**: `services/shared/**`
- **frontend**: `apps/web/**`
- **kubernetes**: `k8s/**`
- **terraform**: `infra/terraform/**`
- **docs**: `docs/**`, `*.md`, `specs/**`

### Test Locally:
```powershell
# See what would run for your changes
./scripts/ci/detect-changes.ps1 -OutputFormat text
```

---

## 💡 Common Scenarios

### Scenario 1: Documentation Update
```
Files changed: docs/architecture.md

Pipeline runs:
✅ detect-changes (30s)
⏭️  All other jobs skipped
✅ ci-status (10s)

Total: 40 seconds
```

### Scenario 2: Frontend Component
```
Files changed: apps/web/src/components/VideoCard.tsx

Pipeline runs:
✅ detect-changes
✅ lint-frontend
✅ test-frontend
⏭️  Python tests skipped
⏭️  Backend builds skipped
✅ ci-status

Total: ~3-4 minutes
```

### Scenario 3: API Endpoint
```
Files changed: services/api/app/routes/videos.py

Pipeline runs:
✅ detect-changes
✅ lint-python
✅ test-api
✅ test-shared
✅ build-images (API)
⏭️  Frontend tests skipped
⏭️  Workers build skipped
✅ ci-status

Total: ~10-12 minutes
```

### Scenario 4: Full Stack Feature
```
Files changed: services/api/, apps/web/, services/workers/

Pipeline runs:
✅ All jobs run (nothing skipped)

Total: ~25-30 minutes
```

---

## 🎨 Pipeline Status Icons

| Icon | Meaning |
|------|---------|
| ✅ | Job passed |
| ❌ | Job failed |
| ⏭️ | Job skipped (not needed) |
| 🎉 | All checks passed |
| 💥 | One or more checks failed |

---

## 🛠️ Adding New Jobs

### Template for Conditional Jobs:
```yaml
my-new-job:
  name: My New Job
  runs-on: ubuntu-latest
  needs: [detect-changes]
  # Only run if specific changes detected
  if: needs.detect-changes.outputs.stage_my_check == 'true'
  steps:
    - uses: actions/checkout@v4
    # ... your steps
```

### Update Change Detection:
Edit `scripts/ci/detect-changes.ps1` to add new patterns:
```powershell
$patterns = @{
    # ... existing patterns
    my_component = @("path/to/my/component/**")
}

# Add to stages
$stages = @{
    # ... existing stages
    my_check = $changes.my_component
}
```

---

## 🐛 Troubleshooting

### Job Not Running When Expected?
1. Check change detection output in `detect-changes` job
2. Verify file paths match patterns in script
3. Test locally: `./scripts/ci/detect-changes.ps1 -OutputFormat text`

### Job Running When It Shouldn't?
1. Check if file matches multiple patterns
2. Verify exclusion patterns (prefixed with `!`)
3. Review change detection logic

### Composite Action Failing?
1. Check action inputs are correct
2. Review action logs for specific error
3. Test equivalent commands locally
4. Check if dependencies are installed

---

## 📊 Performance Tips

### Making PRs Faster:
1. ✅ **Separate docs PRs** - Will complete in < 1 min
2. ✅ **Keep changes focused** - Fewer components = fewer jobs
3. ✅ **Run tests locally first** - Catch issues before push
4. ❌ **Don't mix unrelated changes** - Triggers unnecessary jobs

### Recommended PR Structure:
```
Good:
- PR #1: Update API endpoint (runs API tests only)
- PR #2: Update frontend UI (runs frontend tests only)
- PR #3: Update docs (runs no tests)

Avoid:
- PR #1: Update API + frontend + docs (runs everything)
```

---

## 🔐 Safety Features

### What Always Runs:
- ✅ Change detection
- ✅ Final status check
- ✅ Security scanning (if code changed)

### What's Conditional:
- Tests (only for changed components)
- Builds (only if code/Docker changed)
- Validations (only if infrastructure changed)

### Safety Guarantees:
- Required tests can't be skipped
- Final status validates all necessary jobs ran
- Failed jobs still fail the pipeline
- Skipped jobs are clearly marked

---

## 📖 Additional Resources

- **Full Optimization Guide**: [docs/workflows-advanced-optimization.md](workflows-advanced-optimization.md)
- **Initial Refactoring**: [docs/workflows-refactoring.md](workflows-refactoring.md)
- **Change Detection Script**: `scripts/ci/detect-changes.ps1`
- **Composite Actions**: `.github/actions/*/action.yml`

---

## ❓ FAQ

**Q: Will my PR take longer now?**  
A: No! Most PRs will be significantly faster. Only full-stack changes take the same time.

**Q: Can I force all jobs to run?**  
A: Yes, add the `force-preview` label to your PR.

**Q: What if I break something in a skipped component?**  
A: When you merge to main, the full pipeline runs. Also, the next PR touching that component will catch it.

**Q: How do I test change detection locally?**  
A: Run `./scripts/ci/detect-changes.ps1 -OutputFormat text`

**Q: Can I see which jobs will run before opening a PR?**  
A: Yes, use the change detection script locally with your branch.

---

## 🎓 Examples in the Wild

### Check Change Detection Output:
```yaml
# In any workflow job
- name: Show detected changes
  run: |
    echo "API changed: ${{ needs.detect-changes.outputs.api }}"
    echo "Frontend changed: ${{ needs.detect-changes.outputs.frontend }}"
    echo "Requires build: ${{ needs.detect-changes.outputs.requires_build }}"
```

### Use Health Check:
```yaml
- name: Wait for API to be healthy
  uses: ./.github/actions/health-check
  with:
    url: https://api-pr-${{ github.event.pull_request.number }}.example.com/health/live
    max-attempts: '30'
    interval-seconds: '10'
    service-name: 'Preview API'
```

### Generate Image Tag:
```yaml
- name: Create image tag
  id: tag
  uses: ./.github/actions/generate-image-tag
  with:
    pr-number: ${{ github.event.pull_request.number }}
    commit-sha: ${{ github.sha }}

- name: Use the tag
  run: echo "Tag: ${{ steps.tag.outputs.image-tag }}"
```

---

**Last Updated**: January 11, 2026  
**Optimization Version**: 2.0
