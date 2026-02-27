---
name: github-actions-pipelines
description: GitHub Actions workflows and CI/CD pipelines for the YT Summarizer project including composite actions, workflow patterns, and deployment automation
license: MIT
---

# GitHub Actions Pipelines

## Purpose
Comprehensive guidance for GitHub Actions workflows and CI/CD pipelines in the YT Summarizer project, covering composite actions, workflow patterns, deployment strategies, and troubleshooting.

## When to Use
- Creating or modifying GitHub Actions workflows
- Adding new composite actions
- Understanding deployment pipelines (CI, Preview, Production)
- Debugging workflow failures
- Setting up workflow triggers and concurrency
- Configuring deployment strategies

## Do Not Use When
- Writing application code (use fastapi-patterns or other skills)
- Infrastructure changes (use terraform-style-guide skill)
- Kubernetes operations (use kubernetes-architect skill)

## Workflow Overview

### Main Workflows

| Workflow | File | Purpose | Triggers |
|----------|------|---------|----------|
| **CI** | `ci.yml` | Lint, test, build images | PR, push to main, manual |
| **Preview** | `preview.yml` | Deploy PR previews to AKS + SWA | PR, manual |
| **Preview E2E** | `preview-e2e.yml` | Run E2E tests on preview | After preview deploy |
| **Preview Cleanup** | `preview-cleanup.yml` | Remove stale previews | PR close, schedule |
| **Deploy Prod** | `deploy-prod.yml` | Production deployment | PR merge, manual |
| **Terraform Deploy** | `terraform-deploy.yml` | Infrastructure changes | Path-based, manual |

### Key Composite Actions

| Action | Purpose | Location |
|--------|---------|----------|
| **validate** | Unified K8s/Terraform/ArgoCD validation | `.github/actions/validate/` |
| **build-images** | Build and push Docker images | `.github/actions/build-images/` |
| **argocd-wait** | Wait for ArgoCD sync with auto-recovery | `.github/actions/argocd-wait/` |
| **deployment-validate** | Pre-deployment validation | `.github/actions/deployment-validate/` |
| **run-python-tests** | Python test execution | `.github/actions/run-python-tests/` |
| **run-playwright-tests** | E2E test execution | `.github/actions/run-playwright-tests/` |
| **terraform-plan** | Terraform plan with PR comments | `.github/actions/terraform-plan/` |

## Workflow Patterns

### CI Workflow Structure

```yaml
name: CI

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]
  workflow_dispatch:

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  # Phase 1: Linting
  lint-python:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: ./.github/actions/setup-python-env
      - uses: ./.github/actions/run-ruff-check

  # Phase 2: Testing
  test-api:
    needs: lint-python
    uses: ./.github/actions/run-python-tests
    with:
      service: api

  # Phase 3: Building
  build-images:
    needs: [test-api, test-workers, test-frontend]
    uses: ./.github/actions/build-images
    with:
      tag: pr-${{ github.event.number }}-${{ github.sha }}
```

### Composite Action Structure

```yaml
# .github/actions/my-action/action.yml
name: My Action
description: Description of what this action does

inputs:
  input-name:
    description: 'Description of input'
    required: true
    default: 'default-value'

outputs:
  output-name:
    description: 'Description of output'
    value: ${{ steps.step-id.outputs.value }}

runs:
  using: composite
  steps:
    - name: Step name
      shell: bash
      run: |
        echo "Doing something with ${{ inputs.input-name }}"
        echo "value=result" >> "$GITHUB_OUTPUT"
```

### Deployment Patterns

**Preview Deployment Flow**:
1. Detect changes (code vs K8s-only)
2. Wait for CI images (if code changes)
3. Generate image tags
4. Update Kustomize overlays
5. Deploy to AKS via ArgoCD
6. Deploy frontend to SWA
7. Run E2E tests
8. Post results comment

**Production Deployment Flow**:
1. Build images inline (not waiting for CI)
2. Push to ACR
3. Update production Kustomize
4. ArgoCD sync
5. Verify deployment
6. Update baseline SWA

## Common Operations

### Trigger Workflow Manually

```bash
# Via GitHub CLI
gh workflow run ci.yml
gh workflow run preview.yml -f pr_number=123 -f force_deploy=true

# Via API (for automation)
curl -X POST \
  -H "Authorization: token $GITHUB_TOKEN" \
  -H "Accept: application/vnd.github.v3+json" \
  https://api.github.com/repos/AshleyHollis/yt-summarizer/actions/workflows/ci.yml/dispatches \
  -d '{"ref":"main"}'
```

### Check Workflow Status

```bash
# List recent runs
gh run list --workflow=ci.yml --limit 10

# Watch specific run
gh run watch <run-id>

# View logs
gh run view <run-id> --log
```

### Validate Workflows Locally

```bash
# Install actionlint
brew install actionlint

# Validate all workflows
actionlint

# Validate specific file
actionlint .github/workflows/ci.yml
```

### Debug Failed Jobs

```bash
# Download logs
gh run download <run-id>

# View specific job logs
gh run view <run-id> --job=<job-id>

# Re-run failed jobs
gh run rerun <run-id> --failed
```

## Validation Framework

The project uses a unified validation action (`.github/actions/validate`) that consolidates all validation logic:

### Available Validators

- **yaml-syntax**: Validates YAML syntax for K8s manifests
- **kustomize-build**: Validates kustomize overlays build successfully
- **argocd-paths**: Validates ArgoCD Application paths exist
- **argocd-manifest**: Validates ArgoCD manifests against server state
- **terraform-config**: Validates Terraform configuration
- **k8s-placeholders**: Validates preview patches use placeholders
- **swa-config**: Validates Static Web Apps configuration
- **kustomize-resources**: Validates resource requests against quotas

### Usage Examples

```yaml
# K8s validation
- uses: ./.github/actions/validate
  with:
    validators: yaml-syntax,kustomize-build
    overlay-paths: k8s/overlays/preview,k8s/overlays/prod

# Terraform validation
- uses: ./.github/actions/validate
  with:
    validators: terraform-config
    terraform-directory: infra/terraform

# Resource quota validation
- uses: ./.github/actions/validate
  with:
    validators: kustomize-resources
    overlay-paths: k8s/overlays/prod
    query-aks: 'true'
    aks-resource-group: rg-yt-summarizer-prod
    aks-cluster-name: aks-yt-summarizer-prod
```

## Environment Variables and Secrets

### Required Secrets

- `ACR_USERNAME` / `ACR_PASSWORD`: Azure Container Registry credentials
- `AZURE_CREDENTIALS`: Azure service principal JSON
- `ARGOCD_AUTH_TOKEN`: ArgoCD API token
- `TF_API_TOKEN`: Terraform Cloud token
- `SWA_DEPLOYMENT_TOKEN`: Static Web Apps deployment token

### Required Variables

- `ACR_NAME`: Container registry name (e.g., `acrytsummprd`)
- `ACR_LOGIN_SERVER`: Registry login server
- `AKS_CLUSTER_NAME`: Kubernetes cluster name
- `AKS_RESOURCE_GROUP`: Resource group for AKS

## Best Practices

1. **Use composite actions** for reusable logic across workflows
2. **Fail fast** - validate early, fail on first error
3. **Concurrency control** - use `concurrency` to prevent conflicting runs
4. **Conditional jobs** - use `if:` to skip unnecessary work
5. **Artifact passing** - use `actions/upload-artifact` and `actions/download-artifact`
6. **Matrix builds** - test across multiple versions/configurations
7. **Timeout settings** - always set job/step timeouts
8. **Secret masking** - never log secrets, use `${{ secrets.NAME }}`
9. **Path filtering** - trigger workflows only when relevant files change
10. **Idempotent deployments** - ensure reruns are safe

## Troubleshooting

### Workflow Not Triggering

- Check `on:` triggers match your event
- Verify branch filters (e.g., `branches: [main]`)
- Check if workflow is disabled in GitHub UI
- Look for syntax errors with `actionlint`

### Job Hanging/Timing Out

- Check for infinite loops in scripts
- Verify external service availability
- Add debug logging with `ACTIONS_STEP_DEBUG: true`
- Check runner resource limits

### Permission Denied Errors

- Verify `permissions:` block in workflow
- Check repository/organization settings
- Ensure secrets are properly configured
- Use `GITHUB_TOKEN` with appropriate scopes

### Composite Action Failures

- Check input/output definitions match usage
- Verify `shell:` is specified for each run step
- Use absolute paths: `$GITHUB_ACTION_PATH`
- Test action in isolation before integration

## Common Commands

```bash
# List all workflows
gh workflow list

# View workflow YAML
gh workflow view ci.yml

# Enable/disable workflow
gh workflow enable ci.yml
gh workflow disable ci.yml

# Run workflow with inputs
gh workflow run preview.yml -f pr_number=123

# Cancel running workflow
gh run cancel <run-id>

# Delete old runs
gh run delete <run-id>
```
