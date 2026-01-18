# Unified Validation Action

Consolidated validation for K8s, Kustomize, Argo CD, and Terraform manifests.

## Purpose

This action replaces 5 separate validation actions with a single unified interface:
- `validate-k8s-yaml` → `yaml-syntax` validator
- `kustomize-validate` → `kustomize-build` validator
- `validate-argocd-paths` → `argocd-paths` validator
- `validate-argocd-manifest` → `argocd-manifest` validator
- `validate-terraform-config` → `terraform-config` validator

## Usage

### Example 1: CI - Full K8s Validation

```yaml
- name: Validate Kubernetes manifests
  uses: ./.github/actions/validate
  with:
    validators: yaml-syntax,kustomize-build,argocd-paths
    k8s-directory: k8s
    overlay-paths: k8s/overlays/preview,k8s/overlays/prod,k8s/overlays/prod-secretstore
    base-paths: k8s/base
```

### Example 2: Production - Pre-Deployment

```yaml
- name: Pre-deployment validation
  uses: ./.github/actions/validate
  with:
    validators: kustomize-build,argocd-manifest
    overlay-paths: k8s/overlays/prod
    argocd-app-name: yt-summarizer-prod
    argocd-namespace: argocd
    target-namespace: yt-summarizer
    timeout-seconds: '60'
```

### Example 3: Preview - Pre-Deployment

```yaml
- name: Pre-deployment validation
  uses: ./.github/actions/validate
  with:
    validators: kustomize-build,argocd-manifest
    overlay-paths: k8s/overlays/preview
    argocd-app-name: preview-pr-${{ needs.detect-changes.outputs.pr_number }}
    target-namespace: preview-pr-${{ needs.detect-changes.outputs.pr_number }}
```

### Example 4: Terraform Validation

```yaml
- name: Validate Terraform
  uses: ./.github/actions/validate
  with:
    validators: terraform-config
    terraform-directory: infra/terraform/environments/prod
    terraform-backend-config: 'true'
```

### Example 5: Everything

```yaml
- name: Validate all manifests
  uses: ./.github/actions/validate
  with:
    validators: all
    k8s-directory: k8s
    overlay-paths: k8s/overlays/preview,k8s/overlays/prod
    argocd-app-name: yt-summarizer-prod
    terraform-directory: infra/terraform/environments/prod
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `validators` | Comma-separated list: `yaml-syntax`, `kustomize-build`, `argocd-paths`, `argocd-manifest`, `terraform-config`, `all` | Yes | - |
| `k8s-directory` | K8s manifests directory (for `yaml-syntax`) | No | `k8s` |
| `overlay-paths` | Comma-separated overlay paths (for `kustomize-build`) | No | - |
| `base-paths` | Comma-separated base paths (for `kustomize-build`) | No | - |
| `argocd-app-name` | Argo CD Application name (for `argocd-manifest`) | No | - |
| `argocd-namespace` | Argo CD namespace (for `argocd-manifest`) | No | `argocd` |
| `target-namespace` | Target deployment namespace (for `argocd-manifest`) | No | - |
| `terraform-directory` | Terraform directory (for `terraform-config`) | No | - |
| `terraform-backend-config` | Validate backend config (for `terraform-config`) | No | `false` |
| `fail-fast` | Stop on first failure | No | `true` |
| `timeout-seconds` | Timeout per validator | No | `60` |
| `verbose` | Enable verbose output | No | `false` |

## Outputs

| Output | Description |
|--------|-------------|
| `results` | JSON: `{"passed": [...], "failed": [...], "skipped": [...]}` |
| `all-passed` | Boolean: `true` if all validators passed |
| `passed` | Comma-separated list of validators that passed |
| `failed` | Comma-separated list of validators that failed |

## Validators

### `yaml-syntax`

Validates YAML syntax for all K8s manifests using `kubectl apply --dry-run`.

**Requirements:**
- `kubectl` installed
- `k8s-directory` input set

**What it checks:**
- YAML syntax is valid
- Files can be parsed by kubectl
- No duplicate keys or invalid structures

### `kustomize-build`

Validates that kustomize overlays and bases build successfully.

**Requirements:**
- `kubectl` installed (for `kubectl kustomize`)
- `overlay-paths` or `base-paths` input set

**What it checks:**
- kustomization.yaml exists in each path
- Kustomize build succeeds
- Generated manifests are valid K8s resources
- Resources pass kubectl dry-run validation

### `argocd-paths`

Validates that Argo CD Application CRDs reference valid paths.

**Requirements:**
- Argo CD Application manifests in `k8s/argocd/`

**What it checks:**
- Paths specified in Applications exist
- Paths contain kustomization.yaml files
- No broken references

### `argocd-manifest`

Pre-deployment validation of Argo CD manifest generation.

**Requirements:**
- `kubectl` access to cluster
- `argocd-app-name` input set
- Application must exist in cluster

**What it checks:**
- Application CRD exists
- Application is tracking a branch (not commit SHA)
- No pre-existing sync errors
- No stuck operations (>5 minutes)
- Manifest can be generated
- Resources can be parsed

### `terraform-config`

Validates Terraform configuration syntax and formatting.

**Requirements:**
- `terraform` installed
- `terraform-directory` input set

**What it checks:**
- Terraform files are properly formatted
- Terraform validation passes
- Backend configuration is valid (if enabled)

## Architecture

```
.github/actions/validate/
├── action.yml                  # Main composite action
├── README.md                   # This file
└── validators/
    ├── common.sh              # Shared utilities
    ├── yaml-syntax.sh         # YAML validator
    ├── kustomize-build.sh     # Kustomize validator
    ├── argocd-paths.sh        # Argo CD paths validator
    ├── argocd-manifest.sh     # Argo CD manifest validator
    └── terraform-config.sh    # Terraform validator
```

## Error Handling

- Each validator runs independently
- Validators report detailed errors with context
- Fail-fast mode stops on first error (default)
- Continue mode runs all validators and reports all failures
- Timeout protection prevents hung validators

## Benefits

- **Single Action**: One action to maintain instead of 5
- **Consistent Interface**: Same inputs/outputs across all validators
- **Better Debugging**: Detailed error messages and grouped logs
- **Flexible**: Run any combination of validators
- **Fast**: Fail-fast mode stops early on errors
- **Comprehensive**: Continue mode shows all errors at once

## Migration Guide

### Old Code (using separate actions)

```yaml
- uses: ./.github/actions/validate-k8s-yaml
  with:
    directory: k8s

- uses: ./.github/actions/kustomize-validate
  with:
    overlay-path: k8s/overlays/prod

- uses: ./.github/actions/validate-argocd-paths
```

### New Code (using unified action)

```yaml
- uses: ./.github/actions/validate
  with:
    validators: yaml-syntax,kustomize-build,argocd-paths
    k8s-directory: k8s
    overlay-paths: k8s/overlays/prod
```

## See Also

- [Deployment Validation Guide](../../../docs/deployment-validation-guide.md)
- [AGENTS.md](../../../AGENTS.md) - Repository workflows
