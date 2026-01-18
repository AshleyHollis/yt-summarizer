# Check Argo CD Readiness Action

Pre-deployment checks to ensure an Argo CD Application is ready for sync. This action performs fail-fast validation to catch configuration errors early.

## Features

- ✅ Validates application exists
- ✅ Checks configuration completeness  
- ✅ Detects manifest generation errors
- ✅ Verifies no stale operations
- ✅ Validates target revision format
- ✅ Checks sync policy configuration
- ✅ Includes kubectl availability check

## Inputs

| Name | Description | Required | Default |
|------|-------------|----------|---------|
| `app-name` | Application name to check | Yes | - |
| `namespace` | Argo CD namespace | No | `argocd` |
| `timeout` | Overall check timeout in seconds | No | `60` |
| `verbose` | Enable verbose output | No | `false` |

## Prerequisites

- `kubectl` must be available (use `azure/aks-set-context@v4` or equivalent)
- Kubernetes context must be configured
- Argo CD must be installed in the cluster

## Usage

```yaml
- name: Check Argo CD Application Readiness
  uses: ./.github/actions/check-argocd-readiness
  with:
    app-name: yt-summarizer-prod
    namespace: argocd
    timeout: '60'
    verbose: 'true'
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Application is ready |
| 1 | Application has errors |
| 2 | Application not found |
| 3 | Timeout/configuration error |

## Example Workflow

```yaml
steps:
  - name: Azure Login
    uses: azure/login@v2
    with:
      client-id: ${{ secrets.AZURE_CLIENT_ID }}
      tenant-id: ${{ secrets.AZURE_TENANT_ID }}
      subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

  - name: Set AKS Context
    uses: azure/aks-set-context@v4
    with:
      resource-group: rg-example
      cluster-name: aks-example

  - name: Check Argo CD Readiness
    uses: ./.github/actions/check-argocd-readiness
    with:
      app-name: my-application
      namespace: argocd
```

## Checks Performed

### 1. Application Exists
Verifies the Argo CD Application resource exists in the specified namespace.

### 2. Configuration Valid
Checks that repoURL, targetRevision, and path are configured.

### 3. No Manifest Errors
Detects ComparisonError which indicates manifest generation failures.

### 4. No Stale Operations
Warns if an operation is still running.

### 5. Target Revision Format
Warns if targeting a commit SHA instead of a branch.

### 6. Sync Policy Configured
Checks if automated sync is enabled (warns if not).

## Troubleshooting

### kubectl not found

Ensure you run `azure/aks-set-context` or equivalent before this action:

```yaml
- name: Set AKS Context
  uses: azure/aks-set-context@v4
  with:
    resource-group: ${{ vars.AZURE_RESOURCE_GROUP }}
    cluster-name: ${{ vars.AKS_CLUSTER_NAME }}
```

### Application not found

The application manifest may not have been applied yet. Ensure the `sync-argocd-manifests` job runs before this check.

### ComparisonError

Check your kustomization.yaml for:
- Syntax errors
- Invalid patch references  
- Missing resource files

## Related Actions

- `cleanup-argocd-operation` - Aborts stuck operations
- `wait-for-argocd` - Waits for sync completion
- `verify-deployment` - Verifies deployment images

## Migration Note

This action replaces the direct shell script call:

**Before:**
```yaml
- name: Validate readiness
  shell: bash
  env:
    APP_NAME: yt-summarizer-prod
  run: ./.github/actions/verify-deployment/check-argocd-readiness.sh -v
```

**After:**
```yaml
- name: Validate readiness  
  uses: ./.github/actions/check-argocd-readiness
  with:
    app-name: yt-summarizer-prod
```
