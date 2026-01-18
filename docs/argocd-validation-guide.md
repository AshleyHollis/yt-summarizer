# Argo CD Deployment Validation & Diagnostics Guide

## Overview

This guide documents the comprehensive deployment validation and diagnostics system for Argo CD deployments. These tools enable early detection of configuration errors, prevent timeout failures, and provide detailed troubleshooting information.

## Problem Statement

Previously, production deployments would:
- Wait up to 180 seconds before timing out
- Provide vague error messages without actionable diagnostics
- Miss configuration errors until late in the deployment process
- Require manual cluster inspection to troubleshoot failures

## Solution Architecture

The solution implements three layers:
1. **Pre-Deployment Validation**: Validate configuration before syncing
2. **Fail-Fast Error Detection**: Detect errors early during sync
3. **Comprehensive Diagnostics**: Collect detailed information for troubleshooting

## Quick Start

### 1. Validate Argo CD Deployment Before Sync

```bash
./scripts/validate-argocd-deployment.sh yt-summarizer-prod -v
```

**What it checks:**
- kubectl connectivity and Argo CD CRDs
- Application exists in correct namespace
- Configuration is valid (repo URL, target revision, path)
- No manifest generation errors (ComparisonError)
- No long-running stuck operations
- Target namespace is accessible
- Git repository connectivity

**Exit codes:**
- `0`: All validations passed - ready for sync
- `1`: Validation failed - check error message
- `2`: Application not found

### 2. Collect Detailed Diagnostics

```bash
./scripts/diagnose-argocd-deployment.sh yt-summarizer-prod ./diagnostics
```

**Generates:**
- Application status and configuration
- All Kubernetes resources in target namespace
- Pod details and logs
- Argo CD controller logs
- Git repository information
- Summary report with actionable recommendations

**Output:**
```
Diagnostics saved to: ./.argocd-diagnostics/yt-summarizer-prod-20260118-095430/
```

### 3. Sync Argo CD Manifests

```bash
# Validate and apply all manifests
./scripts/sync-argocd-manifests.sh

# Dry-run to see what would be applied
./scripts/sync-argocd-manifests.sh --dry-run

# Apply only infrastructure applications
./scripts/sync-argocd-manifests.sh --infra-only

# Apply with verbose output
./scripts/sync-argocd-manifests.sh -v
```

## Usage in CI/CD

### Pre-Deployment Validation in Workflow

```yaml
- name: Validate Argo CD Deployment
  run: ./scripts/validate-argocd-deployment.sh ${{ env.APP_NAME }} -v

- name: Wait for Argo CD Sync
  uses: ./.github/actions/wait-for-argocd
  with:
    app-name: ${{ env.APP_NAME }}
    namespace: ${{ env.APP_NAMESPACE }}
```

### Diagnostics on Failure

```yaml
- name: Collect Diagnostics
  if: failure()
  run: ./scripts/diagnose-argocd-deployment.sh ${{ env.APP_NAME }}

- name: Upload Diagnostics
  if: failure()
  uses: actions/upload-artifact@v4
  with:
    name: argocd-diagnostics
    path: ./.argocd-diagnostics/
```

## Validation Checks Explained

### 1. kubectl & Argo CD Availability

**Check:** Verifies kubectl is available and can access Argo CD APIs

**Failure Indicators:**
```
✗ kubectl not found
✗ Cannot access Kubernetes API
✗ Argo CD CRDs not found
```

**Remediation:**
- Install kubectl: `curl https://dl.k8s.io/release/stable.txt | xargs -I {} curl -LO https://dl.k8s.io/release/{}/bin/linux/amd64/kubectl`
- Ensure cluster credentials are configured: `kubectl config view`
- Verify Argo CD is installed: `kubectl get namespace argocd`

### 2. Application Configuration Validation

**Check:** Verifies repository URL, target revision, and path are valid

**Failure Indicators:**
```
✗ Application has incomplete configuration
✗ Invalid repository URL format
```

**Example of valid configuration:**
```
Repository URL: https://github.com/AshleyHollis/yt-summarizer.git
Target Revision: main
Path: k8s/overlays/prod
Destination Namespace: yt-summarizer
```

**Remediation:**
- Check Application manifest: `kubectl describe application <app-name> -n argocd`
- Verify repository is accessible
- Confirm target revision (branch/tag) exists in repository

### 3. Manifest Generation Error Detection

**Check:** Detects ComparisonError which indicates Kustomize/Helm build failures

**Failure Indicators:**
```
✗ ComparisonError detected: Manifest generation failed
```

**Common causes:**
- Invalid `kustomization.yaml` syntax
- Invalid patch target references
- Missing resource files referenced in overlays
- Invalid JSON/YAML in variable patches

**Remediation:**
```bash
# Test kustomize build locally
cd k8s/overlays/prod
kustomize build .

# Check for specific errors
kubectl get application <app-name> -n argocd -o jsonpath='{.status.conditions[?(@.type=="ComparisonError")].message}'
```

### 4. Long-Running Operation Detection

**Check:** Identifies operations stuck for more than 5 minutes

**Failure Indicators:**
```
✗ Operation has been running for 729s (>5 minutes)
✗ This may indicate a stuck sync operation
```

**Causes:**
- Slow pod startup times (slow image pull, health check failures)
- Circular dependency between resources
- Resource hook scripts hanging
- Webhook timeouts

**Remediation:**
- Check pod events: `kubectl get events -n <namespace>`
- View Argo CD controller logs: `kubectl logs -n argocd -l app.kubernetes.io/name=argocd-application-controller -f`
- Check sync operation details: `kubectl get application <app-name> -n argocd -o jsonpath='{.status.operationState}'`

### 5. Sync Policy Verification

**Check:** Ensures auto-sync is configured appropriately

**Warnings:**
```
⚠ Application does not have automated sync enabled
```

**Best practices:**
- Production apps should have automated sync enabled for critical infrastructure
- Use `selfHeal: true` to recover from manual changes
- Configure `prune: true` to clean up removed resources

### 6. Target Revision Format Check

**Check:** Warns if application targets commit SHA instead of branch

**Warning:**
```
⚠ Application targets a commit SHA instead of branch
  This may prevent Argo CD from detecting future changes
```

**Good formats:**
- `main` (branch name)
- `v1.2.3` (tag)
- `{{branch}}` (ApplicationSet template variable)

**Bad format:**
- `a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6` (commit SHA)

## Common Failure Scenarios

### Scenario 1: ComparisonError - Invalid Kustomization

**Symptom:**
```
✗ ComparisonError detected: Manifest generation failed
error: unable to find patch target
```

**Diagnosis:**
```bash
# Reproduce the error locally
cd k8s/overlays/prod
kustomize build . 2>&1 | tail -20
```

**Solution:**
- Review `kustomization.yaml` patch targets
- Verify referenced resource files exist
- Check for typos in patch paths

### Scenario 2: ImagePullBackOff

**Symptom:**
```
kubectl get pods -n <namespace>
pod/api-xyz Failed ImagePullBackOff
```

**Diagnosis:**
```bash
# View pod events
kubectl describe pod <pod-name> -n <namespace>

# Check image pull secrets
kubectl get secrets -n <namespace>
```

**Solution:**
- Verify container image exists in ACR
- Check ExternalSecret for image pull credentials
- Confirm Azure Key Vault has correct image registry credentials

### Scenario 3: CreateContainerConfigError

**Symptom:**
```
pod/api-xyz Failed CreateContainerConfigError
```

**Diagnosis:**
```bash
# Check pod events for missing secrets/configmaps
kubectl describe pod <pod-name> -n <namespace>

# Verify ExternalSecrets created actual Kubernetes secrets
kubectl get secrets -n <namespace>
```

**Solution:**
- Ensure all required ExternalSecrets are synced
- Verify Azure Key Vault has required secrets
- Check ExternalSecret status: `kubectl describe externalsecret -n <namespace>`

### Scenario 4: CrashLoopBackOff

**Symptom:**
```
pod/api-xyz Failed CrashLoopBackOff
```

**Diagnosis:**
```bash
# View container logs
kubectl logs <pod-name> -n <namespace>

# View previous container logs (if crashed before)
kubectl logs <pod-name> -n <namespace> --previous
```

**Solution:**
- Review application logs for error messages
- Check configuration values in ConfigMap
- Verify database connectivity (DATABASE_URL setting)

## Troubleshooting Workflows

### Workflow: Deployment hangs at sync

1. **Run validation first:**
   ```bash
   ./scripts/validate-argocd-deployment.sh yt-summarizer-prod -v
   ```

2. **If validation passes, collect diagnostics:**
   ```bash
   ./scripts/diagnose-argocd-deployment.sh yt-summarizer-prod ./diagnostics
   cat ./diagnostics/yt-summarizer-prod-*/99-summary-report.txt
   ```

3. **Check Argo CD controller logs:**
   ```bash
   kubectl logs -n argocd -l app.kubernetes.io/name=argocd-application-controller --tail=100 -f
   ```

4. **Monitor application status:**
   ```bash
   kubectl get application yt-summarizer-prod -n argocd -w
   ```

5. **Force refresh if needed:**
   ```bash
   kubectl patch application yt-summarizer-prod -n argocd --type merge \
     -p '{"metadata":{"annotations":{"argocd.argoproj.io/refresh":"hard"}}}'
   ```

### Workflow: Configuration error detected

1. **Identify the error:**
   ```bash
   kubectl describe application <app-name> -n argocd | grep -A 20 "Conditions:"
   ```

2. **Fix the source (git repository)**

3. **Sync changes:**
   ```bash
   ./scripts/sync-argocd-manifests.sh
   ```

4. **Verify sync:**
   ```bash
   ./scripts/validate-argocd-deployment.sh <app-name> -v
   ```

## Environment Variables

### Validation Script

```bash
export ARGOCD_NAMESPACE=argocd          # Argo CD namespace
export APP_NAMESPACE=yt-summarizer      # Application namespace
export TIMEOUT=60                       # Validation timeout (seconds)
export VERBOSE=true                     # Enable verbose output

./scripts/validate-argocd-deployment.sh yt-summarizer-prod
```

### Diagnostics Script

```bash
export ARGOCD_NAMESPACE=argocd
export APP_NAMESPACE=yt-summarizer

./scripts/diagnose-argocd-deployment.sh yt-summarizer-prod ./output
```

### Sync Manifests Script

```bash
export ARGOCD_NAMESPACE=argocd

./scripts/sync-argocd-manifests.sh --infra-only -v
```

## Integration with GitHub Actions

See `.github/workflows/deploy-prod.yml` and `.github/workflows/preview.yml` for integration examples.

## Advanced Troubleshooting

### Enable Argo CD Debug Logging

```bash
kubectl patch configmap argocd-cmd-params-cm -n argocd -p '{"data":{"application.instanceLabelKey":"app.kubernetes.io/instance"}}'

kubectl set env deployment/argocd-application-controller -n argocd ARGOCD_APPLICATION_CONTROLLER_LOG_LEVEL=debug
```

### Export Application State

```bash
# Full YAML
kubectl get application <app-name> -n argocd -o yaml > app-state.yaml

# Sync result details
kubectl get application <app-name> -n argocd -o jsonpath='{.status.operationState.syncResult}' | jq .

# Resource status
kubectl get application <app-name> -n argocd -o jsonpath='{.status.resources[*]}' | jq .
```

### Manual Argo CD Sync

```bash
# Full sync (force refresh)
kubectl patch application <app-name> -n argocd --type merge \
  -p '{"metadata":{"annotations":{"argocd.argoproj.io/refresh":"hard"}}}'

# Selective sync (sync specific resource)
argocd app sync <app-name> --resource group:kind:name
```

## Best Practices

1. **Always validate before deploying:**
   ```bash
   ./scripts/validate-argocd-deployment.sh <app-name> -v
   ```

2. **Use dry-run for changes:**
   ```bash
   ./scripts/sync-argocd-manifests.sh --dry-run
   ```

3. **Monitor deployments in real-time:**
   ```bash
   kubectl get applications -n argocd -w
   ```

4. **Keep diagnostics for failed deployments:**
   - Saves logs for future reference
   - Helps identify patterns in failures
   - Useful for team knowledge sharing

5. **Configure alerting on Argo CD:**
   - Monitor for OutOfSync applications
   - Alert on ComparisonError conditions
   - Track sync operation duration

## Related Documentation

- [Argo CD Official Docs](https://argo-cd.readthedocs.io/)
- [Kustomize Documentation](https://kustomize.io/)
- [Kubernetes Troubleshooting](https://kubernetes.io/docs/tasks/debug-application-cluster/)
