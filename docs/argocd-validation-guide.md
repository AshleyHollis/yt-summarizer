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

## Automated Manifest Management

### Overview

Argo CD application manifests (`k8s/argocd/*.yaml`) define which applications and infrastructure components are deployed to the cluster. These manifests are now automatically applied when changed, eliminating the need for manual `kubectl apply` commands.

### Key Manifest Files

| File | Purpose | Managed By |
|------|---------|-----------|
| `k8s/argocd/infra-apps.yaml` | Infrastructure applications (nginx, cert-manager, external-secrets, etc.) | Production workflow |
| `k8s/argocd/prod-app.yaml` | Production application definition | Production workflow |
| `k8s/argocd/preview-appset.yaml` | Preview ApplicationSet for PR environments | Production workflow |

### How It Works

1. **Change Detection**: When a PR modifies files in `k8s/argocd/`, the change is detected by the pipeline
2. **CI Validation**: YAML syntax and manifest structure are validated in CI
3. **Production Sync**: After merge to main, the production workflow automatically applies changed manifests
4. **Verification**: Post-apply verification ensures applications are created/updated successfully

### CI Validation (Automatic)

When you modify Argo CD manifests, CI automatically validates:

```yaml
# .github/workflows/ci.yml
- name: Validate Argo CD manifest syntax
  if: contains(needs.detect-changes.outputs.changed_areas, 'k8s/argocd')
  run: |
    # Validates YAML syntax
    # Checks kind is Application or ApplicationSet
    # Ensures manifests are well-formed
```

**Validation checks:**
- ✓ Valid YAML syntax
- ✓ Kind is Application or ApplicationSet
- ✓ Required fields are present
- ✓ No syntax errors

### Production Deployment (Automatic)

After merging to main, manifests are automatically applied:

```yaml
# .github/workflows/deploy-prod.yml
sync-argocd-manifests:
  name: Sync Argo CD Manifests
  runs-on: ubuntu-latest
  needs: [detect-changes, terraform-apply]
  if: contains(needs.detect-changes.outputs.changed_areas, 'k8s/argocd')
  steps:
    - name: Sync Argo CD manifests
      uses: ./.github/actions/sync-argocd-manifests
      with:
        mode: all
        namespace: argocd
```

**Sync process:**
1. Runs after `terraform-apply` (infrastructure may create resources Argo CD needs)
2. Runs before `update-overlay` (applications need to exist before we try to sync them)
3. Applies all changed manifests to the cluster
4. Verifies applications were created/updated successfully

### Manual Sync (When Needed)

In rare cases, you may need to manually sync manifests:

```bash
# Sync all Argo CD manifests
./scripts/sync-argocd-manifests.sh

# Dry-run to preview changes
./scripts/sync-argocd-manifests.sh --dry-run

# Sync only infrastructure apps
./scripts/sync-argocd-manifests.sh --infra-only

# Sync only main applications
./scripts/sync-argocd-manifests.sh --apps-only

# Skip validation (not recommended)
./scripts/sync-argocd-manifests.sh --skip-validation
```

### Troubleshooting Manifest Sync

#### Application Not Found After Sync

**Symptoms:**
```
✗ Application 'my-app' not found in argocd namespace
```

**Causes:**
- ApplicationSet hasn't generated the application yet (expected delay)
- Manifest references wrong namespace
- Application creation failed due to permissions

**Remediation:**
```bash
# Check if ApplicationSet exists
kubectl get applicationsets -n argocd

# Check ApplicationSet status
kubectl describe applicationset preview-apps -n argocd

# View ApplicationSet-generated applications
kubectl get applications -n argocd -l app.kubernetes.io/managed-by=applicationset-controller
```

#### Manifest Validation Fails in CI

**Symptoms:**
```
::error::Invalid YAML syntax in k8s/argocd/prod-app.yaml
```

**Causes:**
- YAML indentation errors
- Missing required fields
- Invalid references

**Remediation:**
```bash
# Validate YAML locally
yq eval '.' k8s/argocd/prod-app.yaml

# Check for required fields
kubectl apply -f k8s/argocd/prod-app.yaml --dry-run=client

# Use validation script
./scripts/sync-argocd-manifests.sh --dry-run -v
```

#### Sync Succeeds But Application Doesn't Deploy

**Symptoms:**
- Manifest sync reports success
- Application CRD exists
- But workloads aren't deploying

**Causes:**
- Application is configured but has ComparisonError
- Repository is not accessible
- Target revision doesn't exist

**Remediation:**
```bash
# Check application status
kubectl describe application <app-name> -n argocd

# Look for errors
kubectl get application <app-name> -n argocd -o jsonpath='{.status.conditions[*]}'

# Validate application can pull manifests
./scripts/validate-argocd-deployment.sh <app-name> -v
```

### Deployment Workflow

```
┌─────────────────────────────────────────────────────────────────┐
│ Developer modifies k8s/argocd/prod-app.yaml                    │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│ PR → CI validates YAML syntax                                   │
│ ✓ YAML is well-formed                                           │
│ ✓ Kind is Application/ApplicationSet                            │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│ PR merged → Production workflow detects k8s/argocd/ change     │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│ sync-argocd-manifests job runs                                  │
│ 1. Azure Login                                                  │
│ 2. Set AKS Context                                              │
│ 3. Apply changed manifests                                      │
│ 4. Verify applications exist                                    │
└────────────────────┬────────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────────┐
│ Argo CD detects new/updated applications                       │
│ Auto-sync kicks in (if enabled)                                 │
│ Workloads deploy to cluster                                     │
└─────────────────────────────────────────────────────────────────┘
```

### When to Update Argo CD Manifests

**Update `infra-apps.yaml` when:**
- Adding new infrastructure components (new cert-manager config, etc.)
- Changing sync policies for infrastructure apps
- Updating version pins or source repositories

**Update `prod-app.yaml` when:**
- Changing production application configuration
- Updating sync policies or health checks
- Modifying ignoreDifferences patterns

**Update `preview-appset.yaml` when:**
- Changing preview environment generation logic
- Updating preview sync policies
- Modifying preview resource constraints

### Best Practices for Manifest Changes

1. **Test locally before pushing:**
   ```bash
   ./scripts/sync-argocd-manifests.sh --dry-run -v
   ```

2. **Use small, focused changes:**
   - One logical change per PR
   - Don't mix infra and app changes

3. **Verify in PR preview:**
   - CI validation passes
   - YAML syntax is correct

4. **Monitor after merge:**
   ```bash
   kubectl get applications -n argocd -w
   ```

5. **Check workflow logs:**
   - Verify sync-argocd-manifests job succeeded
   - Look for application creation/update confirmation

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
