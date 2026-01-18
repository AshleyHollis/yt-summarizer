# Production Deployment Validation & Troubleshooting Guide

## Overview

This guide documents the permanent deployment validation and error detection system implemented to eliminate timeout-waiting issues in production deployments.

## Problem Statement

Previously, production deployments would wait up to 180 seconds before timing out, even when syncs completed successfully. Example: Sync finished at T+61s, but verification failed at T+60s with a timeout error.

**Root Causes:**
- No pre-flight checks before starting the wait-for-sync loop
- No early detection of manifest errors or sync failures
- Timeout was too short for production syncs with database migration hooks
- Error messages weren't specific enough to diagnose issues quickly

## Solution Architecture

The solution implements three layers of validation and error detection:

## Validation & Error Detection Flow

### Layer 1: Pre-Deployment Manifest Validation (60 seconds)

**Action:** `validate-argocd-manifest`

Runs BEFORE Argo CD sync to detect configuration errors early.

**Validates:**
- ✅ Argo CD Application CRD exists and is accessible
- ✅ Application references correct git branch (not commit SHA)
- ✅ Target namespace configuration is correct
- ✅ No pre-existing sync error conditions
- ✅ Manifest can be generated without errors
- ✅ No long-running operations are stuck (>5 minutes)

**Example Output - Success:**
```
🔍 Pre-deployment Argo CD manifest validation...
  Application: yt-summarizer-prod
  Namespace: yt-summarizer
  Timeout: 60s

✅ Check 1: Argo CD Application CRD exists
✅ Check 2: Application configuration
  Target Revision: main
  Repository: https://github.com/AshleyHollis/yt-summarizer.git
  Path: k8s/overlays/prod
  Destination Namespace: yt-summarizer

✅ Check 3: Manifest generation
✅ Check 4: Sync conditions
  Health Status: Progressing
  Sync Status: OutOfSync

✅ Check 5: Sync operation status
✅ Check 6: Resource validation
  Resource kinds found: Namespace, ConfigMap, ServiceAccount, Service, Deployment, ExternalSecret
  Total resources: 27

✅ All pre-deployment validation checks passed!
```

**Example Output - Failure (Invalid Manifest):**
```
❌ Pre-existing sync error condition detected:
  ComparisonError: kustomize build failed - unable to find patch target

Sync conditions:
{
  "type": "ComparisonError",
  "status": "True",
  "message": "unable to find patch target"
}

Solution: Check kustomization.yaml for invalid patch references
```

### Layer 2: Early Sync Error Detection (Every 30 seconds)

**Enhancement:** `wait-for-argocd-sync` script

Monitors Argo CD for errors during the sync operation. Fails immediately when errors are detected instead of waiting for timeout.

**Detects:**
- ❌ Manifest generation errors (ComparisonError)
- ❌ Invalid resource paths
- ❌ Failed sync operations
- ❌ Hook job failures (database migrations, etc.)
- ❌ Pod-level issues (ImagePullBackOff, CrashLoopBackOff, etc.)

**Example Output - Manifest Error (Detected at 30s):**
```
🔍 Argo CD Status Update (6/36)
  Current Sync Status: OutOfSync
  Target Branch/Revision: main
  Synced to Commit: c64414675e...

  🔍 Checking for manifest generation errors...
  ❌ MANIFEST GENERATION ERROR DETECTED (fail-fast):
    kustomize build failed - invalid YAML syntax

  This means the YAML/Kustomize overlay has invalid syntax.
  Argo CD cannot sync until this is fixed.

  Exit code: 1
```

**Saves:** 150 seconds (180s - 30s = 150s saved per failed deployment)

### Layer 3: Appropriate Timeout (360 seconds for production)

**Updated from:** 180 seconds → 360 seconds

**Rationale:**
- **180s was too short** for production syncs with database migration hooks
- Last production sync: 61 seconds from start to finish
- Total time including Argo CD comparison, planning, and reconciliation: ~2-6 minutes
- **360s (6 minutes) accommodates:**
  - Argo CD comparison phase: 10-30 seconds
  - Manifest generation: 5-15 seconds
  - Resource creation: 10-30 seconds
  - Sync hooks (database migrations): 30-60+ seconds
  - Argo CD finalization: 10-20 seconds

## Deployment Validation Flow

```
┌─────────────────────────────┐
│  Update Production Overlay   │
│  (kustomization validation)  │
└──────────────┬──────────────┘
               │
               ▼
┌──────────────────────────────────────┐
│  PRE-DEPLOYMENT VALIDATION (60s)     │ ← NEW
│  ✅ validate-argocd-manifest action   │
│  - CRD exists & configured correctly  │
│  - No pre-existing sync errors        │
│  - Manifest generates without errors  │
└──────────────┬───────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────┐
│  WAIT FOR SYNC (up to 360s)                      │
│  ✅ wait-for-argocd-sync action (enhanced)       │
│  - Every 30s: Check for manifest errors (fail-fast)
│  - Every 30s: Check for hook job failures        │
│  - Every 30s: Check for pod-level issues        │
│  - Success: Namespace created + Synced=True      │
└──────────────┬───────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────┐
│  VERIFY DEPLOYMENT                   │
│  - Correct image tags                │
│  - Rollout completed                 │
│  - Health checks pass                │
└──────────────────────────────────────┘
```

## Common Error Scenarios & Fixes

### Scenario 1: Manifest Generation Error

**Error Message:**
```
❌ MANIFEST GENERATION ERROR DETECTED:
  unable to find patch target api
```

**Causes:**
- Invalid kustomization.yaml syntax
- Patch references non-existent resource
- Broken YAML structure

**Fix:**
```bash
# Validate kustomization builds locally
kubectl kustomize k8s/overlays/prod > /tmp/manifest.yaml

# Check YAML syntax
kubectl apply --dry-run=client -f /tmp/manifest.yaml

# Fix the kustomization.yaml and push
git add k8s/overlays/prod/kustomization.yaml
git commit -m "fix: correct kustomization syntax error"
git push
```

### Scenario 2: ExternalSecret Failure

**Error Message:**
```
❌ FAILED EXTERNALSECRETS DETECTED:
  ExternalSecret 'db-credentials' failed:
  could not get secret data from provider
```

**Causes:**
- Secret doesn't exist in Azure Key Vault
- Workload Identity lacks permissions
- SecretStore misconfigured

**Fix:**
```bash
# Check if secret exists in Key Vault
az keyvault secret list --vault-name <vault-name> | grep <secret-name>

# Check Workload Identity permissions
az keyvault set-policy --vault-name <vault-name> \
  --spn <workload-identity-client-id> \
  --secret-permissions get list

# Verify SecretStore exists in namespace
kubectl get secretstore -n yt-summarizer
```

### Scenario 3: Image Pull Failure

**Error Message:**
```
❌ IMAGE PULL ERRORS DETECTED:
  Pod 'api-5d6f7c8b9e' cannot pull image
  Image: acrytsummprd.azurecr.io/yt-summarizer-api:sha-12345678
  Error: imagepullbackoff
```

**Causes:**
- CI build failed (image doesn't exist in ACR)
- AKS cluster lacks ACR permissions
- ACR firewall blocking access

**Fix:**
```bash
# Verify image exists in ACR
az acr repository show --name acrytsummprd \
  --repository yt-summarizer-api \
  --query "tags.sha-12345678"

# Check AKS kubelet identity permissions
az role assignment list --assignee-type serviceprincipal \
  --query "[?roleDefinitionName=='AcrPull']"

# Grant AcrPull permission if needed
az role assignment create --assignee-principal-id <kubelet-identity-oid> \
  --role AcrPull \
  --scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.ContainerRegistry/registries/acrytsummprd
```

### Scenario 4: Hook Job Failure (Database Migration)

**Error Message:**
```
❌ HOOK JOB FAILED:
  Hook job db-migration has failed

Pod logs:
  Error: Connection refused connecting to database
  Failed to apply migration script
```

**Causes:**
- Database connection issues
- Migration script syntax errors
- Missing database credentials

**Fix:**
```bash
# Check database is accessible
kubectl port-forward -n yt-summarizer svc/sql-server 1433:1433 &
sqlcmd -S localhost -U <user> -P <password> -Q "SELECT @@VERSION"

# Check migration pod logs
kubectl logs -n yt-summarizer -l job-name=db-migration --tail=50

# Verify database credentials secret
kubectl get secret db-credentials -n yt-summarizer -o jsonpath='{.data}'

# Check database is running
kubectl get pod -n yt-summarizer -l app=database
```

### Scenario 5: Sync Loop (Synced → OutOfSync Repeatedly)

**Error Message:**
```
❌ SYNC LOOP DETECTED (fail-fast at 3/36):
  Argo CD is repeatedly syncing successfully but immediately returning to OutOfSync.

  Pattern detected:
    - Operation completes successfully (Succeeded)
    - Sync status briefly becomes 'Synced'
    - Immediately flips back to 'OutOfSync'
    - This has repeated 3 times

  Common causes:
    1. Resource has fields that are modified by controllers/admission webhooks
    2. Spec in git doesn't match actual desired state
    3. ignoreDifferences configuration needed for certain fields
    4. Resource is managed by multiple controllers (conflict)
```

**Root Cause:**
The most common cause is **Jobs with Sync hooks** combined with **selfHeal: true**:
1. Job completes successfully and `.status` fields change (completionTime, succeeded, etc.)
2. selfHeal detects difference between desired state (no status) and actual state (completed)
3. selfHeal triggers new sync, creating a new Job (due to BeforeHookCreation delete policy)
4. Loop repeats infinitely

**Fix:**
Add `ignoreDifferences` to the Argo CD Application to ignore Job status fields:

```yaml
# k8s/argocd/prod-app.yaml
spec:
  ignoreDifferences:
    # Ignore Job completion status to prevent sync loop with selfHeal
    - group: batch
      kind: Job
      jqPathExpressions:
        - .status.completionTime
        - .status.conditions
        - .status.startTime
        - .status.succeeded
        - .status.active
        - .status.failed
```

**Other Common Resources Needing ignoreDifferences:**
```yaml
# Deployments (Kubernetes adds default values)
- group: apps
  kind: Deployment
  jqPathExpressions:
    - .spec.replicas  # If using HPA
    - .spec.template.spec.containers[].resources  # If modified by VPA

# Services (cloud providers modify)
- group: ""
  kind: Service
  jqPathExpressions:
    - .spec.clusterIP
    - .spec.clusterIPs
    - .metadata.annotations.cloud\.google\.com  # Cloud-specific annotations
```

**Verification:**
```bash
# Watch for sync loop pattern
kubectl get application yt-summarizer-prod -n argocd -w

# Check which resources are out of sync
kubectl get application yt-summarizer-prod -n argocd \
  -o jsonpath='{.status.resources}' | jq '.[] | select(.status != "Synced")'

# View diff between desired and actual state
argocd app diff yt-summarizer-prod
```

### Scenario 6: Application Crash Loop

**Error Message:**
```
❌ CRASH LOOP DETECTED:
  Pod 'api-5d6f7c8b9e' is crash looping

Logs (previous run):
  raise DatabaseConnectionError("Cannot connect to database")
  No such environment variable: DB_HOST
```

**Causes:**
- Missing environment variables
- Configuration errors
- Application startup failures

**Fix:**
```bash
# Check environment variables in pod
kubectl describe pod <pod-name> -n yt-summarizer | grep -A 20 "Environment:"

# Check ConfigMap and Secrets
kubectl get configmap -n yt-summarizer -o yaml
kubectl get secret -n yt-summarizer -o yaml | head -50

# Verify database connection
kubectl exec -it <pod-name> -n yt-summarizer -- /bin/bash
# Inside pod:
nc -zv sql-server 1433
echo $DB_HOST $DB_USER
```

## Monitoring & Observability

### Validation Consolidation Strategy

**Overview:** We have validation at multiple stages - here's when and why each runs:

| Stage | Where | Tool | Purpose | Runs On |
|-------|-------|------|---------|---------|
| **Pre-commit** | Developer machine | `pre-commit`, linters | Basic syntax | Local |
| **PR Validation** | CI on all branches | `kustomize-validate` action | Build + validate + CPU checks | All branches |
| **Prod Overlay Validation** | CI before merge | `kustomize-validate` action | Prod-specific validation | Main branch |
| **Pre-deployment (new)** | Deploy-prod workflow | `validate-argocd-manifest` action | Argo CD CRD configuration | Production deploy |
| **Post-update (safety)** | Deploy-prod workflow | Inline `kubectl kustomize` | Validate after image tag update | Production deploy |
| **During sync (new)** | Deploy-prod workflow | `wait-for-argocd-sync` script | Early error detection every 30s | Production deploy |

**Consolidation Notes:**
- The first inline validation in `deploy-prod.yml` ("Validate current kustomization baseline") is redundant since CI has already validated the prod overlay before the branch was merged to main. It's kept as a defensive safety net.
- The second inline validation ("Validate kustomization builds successfully") is critical - it runs AFTER `update-prod-kustomization` inserts image tags. This catches errors introduced by the kustomization update action.
- The new `validate-argocd-manifest` action is **not a duplicate** - it validates Argo CD Application CRD configuration, sync conditions, and manifest generation from Argo CD's perspective, which local kustomize validation doesn't check.

**Future Optimization:** Replace both inline `kubectl kustomize` calls with calls to the `kustomize-validate` action for consistency, once all edge cases are understood.

### Deployment Logs

1. **Navigate to workflow run**
   ```
   https://github.com/AshleyHollis/yt-summarizer/actions/runs/{RUN_ID}
   ```

2. **Expand job steps to see:**
   - Pre-deployment validation results
   - Argo CD status every 30 seconds
   - Manifest errors (fail-fast detection)
   - Final verification results

3. **Key indicators in logs:**
   - ✅ = Success (proceed)
   - ⚠️ = Warning (not blocking)
   - ❌ = Fatal error (deployment fails)
   - 🔍 = Status check (every 30s)

### Argo CD Dashboard

**Access:** `https://argocd.<cluster-domain>/applications/yt-summarizer-prod`

**Key Metrics:**
- **Sync Status:** Should go from `OutOfSync` → `Synced` within 6 minutes
- **Health:** Should go from `Progressing` → `Healthy`
- **Operation:** Should show `Phase: Succeeded` after sync completes

### Kubernetes Events

Check Argo CD controller logs for sync details:

```bash
# Monitor Argo CD controller logs
kubectl logs -n argocd deployment/argocd-application-controller -f

# Check namespace events
kubectl get events -n yt-summarizer --sort-by='.lastTimestamp'

# Describe deployment for progress details
kubectl describe deployment api -n yt-summarizer
```

## Validation Checklist

Before merging changes to production:

- [ ] All kustomization files validate with `kubectl kustomize k8s/overlays/prod`
- [ ] No YAML syntax errors
- [ ] All patches reference existing resources
- [ ] ConfigMap and ExternalSecret names match deployment references
- [ ] Image tags are set correctly in kustomization.yaml
- [ ] Database migration hooks are properly configured
- [ ] All required secrets exist in Azure Key Vault

## Performance Baseline

**Expected deployment times (from overlay commit to sync complete):**

| Scenario | Time |
|----------|------|
| Config-only change (no hooks) | 30-60 seconds |
| Code change (container restart) | 45-90 seconds |
| With database migration hook | 90-180 seconds |
| Large resource additions | 120-240 seconds |
| Timeout (error detection) | 30-60 seconds (early failure) |
| Timeout (legitimate issue) | 360 seconds (max wait) |

**Historical Data:**
- Last successful production sync: 61 seconds
- Typical database migration: 45-60 seconds  
- Slow syncs (rare): 120-180 seconds

## Future Improvements

1. **Proactive Health Checks**
   - Detect pod readiness issues before timeout expires
   - Pre-check database connectivity before migration
   - Validate all secrets exist before sync

2. **Better Async Patterns**
   - Instead of polling, use Argo CD webhooks
   - Real-time status updates instead of 30s intervals
   - Event-driven sync completion detection

3. **Timeout Optimization**
   - Per-resource type timeouts (migrations vs. deployments)
   - Dynamic timeout based on resource count
   - Machine learning for realistic timeout prediction

4. **Observability**
   - Structured logging with correlation IDs
   - Metrics for sync duration by change type
   - Dashboard with deployment timeline

## References

- **Argo CD Application Status:** https://argo-cd.readthedocs.io/en/stable/user-guide/status-badge/#application-status
- **Argo CD Troubleshooting:** https://argo-cd.readthedocs.io/en/stable/user-guide/troubleshooting/
- **Azure ExternalSecrets:** https://external-secrets.io/latest/provider/azure-keyvault/
- **Kubernetes Workload Identity:** https://learn.microsoft.com/en-us/azure/aks/workload-identity-deploy-cluster

## Support

For deployment issues:

1. Check the GitHub Actions workflow logs for specific error messages
2. Review the common error scenarios in this guide
3. Check Argo CD dashboard for application status
4. Examine Kubernetes events and pod logs
5. Verify all secrets and configuration are correct
6. If still stuck, check recent changes to kustomization.yaml or manifests

---

**Last Updated:** 2026-01-18  
**Author:** Deployment Engineering  
**Version:** 1.0
