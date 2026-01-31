# Infrastructure Issues Blocking CI/CD

## AKS Cluster DNS Resolution Failure

**Status**: BLOCKING preview deployments  
**Severity**: High  
**Component**: Azure Kubernetes Service (AKS)

### Problem

Preview deployment workflows fail when attempting to verify Kubernetes can pull images from ACR. The failure occurs during DNS resolution of the AKS API server:

```
Error: dial tcp: lookup ytsumm-prd-3jclj263.hcp.eastasia.azmk8s.io on 127.0.0.53:53: no such host
```

### Analysis

1. **Cluster Exists**: `az aks get-credentials` command succeeds, confirming the cluster exists in Azure
2. **DNS Fails**: `kubectl` commands fail because they cannot resolve the cluster's API server FQDN
3. **Terraform State**: No terraform deployments found in workflow history - cluster likely created manually
4. **Configuration**: Terraform shows cluster configured as public (not private) with no authorized IP restrictions

### Root Cause

The AKS cluster's API server is not accessible from GitHub Actions hosted runners. Possible causes:

1. **DNS Propagation**: Cluster FQDN not propagated to public DNS
2. **Network Configuration**: Despite terraform showing public config, actual Azure resource may have restrictions
3. **Stale Configuration**: Kubeconfig contains outdated/incorrect API server hostname
4. **Deleted/Recreated**: Cluster was deleted and recreated with different FQDN

### Impact

**CRITICAL: Preview deployments are completely non-functional**

- ❌ **All kubectl operations fail** (cannot communicate with AKS API server)
- ❌ **ArgoCD application management impossible** (relies on kubectl)
- ❌ **Cannot verify deployments** (kubectl get deployments/pods fails)
- ❌ **Cannot create/update preview environments** (entire workflow blocked)
- ❌ **PR preview testing completely unavailable**

**Affected workflow steps:**
1. Update Preview Overlay: ✅ Succeeds (only updates Git, no K8s access needed)
2. Verify cluster can pull image: ❌ Fails (kubectl run cannot connect) - DISABLED as workaround
3. Verify Deployment: ❌ **FAILS** (ArgoCD CLI uses kubectl, all queries fail)
   - Waits 180s for ArgoCD app `preview-pr-124` but never finds it
   - Every kubectl command: `Unable to connect to the server: dial tcp: lookup ytsumm-prd-3jclj263.hcp.eastasia.azmk8s.io... no such host`
4. Deploy Frontend Preview: Unknown (likely affected if it uses kubectl)
5. Preview Status Check: ❌ Fails (depends on deployment verification)

**This is not just a test failure - preview deployments cannot function at all without AKS access.**

### Recommended Fixes (Priority Order)

#### 1. Verify Cluster Exists and Is Accessible

```bash
# Check if cluster exists
az aks list --resource-group rg-ytsumm-prd --query "[].name"

# Get current API server FQDN
az aks show --resource-group rg-ytsumm-prd --name aks-ytsumm-prd \
  --query "fqdn" -o tsv

# Test DNS resolution
nslookup <fqdn-from-above>
```

#### 2. Check Network Configuration

```bash
# Verify cluster is public (not private)
az aks show --resource-group rg-ytsumm-prd --name aks-ytsumm-prd \
  --query "apiServerAccessProfile"

# Check authorized IP ranges
az aks show --resource-group rg-ytsumm-prd --name aks-ytsumm-prd \
  --query "apiServerAccessProfile.authorizedIpRanges"
```

#### 3. Refresh Kubeconfig

The workflow already runs `az aks get-credentials` but if the cluster was recreated, the FQDN may have changed:

```bash
# Force refresh kubeconfig
az aks get-credentials --resource-group rg-ytsumm-prd \
  --name aks-ytsumm-prd --overwrite-existing
```

#### 4. Terraform State Sync

If cluster was manually created/modified, sync terraform state:

```bash
cd infra/terraform/environments/prod
terraform import azurerm_kubernetes_cluster.aks \
  /subscriptions/<sub-id>/resourceGroups/rg-ytsumm-prd/providers/Microsoft.ContainerService/managedClusters/aks-ytsumm-prd
terraform plan  # Should show no changes if in sync
```

#### 5. Alternative: Self-Hosted Runners

If cluster must remain private/restricted, use self-hosted GitHub Actions runners with network access to AKS:

- Deploy runner in same VNET as AKS
- Configure authorized IP ranges to include runner's public IP

### Temporary Workaround

**UPDATE: No viable workaround exists - preview deployments remain fully blocked**

Attempted workaround:
1. ✅ Disabled K8s pull test - "Update Preview Overlay" step now succeeds
2. ❌ "Verify Deployment" step still fails - ALL kubectl operations affected, not just image pull test

**Why the workaround failed:**
- ArgoCD CLI uses kubectl to check application status
- Workflow waits 180s for ArgoCD application `preview-pr-124` but never finds it (cannot query K8s)
- Every kubectl command in the workflow fails with identical DNS error
- Frontend deployment may also be affected (status unknown)

**Conclusion:** Preview deployments cannot proceed until AKS cluster API server is accessible from GitHub Actions runners. There is no code-level workaround.

**REQUIRED ACTION:** Azure administrator MUST resolve AKS cluster accessibility. This is a hard infrastructure blocker.

### Files Modified

- `.github/workflows/preview.yml`: Set `run-k8s-pull-test: 'false'` (line 511)
- `.github/actions/validate-docker-image/test-k8s-pull.sh`: Improved error diagnostics

### Next Steps

1. Azure admin verifies AKS cluster accessibility
2. Test DNS resolution from GitHub Actions runner
3. Re-enable K8s pull test once connectivity confirmed
4. Run terraform apply to ensure infrastructure matches code
