# Infrastructure Issues - RESOLVED

## AKS Cluster DNS Resolution Failure - ✅ FIXED

**Status**: ✅ RESOLVED  
**Date Resolved**: 2026-01-31  
**Severity**: High (was blocking all preview deployments)  
**Component**: Azure Kubernetes Service (AKS)

### Problem

Preview deployment workflows failed when attempting to access the AKS cluster. All kubectl operations failed with DNS resolution errors:

```
Error: dial tcp: lookup ytsumm-prd-3jclj263.hcp.eastasia.azmk8s.io on 127.0.0.53:53: no such host
```

### Root Cause Analysis

**FOUND**: The AKS cluster was in a **STOPPED** state (`PowerState: Stopped`).

When an AKS cluster is stopped:
- DNS records for the API server are deregistered
- The cluster's FQDN becomes unresolvable
- All kubectl operations fail
- The cluster still exists in Azure but is not running
- This is by design to save costs when the cluster isn't needed

### Investigation Steps Performed

1. ✅ Verified cluster exists in Azure: `az aks list` showed cluster present
2. ✅ Confirmed public accessibility: No private cluster config, no authorized IP restrictions
3. ✅ Tested DNS resolution: `nslookup` failed with "Non-existent domain"
4. ✅ Reproduced locally: Same DNS failure on developer machine (not GitHub Actions-specific)
5. ✅ Checked provisioning state: ProvisioningState=Succeeded, PowerState=**Stopped** ← ROOT CAUSE
6. ✅ Started cluster: `az aks start`
7. ✅ Verified resolution: DNS now resolves to 20.24.254.87, kubectl connectivity confirmed

### Resolution Applied

```bash
# Start the AKS cluster
az aks start --resource-group rg-ytsumm-prd --name aks-ytsumm-prd

# Verify cluster is running
az aks show --resource-group rg-ytsumm-prd --name aks-ytsumm-prd \
  --query "{PowerState:powerState.code, ProvisioningState:provisioningState}"

# Test connectivity
kubectl cluster-info
kubectl get nodes
```

**Results**:
- PowerState: Running ✅
- ProvisioningState: Succeeded ✅
- DNS resolves: 20.24.254.87 ✅
- kubectl connectivity: ✅
- Nodes ready: aks-system2-36700510-vmss000004 (v1.33.5) ✅

### Impact Resolution

✅ **All kubectl operations now functional**
✅ **ArgoCD can manage applications**
✅ **Preview deployments can proceed**
✅ **PR testing environment available**

### Lessons Learned

1. **AKS Stop/Start Feature**: Clusters can be stopped to save costs but this breaks all access
2. **DNS Deregistration**: Stopped clusters have no DNS records - not a DNS propagation issue
3. **Cost vs Availability**: Need clear policy on when to stop/start cluster
4. **Monitoring**: Should alert if cluster is stopped when deployments expected

### Recommendations

#### 1. Cluster Lifecycle Policy

Define when the cluster should be stopped/started:
- **Option A**: Keep running 24/7 for dev/preview environments
- **Option B**: Auto-stop/start on schedule (e.g., off-hours, weekends)
- **Option C**: Manual control with clear communication

#### 2. Add Startup Step to Workflows

If cluster stop/start is desired, add a workflow step to ensure cluster is running:

```yaml
- name: Ensure AKS cluster is running
  run: |
    STATE=$(az aks show -g rg-ytsumm-prd -n aks-ytsumm-prd --query "powerState.code" -o tsv)
    if [ "$STATE" = "Stopped" ]; then
      echo "Cluster is stopped. Starting..."
      az aks start -g rg-ytsumm-prd -n aks-ytsumm-prd --no-wait
      # Wait for cluster to be accessible
      for i in {1..30}; do
        if az aks show -g rg-ytsumm-prd -n aks-ytsumm-prd --query "provisioningState" -o tsv | grep -q "Succeeded"; then
          break
        fi
        sleep 10
      done
    fi
```

#### 3. Cost Optimization

If keeping cluster running is too expensive:
- Use smaller node SKUs for dev/preview (e.g., Standard_B2s instead of Standard_D2s_v3)
- Enable cluster autoscaler to scale down to 0 nodes when idle
- Use Azure Dev/Test pricing for non-production subscriptions

#### 4. Monitoring & Alerts

- Monitor cluster PowerState in Azure Monitor
- Alert on unexpected state changes
- Dashboard showing cluster status before deployments

### Status

- ✅ Cluster is now running and accessible
- ✅ Preview deployments unblocked
- ✅ All workflow steps can proceed
- ⏭️ E2E tests remain disabled (separate known issue - will fix another time)

### Next Steps

1. Test full preview deployment workflow
2. Decide on cluster lifecycle policy (always-on vs scheduled vs manual)
3. Implement workflow startup step if stop/start model desired
4. Update runbooks with cluster start/stop procedures
