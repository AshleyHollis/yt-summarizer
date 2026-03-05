# Decision: AKS-ACR Credential Provider Must Be Attached

**Date:** 2026-03-05  
**Author:** Parker (DevOps)  
**Context:** PR #170 deploy monitoring (Run #22706152345)

## Problem

ArgoCD sync is blocked because the `db-migration` Job cannot pull images from `acrytsummprdci.azurecr.io` (401 Unauthorized). The AcrPull role exists on the kubelet managed identity, but the AKS cluster's credential provider plugin is not registered for this ACR (`acrProfile: null`).

## Decision

Run `az aks update --name aks-ytsumm-prd-ci --resource-group rg-ytsumm-prd-ci --attach-acr acrytsummprdci` to register the ACR with the AKS credential provider. This is a prerequisite for any image deployment from the new registry.

Additionally, the Terraform AKS module should include `acr_id` in the `aks` resource to ensure this attachment is managed as code and doesn't break again on future rebuilds.

## Impact

- **Blocking**: No new images can be deployed until this is resolved.
- **All pods** currently run old images from `acrytsummprd.azurecr.io` — CORS and security header fixes from PR #170 are NOT live.
- **SWA** not created (Terraform skipped due to CI failure).

## Additional Blockers

- CI pipeline fails due to `npm audit` vulnerabilities in frontend dependencies (13 vulns, 2 high). Frontend team must address.
