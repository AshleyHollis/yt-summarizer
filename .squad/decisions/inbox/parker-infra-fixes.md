# Parker — Infrastructure Fixes Post-Rebuild (2026-03-04)

## Decisions Made

### 1. Pipeline Fix: Ternary String Pattern for Boolean Inputs
**Decision**: Use `${{ inputs.X && 'true' || 'false' }}` pattern instead of raw `${{ inputs.X }}` for `continue-on-error` and similar fields that require boolean strings.
**Rationale**: GitHub Actions converts boolean `false` to empty string `''` in expression contexts outside `if:` conditionals. This is a platform behavior, not a bug in our code, but it causes YAML validation errors.
**PR**: #169

### 2. Key Vault RBAC: Bootstrap Dependency
**Decision**: The `github-actions-yt-summarizer` SP's Key Vault Secrets Officer role is a bootstrap dependency that must be provisioned outside Terraform (via Azure CLI or shared-infra). It was granted manually.
**Rationale**: Terraform requires Key Vault read access to plan (import blocks read existing secrets). The SP's role assignment was lost during the cluster rebuild to centralindia. This is a chicken-and-egg problem — Terraform can't self-provision the role it needs to run.
**Action needed**: This role assignment should be codified in `shared-infra` repo to prevent loss during future rebuilds.

## Manual Actions Required (Ashley)

### A. Merge PR #169
Unblocks ALL production deployments. One-line fix.

### B. Populate Webshare Proxy Credentials in Key Vault
```bash
az keyvault secret set --vault-name kv-ytsumm-prd-ci --name webshare-proxy-username --value "<YOUR_USERNAME>"
az keyvault secret set --vault-name kv-ytsumm-prd-ci --name webshare-proxy-password --value "<YOUR_PASSWORD>"
```
Then restart the transcribe-worker:
```bash
kubectl rollout restart deployment/transcribe-worker -n yt-summarizer
```

### C. Update SWA_DEPLOYMENT_TOKEN After Terraform Creates SWA
After the first successful deploy-prod.yml run (which creates `swa-ytsumm-prd`):
1. Get the new SWA deployment token: `terraform output -raw swa_api_key`
2. Update GitHub secret: Settings → Secrets → `SWA_DEPLOYMENT_TOKEN`
3. Re-run the deploy-prod.yml workflow to deploy frontend content
