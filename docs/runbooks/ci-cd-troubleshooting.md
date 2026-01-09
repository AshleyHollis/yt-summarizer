# CI/CD Troubleshooting Guide

This guide covers common issues and solutions for the GitHub Actions CI/CD pipelines.

## Table of Contents

1. [CI Pipeline Issues](#ci-pipeline-issues)
2. [Build & Push Issues](#build--push-issues)
3. [Production Deployment Issues](#production-deployment-issues)
4. [Infrastructure Pipeline Issues](#infrastructure-pipeline-issues)
5. [Common Error Messages](#common-error-messages)
6. [Emergency Procedures](#emergency-procedures)

## CI Pipeline Issues

### Tests Failing

**Symptom**: Test jobs are failing in CI

**Steps**:

1. Check the specific test output in GitHub Actions
2. Run tests locally to reproduce:

```powershell
# Python tests
cd services/api; python -m pytest tests/ -v

# Frontend tests
cd apps/web; npm run test:run

# E2E tests (requires Aspire)
aspire run  # Start backend
cd apps/web; $env:USE_EXTERNAL_SERVER = "true"; npx playwright test
```

3. Common causes:
   - Missing dependencies (check `pyproject.toml` or `package.json`)
   - Environment variables not set
   - Database connection issues (E2E tests)
   - Flaky tests (race conditions)

### Lint Failures

**Symptom**: `lint-python` or `lint-frontend` jobs fail

**Python**:
```powershell
cd services
ruff check . --fix
ruff format .
```

**Frontend**:
```powershell
cd apps/web
npm run lint -- --fix
npm run format
```

### E2E Tests Timeout

**Symptom**: E2E tests hang or timeout

**Steps**:

1. Check if Aspire services started correctly
2. Verify health endpoints respond:
```powershell
curl http://localhost:8000/health
curl http://localhost:3000
```

3. Check Docker container status:
```powershell
docker ps
docker logs mssql
```

4. Increase timeout in `playwright.config.ts` if needed

### Terraform Validation Failed

**Symptom**: `validate-terraform` job fails

```powershell
cd infra/terraform/environments/staging
terraform init
terraform validate
```

Common fixes:
- Update provider versions
- Fix variable references
- Check module paths

### Kustomize Validation Failed

**Symptom**: `validate-kustomize` job fails

```powershell
kustomize build k8s/overlays/staging
kustomize build k8s/overlays/production
```

Common fixes:
- Fix YAML syntax errors
- Ensure base resources exist
- Verify patch paths match

## Build & Push Issues

### Azure Login Failed

**Symptom**: `Azure Login via OIDC` step fails

**Causes**:
- Federated credentials not configured
- Wrong subscription/tenant ID
- OIDC token expired

**Steps**:

1. Verify GitHub secrets are set:
   - `AZURE_CLIENT_ID`
   - `AZURE_TENANT_ID`
   - `AZURE_SUBSCRIPTION_ID`

2. Check federated credentials in Azure:
```powershell
az ad app federated-credential list --id <app-id>
```

3. Verify the federated credential matches:
   - Issuer: `https://token.actions.githubusercontent.com`
   - Subject: `repo:AshleyHollis/yt-summarizer:ref:refs/heads/main`

### ACR Push Failed

**Symptom**: `docker push` fails with authentication error

**Steps**:

1. Verify ACR login:
```powershell
az acr login --name <acr-name>
```

2. Check service principal has `AcrPush` role:
```powershell
az role assignment list --scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.ContainerRegistry/registries/<acr>
```

3. Verify image tag format matches ACR expectations

### Docker Build Failed

**Symptom**: Docker build fails during CI

**Common causes**:

1. **Missing files in build context**:
   - Check `.dockerignore` isn't excluding needed files
   - Verify file paths in Dockerfile

2. **Dependency installation failures**:
   - Check network access from runner
   - Verify package versions exist

3. **Multi-platform build issues**:
   - Ensure buildx is available
   - Check platform support for base images

### SWA Deployment Failed

**Symptom**: Static Web Apps deployment fails

**Steps**:

1. Verify `SWA_STAGING_TOKEN` or `SWA_PRODUCTION_TOKEN` secret is set
2. Check build output exists at expected location
3. Verify `staticwebapp.config.json` syntax

## Preview Environment Issues

### Preview Not Created

**Symptom**: PR merged but no preview environment appears

**Steps**:

1. Check if CI passed (preview requires CI success):
   - Go to PR > Checks tab > Verify "CI" passed

2. Check Preview workflow ran:
   - Actions > Preview workflow > Find run for your PR

3. Verify preview overlay was created:
```bash
ls k8s/overlays/previews/pr-<number>/
```

4. Check Argo CD ApplicationSet picked it up:
```bash
argocd app list | grep preview
```

### Preview Environment Not Accessible

**Symptom**: Preview URL returns 404 or connection refused

**Steps**:

1. Check pods are running:
```bash
kubectl get pods -n preview-pr-<number>
```

2. Check ingress is configured:
```bash
kubectl get ingress -n preview-pr-<number>
kubectl describe ingress -n preview-pr-<number>
```

3. Check services:
```bash
kubectl get svc -n preview-pr-<number>
kubectl get endpoints -n preview-pr-<number>
```

4. Check pod logs:
```bash
kubectl logs -n preview-pr-<number> deployment/api
```

### Preview Not Cleaned Up

**Symptom**: Preview namespace still exists after PR closed/merged

**Steps**:

1. Check cleanup workflow ran:
   - Actions > Preview Cleanup > Find run for your PR

2. Verify overlay was deleted:
```bash
ls k8s/overlays/previews/  # Should not contain pr-<number>
```

3. Manual cleanup if needed:
```bash
# Delete the overlay directory
rm -rf k8s/overlays/previews/pr-<number>
git add -A
git commit -m "chore: manual cleanup of pr-<number> preview"
git push origin main

# Argo CD will prune the namespace automatically
```

### Max Preview Limit Reached

**Symptom**: Preview workflow skipped with "Max previews exceeded"

**Steps**:

1. Check current preview count:
```bash
ls k8s/overlays/previews/ | grep -c "pr-"
```

2. Close old PRs or manually clean up stale previews:
```bash
# List PRs with previews
for dir in k8s/overlays/previews/pr-*/; do
  pr_num=$(basename $dir | sed 's/pr-//')
  echo "PR #$pr_num: $(gh pr view $pr_num --json state -q .state)"
done
```

3. Delete stale previews for closed PRs

## Production Deployment Issues

### Confirmation Not Accepted

**Symptom**: Workflow fails with "Deployment not confirmed"

**Fix**: Enter exactly `DEPLOY` (case-sensitive) in the confirmation field

### Image Not Found in ACR

**Symptom**: "API image with tag sha-xxx not found"

**Steps**:

1. Verify the staging SHA exists:
```powershell
az acr repository show-tags --name <acr> --repository api
az acr repository show-tags --name <acr> --repository workers
```

2. Wait for staging deployment to complete first
3. Use the correct SHA from staging deployment logs

### Argo CD Not Syncing

**Symptom**: Manifest updated but pods not changing

**Steps**:

1. Check Argo CD application status:
```bash
argocd app get yt-summarizer-production
```

2. Manually trigger sync:
```bash
argocd app sync yt-summarizer-production
```

3. Check for sync errors:
```bash
argocd app get yt-summarizer-production -o json | jq '.status.operationState'
```

### Health Check Failed

**Symptom**: Deployment completes but health check fails

**Steps**:

1. Check pod status:
```bash
kubectl get pods -n yt-summarizer
kubectl describe pod <pod-name> -n yt-summarizer
```

2. Check service endpoints:
```bash
kubectl get endpoints -n yt-summarizer
```

3. Check ingress:
```bash
kubectl get ingress -n yt-summarizer
kubectl describe ingress api-ingress -n yt-summarizer
```

4. Check logs:
```bash
kubectl logs -l app=api -n yt-summarizer
```

## Infrastructure Pipeline Issues

### Terraform Init Failed

**Symptom**: `terraform init` fails

**Causes**:
- Storage account not accessible
- Backend configuration wrong
- Network issues

**Steps**:

1. Check storage account exists:
```powershell
az storage account show --name <storage-account>
```

2. Verify container exists:
```powershell
az storage container list --account-name <storage-account>
```

3. Check OIDC permissions for storage access

### Terraform Apply Failed

**Symptom**: `terraform apply` fails mid-deployment

**Steps**:

1. Check error message for specific resource
2. Look for quota limits:
```powershell
az vm list-usage --location eastus -o table
```

3. Check for naming conflicts (resources already exist)
4. Review state lock:
```powershell
terraform force-unlock <lock-id>
```

### Drift Detected

**Symptom**: Terraform shows unexpected changes

**Steps**:

1. Review the planned changes carefully
2. Import existing resources if needed:
```powershell
terraform import azurerm_resource_group.main /subscriptions/.../resourceGroups/rg-name
```

3. Refresh state:
```powershell
terraform refresh
```

## Common Error Messages

### "Error: context deadline exceeded"

**Cause**: Network timeout connecting to Azure
**Fix**: Retry the workflow, check Azure service health

### "Error: subscription not found"

**Cause**: Wrong subscription ID or no access
**Fix**: Verify `AZURE_SUBSCRIPTION_ID` secret

### "Error: ResourceNotFound"

**Cause**: Resource was deleted or never created
**Fix**: Check resource exists, run terraform apply

### "denied: requested access to the resource is denied"

**Cause**: ACR authentication failed
**Fix**: Re-run `az acr login`, check RBAC permissions

### "ImagePullBackOff"

**Cause**: Kubernetes can't pull image from ACR
**Fix**: 
1. Verify ACR attachment to AKS
2. Check image tag exists
3. Verify AcrPull role assignment

## Emergency Procedures

### Rollback Deployment

```bash
# Via Argo CD
argocd app rollback yt-summarizer-production

# Via Git revert
git revert HEAD
git push origin main
```

### Stop Deployment

1. Cancel the running workflow in GitHub Actions
2. If pods are crashing, scale down:
```bash
kubectl scale deployment api --replicas=0 -n yt-summarizer
```

### Disable Auto-Sync

```bash
argocd app set yt-summarizer-production --sync-policy none
```

### Force Manual State

```bash
# Disable all automatic deployments
argocd app set yt-summarizer-staging --sync-policy none
argocd app set yt-summarizer-production --sync-policy none

# Manually apply known-good manifests
kubectl apply -k k8s/overlays/staging
```

### Contact Points

- **GitHub Actions**: Check workflow run logs
- **Azure Portal**: Monitor resource health
- **Argo CD Dashboard**: View sync status and logs
- **Kubernetes**: Use kubectl for direct cluster access
