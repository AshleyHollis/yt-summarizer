# Production Deployment Reference

> **Last Updated**: January 9, 2026  
> **Deployed By**: Initial bootstrap via Terraform + Argo CD

## Azure Resources

| Resource | Name | Region |
|----------|------|--------|
| Resource Group | `rg-ytsumm-prd` | East Asia |
| Container Registry | `acrytsummprd.azurecr.io` | East Asia |
| AKS Cluster | `aks-ytsumm-prd` | East Asia |
| SQL Server | `sql-ytsumm-prd.database.windows.net` | East Asia |
| SQL Database | `ytsummarizer` | East Asia |
| Key Vault | `kv-ytsumm-prd.vault.azure.net` | East Asia |
| Storage Account | `stytsummprd.blob.core.windows.net` | East Asia |
| Static Web App | `swa-ytsumm-prd` | Global |

## Endpoints

| Service | URL |
|---------|-----|
| Frontend (SWA) | https://red-grass-06d413100.6.azurestaticapps.net |
| Ingress Controller IP | `20.255.113.149` |
| API (after DNS setup) | https://api.ytsummarizer.dev |

## Accessing the Cluster

```powershell
# Get AKS credentials
az aks get-credentials --resource-group rg-ytsumm-prd --name aks-ytsumm-prd

# Verify connection
kubectl get nodes
```

## Argo CD Access

```powershell
# Port-forward to access Argo CD UI
kubectl port-forward svc/argocd-server -n argocd 8080:443

# Open in browser: https://localhost:8080
# Username: admin
# Password: Stored in Azure Key Vault (see below)
```

### Retrieving Argo CD Password

```powershell
# Option 1: From Kubernetes secret
kubectl -n argocd get secret argocd-initial-admin-secret -o jsonpath="{.data.password}" |
    ForEach-Object { [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($_)) }

# Option 2: From Azure Key Vault
az keyvault secret show --vault-name kv-ytsumm-prd --name argocd-admin-password --query value -o tsv
```

## Argo CD Applications

| Application | Sync Status | Description |
|-------------|-------------|-------------|
| `ingress-nginx` | Auto-sync | NGINX Ingress Controller |
| `external-secrets` | Auto-sync | External Secrets Operator |
| `eso-secretstore` | Auto-sync | Azure Key Vault integration |
| `yt-summarizer-prod` | Auto-sync | Production application |
| `yt-summarizer-previews` | ApplicationSet | PR preview environments |

```powershell
# Check application status
kubectl get applications -n argocd

# Sync an application manually
kubectl patch application <app-name> -n argocd --type merge -p '{"operation":{"sync":{}}}'
```

## Key Vault Secrets

| Secret Name | Description |
|-------------|-------------|
| `sql-connection-string` | SQL Server connection string |
| `storage-connection` | Azure Storage connection string |
| `argocd-admin-password` | Argo CD admin password |

```powershell
# List all secrets
az keyvault secret list --vault-name kv-ytsumm-prd --query "[].name" -o tsv

# Get a secret value
az keyvault secret show --vault-name kv-ytsumm-prd --name <secret-name> --query value -o tsv
```

## DNS Configuration (TODO)

Configure these DNS records once you have a domain:

| Type | Name | Value |
|------|------|-------|
| A | `api.ytsummarizer.dev` | `20.255.113.149` |
| A | `*.preview.ytsummarizer.dev` | `20.255.113.149` |
| CNAME | `ytsummarizer.dev` | `red-grass-06d413100.6.azurestaticapps.net` |

## Troubleshooting

### Check Pod Status
```powershell
kubectl get pods -n yt-summarizer
kubectl describe pod <pod-name> -n yt-summarizer
kubectl logs <pod-name> -n yt-summarizer
```

### Check Ingress
```powershell
kubectl get ingress -n yt-summarizer
kubectl describe ingress -n yt-summarizer
```

### Check External Secrets
```powershell
kubectl get externalsecrets -n yt-summarizer
kubectl describe externalsecret <name> -n yt-summarizer
```

### Argo CD App Sync Issues
```powershell
# Get detailed app status
kubectl get application <app-name> -n argocd -o yaml

# Force refresh
kubectl patch application <app-name> -n argocd --type merge -p '{"metadata":{"annotations":{"argocd.argoproj.io/refresh":"hard"}}}'
```

## Related Documentation

- [Argo CD Setup](argocd-setup.md)
- [Deployment Rollback](deployment-rollback.md)
- [CI/CD Troubleshooting](ci-cd-troubleshooting.md)
- [Operations Guide](operations.md)
