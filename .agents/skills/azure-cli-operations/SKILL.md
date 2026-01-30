---
name: azure-cli-operations
description: Azure CLI operations for ACR, AKS, Storage, and Key Vault management in the YT Summarizer infrastructure
license: MIT
---

# Azure CLI Operations

## Purpose
Common Azure CLI operations for managing YT Summarizer infrastructure resources including container registries, Kubernetes clusters, storage accounts, and secrets.

## When to Use
- Checking container image tags in ACR
- Managing AKS cluster resources
- Querying storage accounts and connection strings
- Retrieving secrets from Key Vault
- Validating Azure resource status

## Do Not Use When
- Modifying production infrastructure (use Terraform)
- Making permanent configuration changes
- Operations that should be automated in CI/CD

## Common Operations

### Azure Container Registry (ACR)

**List image tags**
```bash
az acr repository show-tags \
  --name acrytsummprd \
  --repository yt-summarizer-api \
  --orderby time_desc \
  --top 10
```

**Show repository manifests**
```bash
az acr repository show-manifests \
  --name acrytsummprd \
  --repository yt-summarizer-api
```

**Check repository list**
```bash
az acr repository list --name acrytsummprd
```

### Azure Kubernetes Service (AKS)

**Get cluster credentials**
```bash
az aks get-credentials \
  --resource-group rg-yt-summarizer-prod \
  --name aks-yt-summarizer-prod
```

**List node pools**
```bash
az aks nodepool list \
  --resource-group rg-yt-summarizer-prod \
  --cluster-name aks-yt-summarizer-prod
```

**Show cluster details**
```bash
az aks show \
  --resource-group rg-yt-summarizer-prod \
  --name aks-yt-summarizer-prod
```

### Azure Storage

**Get connection string**
```bash
az storage account show-connection-string \
  --name stytsummprd \
  --resource-group rg-yt-summarizer-prod
```

**List storage accounts**
```bash
az storage account list \
  --resource-group rg-yt-summarizer-prod
```

**Check blob containers**
```bash
az storage container list \
  --account-name stytsummprd \
  --connection-string "<connection-string>"
```

### Azure Key Vault

**Get secret value**
```bash
az keyvault secret show \
  --name OpenAI-ApiKey \
  --vault-name kv-yt-summarizer \
  --query value \
  --output tsv
```

**List secrets (names only)**
```bash
az keyvault secret list \
  --vault-name kv-yt-summarizer \
  --query "[].name"
```

**Check secret expiration**
```bash
az keyvault secret show \
  --name <secret-name> \
  --vault-name kv-yt-summarizer \
  --query "{name:name, expires:attributes.expires}"
```

### Resource Groups

**List resources in group**
```bash
az resource list \
  --resource-group rg-yt-summarizer-prod \
  --output table
```

**Show resource group info**
```bash
az group show \
  --name rg-yt-summarizer-prod
```

## Validation Patterns

**Check if image exists before deployment**
```bash
if az acr repository show-tags \
  --name acrytsummprd \
  --repository yt-summarizer-api \
  --query "contains(@, 'pr-110')" \
  --output tsv; then
  echo "Image exists"
else
  echo "Image not found"
fi
```

**Verify AKS cluster health**
```bash
az aks get-credentials \
  --resource-group rg-yt-summarizer-prod \
  --name aks-yt-summarizer-prod

kubectl get nodes
kubectl get pods --all-namespaces
```

## Best Practices

1. **Always specify resource group** explicitly to avoid accidents
2. **Use `--output tsv`** for scripting and piping
3. **Use `--query`** to filter results and reduce output
4. **Validate before acting** - check if resources exist first
5. **Never commit secrets** - use Key Vault references instead
