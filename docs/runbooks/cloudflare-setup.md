# Cloudflare DNS Setup Runbook

## Overview

This runbook covers the Cloudflare DNS configuration required for preview and production traffic on `*.yt-summarizer.apps.ashleyhollis.com`.

## Prerequisites

- Gateway external IP from `kubectl get gateway -n gateway-system`
- Access to the `ashleyhollis.com` Cloudflare zone
- Access to Azure Key Vault for secrets

## Step 1: Verify Cloudflare Nameservers

```bash
# Ensure the parent zone is managed by Cloudflare
# Expected output: two Cloudflare nameservers

dig NS ashleyhollis.com +short
```

## Step 2: Create Wildcard DNS Record

Create a wildcard A record in Cloudflare:

- **Type:** A
- **Name:** `*.yt-summarizer.apps`
- **Value:** `<GATEWAY_EXTERNAL_IP>`
- **Proxy status:** DNS only (gray cloud)
- **TTL:** Auto

Optional (recommended) base record:

- **Type:** A
- **Name:** `yt-summarizer.apps`
- **Value:** `<GATEWAY_EXTERNAL_IP>`
- **Proxy status:** DNS only

## Step 3: Create Cloudflare API Token

Create a token with minimal permissions:

- Zone / Zone / Read
- Zone / DNS / Edit
- Zone Resources: `ashleyhollis.com`

Store the token securely for the next step.

## Step 4: Store Token in Azure Key Vault

```bash
az keyvault secret set \
  --vault-name <keyvault-name> \
  --name cloudflare-api-token \
  --value "<token>"
```

## Step 5: Verify Kubernetes Secret Sync

```bash
kubectl get externalsecret cloudflare-api-token -n gateway-system
kubectl get secret cloudflare-api-token -n gateway-system
kubectl get secret cloudflare-api-token -n cert-manager
```

## Step 6: Validate DNS Resolution

```bash
# Production hostname

dig api.yt-summarizer.apps.ashleyhollis.com +short

# Preview hostname

dig api-pr-42.yt-summarizer.apps.ashleyhollis.com +short
```

**Pass Criteria**: Both records resolve to the Gateway external IP within 5 minutes.

## Troubleshooting

### DNS record resolves to old IP

- Confirm the Gateway external IP in `gateway-system`
- Update the Cloudflare record to the new IP
- Wait 1-5 minutes for propagation

### ExternalDNS cannot create records

- Verify the token is synced and valid
- Confirm ExternalDNS deployment logs in `gateway-system`
- Ensure the `apps.ashleyhollis.com` domain filter is configured

## Change Log

- **2026-01-17:** Initial Cloudflare setup runbook
