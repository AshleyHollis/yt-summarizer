# Decision: Preview Environment PR-177 — Infrastructure Dependencies Verified

**Author:** Parker (DevOps)  
**Date:** 2026-03-05  
**Context:** Ashley requested a full audit of `preview-pr-177` namespace to confirm all secrets, worker deployments, and external connectivity are in place.

## Decision / Finding

The preview environment is **fully operational** — no missing infrastructure gaps found.

## Evidence

### Secrets (5/5 synced from Azure Key Vault via ExternalSecret)
| Secret | Keys Present |
|--------|-------------|
| `auth0-credentials` | `client-id`, `client-secret`, `domain`, `session-secret` |
| `db-credentials` | `connection-string` |
| `openai-credentials` | `api-key`, `azure-api-key`, `azure-deployment`, `azure-embedding-deployment`, `azure-endpoint` |
| `proxy-credentials` | `username`, `password` |
| `storage-credentials` | `connection-string` (covers blob + queue) |

All ExternalSecrets report `SecretSynced: True` against `ClusterSecretStore/azure-keyvault-cluster` (Valid, ReadWrite).

### Worker Deployments (all healthy)
| Worker | Status | Restarts | Queue Connectivity |
|--------|--------|----------|--------------------|
| transcribe-worker | Running 1/1 | 0 | HTTP 200 ✅ |
| summarize-worker | Running 1/1 | 0 | HTTP 200 ✅ |
| embed-worker | Running 1/1 | 0 | HTTP 200 ✅ |
| relationships-worker | Running 1/1 | 0 | HTTP 200 ✅ |

All workers are actively polling their respective Azure Storage queues against `stytsummprd.queue.core.windows.net`.

### ArgoCD
- App `preview-pr-177`: **Synced + Healthy** @ `b3e7c6e5`

## Notable Design Note
- `relationships-worker` only has `OPENAI_API_KEY` (standard OpenAI), not `AZURE_OPENAI_*` keys. This is intentional — it uses GPT for graph relationships rather than Azure OpenAI embeddings/completions. Consistent with summarize/embed workers which have full Azure OpenAI keys.
- Single storage connection string covers both blob and queue access (Azure Storage account-level key), so no separate blob vs. queue secrets are needed.

## Action Required
None — environment is ready for PR-177 testing.
