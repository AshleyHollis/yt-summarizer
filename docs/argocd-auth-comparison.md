# ArgoCD GitHub Authentication Comparison

## Overview

ArgoCD ApplicationSet PR generator needs GitHub API access to discover open pull requests. This document compares authentication methods.

## Comparison Table

| Feature | GitHub PAT (Manual) | GitHub PAT + External Secrets | **GitHub App (Recommended)** |
|---------|-------------------|------------------------------|---------------------------|
| **Expiration** | ⚠️ Max 1 year | ⚠️ Max 1 year | ✅ Never (only key) |
| **Rate Limit** | ❌ 60 req/hour | ❌ 60 req/hour | ✅ 5,000 req/hour |
| **Auto-Rotation** | ❌ Manual | ⚠️ Semi-auto* | ✅ Not needed |
| **Team Changes** | ❌ Breaks if owner leaves | ❌ Breaks if owner leaves | ✅ Org-level |
| **Permissions** | ⚠️ User-level (all repos) | ⚠️ User-level (all repos) | ✅ Scoped to repo |
| **Audit Trail** | ❌ Limited | ❌ Limited | ✅ Full GitHub audit |
| **Setup Complexity** | ✅ Simple | ⚠️ Medium | ⚠️ Medium |
| **Maintenance** | ❌ High (manual rotation) | ⚠️ Medium (still expires) | ✅ Zero |

\* External Secrets syncs from Key Vault, but you still need to manually rotate the PAT in Key Vault before expiration

## Detailed Analysis

### 1. GitHub PAT (Manual) ❌ **NOT RECOMMENDED**

**Current implementation** - what we have now.

#### How it works:
```powershell
kubectl create secret generic github-token -n argocd --from-literal=token=<YOUR_PAT>
```

#### Problems:
- **Expiration**: PAT expires in 1 year max
- **No warning**: ArgoCD silently fails when token expires
- **Manual rotation**: Someone needs to remember to rotate
- **User-dependent**: If token owner leaves team, token becomes invalid
- **Security**: Stored as plain secret in etcd

#### When preview breaks:
- ❌ No preview apps created
- ❌ Health checks fail with "preview-pr-X namespace not found"
- ❌ Requires emergency rotation

---

### 2. GitHub PAT + External Secrets ⚠️ **BETTER BUT STILL SUBOPTIMAL**

Stores PAT in Azure Key Vault, auto-syncs to Kubernetes.

#### How it works:
```yaml
# k8s/argocd/github-token-externalsecret.yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
spec:
  refreshInterval: 1h
  data:
    - secretKey: token
      remoteRef:
        key: github-argocd-token  # From Key Vault
```

#### Improvements over manual:
- ✅ Centralized in Azure Key Vault
- ✅ Auto-syncs to cluster every hour
- ✅ Can set Key Vault alerts for upcoming expiration
- ✅ Easier rotation (update Key Vault only)

#### Remaining problems:
- ❌ **PAT still expires** (1 year max)
- ❌ Still requires manual rotation of PAT in Key Vault
- ❌ Still user-dependent (tied to GitHub account)
- ❌ Low rate limit (60 req/hour)

#### Rotation process:
1. Set calendar reminder 2 weeks before expiration
2. Generate new PAT in GitHub
3. Update Key Vault secret
4. External Secrets syncs within 1 hour
5. ArgoCD picks up new token

---

### 3. GitHub App ✅ **RECOMMENDED**

Official GitHub/ArgoCD recommended approach.

#### How it works:
```powershell
# One-time setup
./scripts/setup-argocd-github-app.ps1

# ApplicationSet uses app
spec:
  generators:
    - pullRequest:
        github:
          appSecretName: github-app  # Uses App ID + private key
```

#### Benefits:
- ✅ **No expiration**: Private key doesn't expire
- ✅ **High rate limits**: 5,000 req/hour (83x more than PAT)
- ✅ **Organization-level**: Survives team member changes
- ✅ **Scoped permissions**: Only read PRs from specific repo
- ✅ **Audit trail**: Full GitHub audit log of API calls
- ✅ **Zero maintenance**: Set it and forget it

#### Setup complexity:
1. Create GitHub App (5 minutes)
2. Generate private key (1 click)
3. Install app on repository (1 click)
4. Create Kubernetes secret (1 command)
5. Update ApplicationSet config (1 line change)

**Total time: ~10 minutes**

#### Long-term maintenance:
- **Zero** - it just works

---

## Migration Path

### From: GitHub PAT (current)
### To: GitHub App (recommended)

**Step 1: Create GitHub App** (10 minutes)
```powershell
cd C:\Users\ashle\Source\GitHub\AshleyHollis\yt-summarizer
.\scripts\setup-argocd-github-app.ps1
```

**Step 2: Update ApplicationSet** (2 minutes)
```yaml
# k8s/argocd/preview-appset.yaml
generators:
  - pullRequest:
      github:
        owner: AshleyHollis
        repo: yt-summarizer
        # Before:
        # tokenRef:
        #   secretName: github-token
        #   key: token
        # After:
        appSecretName: github-app  # ✅ Use GitHub App
```

**Step 3: Apply and verify** (1 minute)
```powershell
kubectl apply -f k8s/argocd/preview-appset.yaml

# Verify ApplicationSet picks up the change
kubectl logs -n argocd -l app.kubernetes.io/name=argocd-applicationset-controller --tail=20

# Should see: "generated X applications" with appSecretName in the log
```

**Step 4: Cleanup old secret** (optional)
```powershell
kubectl delete secret github-token -n argocd
```

---

## Recommendation

**Use GitHub App** for the following reasons:

1. **Zero maintenance** - No expiration, no rotation, no calendar reminders
2. **Better rate limits** - 5000 req/hour vs 60 (handles 83x more PRs)
3. **Team-proof** - Doesn't break when people leave
4. **Security** - Scoped to specific repo, full audit trail
5. **Official** - Recommended by both GitHub and ArgoCD

**Migration effort**: ~15 minutes  
**Maintenance savings**: ~30 minutes/year (no rotation) + eliminated outage risk

## References

- [ArgoCD ApplicationSet GitHub App docs](https://argo-cd.readthedocs.io/en/stable/operator-manual/applicationset/Generators-Pull-Request/#github)
- [GitHub Apps documentation](https://docs.github.com/en/apps/creating-github-apps)
- [GitHub API rate limits](https://docs.github.com/en/rest/overview/resources-in-the-rest-api#rate-limiting)
