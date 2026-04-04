# Design: Azure CI/CD Pipelines

**Status**: Implementing
**Milestone**: M2
**Spec Phase**: execution
**Created**: 2026-01-08
**Updated**: 2026-01-09

---

## Architecture Overview

The CI/CD system uses a GitOps architecture built on GitHub Actions, Argo CD, Kustomize, and Azure-native services. The key principle is that every merge to main deploys the same artifacts that were validated in the PR preview — no rebuild on merge.

```
┌──────────────────────────────────────────────────────────────────────────┐
│  PR PREVIEW FLOW                                                          │
├──────────────────────────────────────────────────────────────────────────┤
│  Developer opens PR                                                       │
│         │                                                                 │
│         ▼                                                                 │
│  ci.yml — Run all tests, lint, type-check, build frontend                 │
│         │                                                                 │
│         ▼ (on CI pass)                                                    │
│  preview.yml — Build API + Workers images → Push to ACR                  │
│             — Create k8s/overlays/preview/ in PR branch                  │
│             — Commit & push to PR branch                                  │
│             — Build & deploy frontend to SWA staging environment          │
│             — Post preview URL as PR comment                              │
│         │                                                                 │
│         ▼                                                                 │
│  Argo CD ApplicationSet (Pull Request Generator)                          │
│         — Detects open PR via GitHub API                                  │
│         — Creates Application: yt-summarizer-pr-<num>                     │
│         — Points to PR branch, k8s/overlays/preview/                     │
│                                                                           │
│  Preview URLs:                                                            │
│  ├── Backend: api-pr-<num>.yt-summarizer.apps.ashleyhollis.com           │
│  └── Frontend: SWA staging URL (posted as PR comment)                    │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│  PRODUCTION FLOW                                                          │
├──────────────────────────────────────────────────────────────────────────┤
│  PR merged to main                                                        │
│         │                                                                 │
│         ▼                                                                 │
│  ci.yml runs on main (same test suite)                                    │
│         │                                                                 │
│         ▼ (workflow_run trigger after CI passes)                          │
│  deploy-prod.yml — Update k8s/overlays/prod/kustomization.yaml           │
│                  — with same image digests from PR preview               │
│                  — Commit & push to main                                  │
│                  — Deploy SWA production slot                             │
│         │                                                                 │
│         ▼                                                                 │
│  Argo CD auto-syncs prod Application from updated manifests               │
│         — Health checks pass → production live                            │
│         — Health checks fail → auto-rollback                              │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Technical Decisions

| Decision | Options Considered | Choice | Rationale |
|----------|--------------------|--------|-----------|
| Kubernetes deployment target | ACA, k3s, AKS multi-node | AKS single-node | ~$30/month fixed, supports GitOps, rollback built in |
| GitOps controller | Flux, Argo CD | Argo CD | Web UI, Pull Request Generator, one-click rollback |
| Manifest templating | Helm, Kustomize, raw YAML | Kustomize | Built into kubectl, no templating language, simple overlay pattern |
| Preview overlays location | main branch, PR branch | PR branch | Keeps main clean; Argo CD Pull Request Generator reads from PR head |
| Frontend hosting | AKS Ingress, Vercel, Azure SWA | Azure SWA | Built-in PR staging slots, HTTPS free, no cert management |
| TLS for preview backends | Per-PR Let's Encrypt (HTTP-01), nip.io, wildcard cert | Wildcard cert (DNS-01) | Single cert covers all PRs; DNS-01 supports wildcards |
| Production environment model | staging + production, single prod | Single `prod` overlay | No long-lived staging; PR previews are pre-production validation |
| Production trigger | Manual, polling, `workflow_run` | `workflow_run` after CI | Auto-deploys only after all checks pass; no polling |
| Secret storage | Repository files, GitHub Secrets, Key Vault | GitHub Secrets + Key Vault | Runtime secrets in Key Vault synced via External Secrets Operator |
| Azure authentication | Static keys, managed identity, OIDC | OIDC federation | No secrets to rotate; short-lived tokens |

---

## Component Responsibilities

### `.github/workflows/ci.yml`
Runs on every pull request and push to main. Executes: shared library tests, API tests, worker tests, frontend Vitest tests, ruff linting, eslint linting, `npm run build` (TypeScript compile check), Terraform validation, Kustomize validation, gitleaks secret scan.

### `.github/workflows/preview.yml`
Runs on pull request after CI passes. Builds API and worker Docker images with PR-SHA tags, pushes to ACR, generates `k8s/overlays/previews/pr-<number>/` from the template, commits the overlay to the PR branch, deploys frontend to SWA staging slot, posts preview URL as PR comment.

### `.github/workflows/preview-cleanup.yml`
Runs when a pull request is closed or merged. Deletes `k8s/overlays/previews/pr-<number>/` from the PR branch, commits and pushes the deletion. Argo CD detects the deleted Application source and prunes the preview environment.

### `.github/workflows/deploy-prod.yml`
Triggered by `workflow_run` after `ci.yml` completes successfully on `main`. Updates `k8s/overlays/prod/kustomization.yaml` with the image digests from the merged PR, commits and pushes to main, deploys the SWA production slot, runs health checks.

### `.github/workflows/infra.yml`
Runs Terraform plan on PRs (posts result as comment), runs Terraform apply on merge to main.

### `k8s/base/`
Shared Kubernetes manifests: namespace, API deployment, API service, API ingress, worker deployments, configmap, external secrets, priority class.

### `k8s/overlays/prod/`
Production environment overlay: patches for production-scale replicas, resource limits, ingress hostname, image digests pinned per deployment.

### `k8s/overlays/previews/_template/`
Template for PR preview overlays: namespace, resource quota, limit range, kustomization, ingress patch with PR-scoped hostname.

### `k8s/argocd/`
Argo CD application definitions: `prod-app.yaml` (production Application), `preview-appset.yaml` (ApplicationSet with Pull Request Generator), `infra-apps.yaml` (cluster infrastructure: ingress-nginx, cert-manager, external-secrets).

### `infra/terraform/`
Azure infrastructure as code. Modules: ACR, AKS (single-node), Azure SWA, Azure Storage (blob + queue), Azure SQL Database, Azure Key Vault. Single environment in `environments/prod/`. Helm/Kubernetes providers removed (Argo CD manages cluster resources).

---

## Repository Structure

```
.github/
├── actions/
│   ├── setup-python/action.yml       # Reusable Python setup (uv + cache)
│   ├── setup-node/action.yml         # Reusable Node.js setup (npm cache)
│   ├── compute-preview-urls/         # Computes preview hostname from PR number
│   └── verify-certificate/           # Verifies shared wildcard TLS secret
└── workflows/
    ├── ci.yml                         # PR: tests, lint, build, validation
    ├── preview.yml                    # PR: build images, deploy preview
    ├── preview-cleanup.yml            # PR close: tear down preview
    ├── deploy-prod.yml                # main merge: promote to production
    └── infra.yml                      # Terraform plan/apply

k8s/
├── base/                              # Shared manifests
│   ├── kustomization.yaml
│   ├── namespace.yaml
│   ├── api-deployment.yaml
│   ├── api-service.yaml
│   ├── api-ingress.yaml
│   ├── *-worker-deployment.yaml       # transcribe, summarize, embed, relationships
│   ├── configmap.yaml
│   ├── externalsecret-*.yaml
│   ├── priority-class.yaml
│   └── secretstore.yaml
├── overlays/
│   ├── prod/
│   │   ├── kustomization.yaml         # Image digest pins (updated by deploy-prod.yml)
│   │   └── patches/
│   └── previews/
│       └── _template/                 # PR overlay template
└── argocd/
    ├── prod-app.yaml
    ├── preview-appset.yaml
    ├── infra-apps.yaml
    └── cert-manager/
        └── clusterissuer-cloudflare.yaml

infra/terraform/
├── providers.tf
├── backend.tf
├── variables.tf
├── modules/
│   ├── container-registry/
│   ├── aks/
│   ├── static-web-app/
│   ├── storage/
│   ├── sql-database/
│   └── key-vault/
└── environments/
    └── prod/
        ├── main.tf
        └── providers.tf

scripts/
├── bootstrap-argocd.ps1               # Cluster bootstrap (one-time)
├── deploy-infra.ps1                   # Infrastructure deployment
└── run-tests.ps1                      # Local test runner
```

---

## Preview TLS Architecture

```
*.yt-summarizer.apps.ashleyhollis.com  (wildcard DNS → AKS Ingress IP)
                 │
                 ▼
    cert-manager (DNS-01 via Cloudflare)
                 │
                 ▼
    Shared wildcard TLS secret in cluster
                 │
                 ├── api-pr-141.yt-summarizer.apps.ashleyhollis.com → preview ns
                 ├── api-pr-142.yt-summarizer.apps.ashleyhollis.com → preview ns
                 └── api.yt-summarizer.apps.ashleyhollis.com → prod ns
```

No per-PR certificate is provisioned. All preview backends share the wildcard certificate. Frontend previews are served via Azure SWA staging slots (HTTPS provided natively by SWA).

---

## Error Handling

| Failure | Detection | Response |
|---------|-----------|----------|
| CI test failure | GitHub Actions status check | PR merge blocked; failure details linked in PR |
| Preview build failure | `preview.yml` step failure | PR comment updated to "failed"; preview not accessible |
| Preview health check failure | Post-deploy smoke test | PR comment updated with error; Argo CD app marked degraded |
| Production deployment failure | Health check step in `deploy-prod.yml` | Argo CD auto-sync with rollback to previous healthy revision |
| Terraform apply failure | `infra.yml` failure | Application deployment blocked; failure reported on commit |
| Secret exposure | gitleaks scan in `ci.yml` | PR blocked; scan failure reported |

---

## Security Considerations

- No static credentials in the repository; all Azure authentication via OIDC federated tokens
- GitHub Secrets store: subscription IDs, tenant IDs, client IDs (non-sensitive references only)
- Azure Key Vault stores runtime secrets (connection strings, API keys); External Secrets Operator syncs them into Kubernetes
- Secrets never written to logs (`::add-mask::` used for any sensitive outputs)
- Preview namespaces have ResourceQuota and LimitRange to prevent noisy-neighbour issues
- Production pods use PriorityClass `production-critical` to protect against preview workloads consuming resources
- gitleaks scans every PR for accidentally committed secrets
