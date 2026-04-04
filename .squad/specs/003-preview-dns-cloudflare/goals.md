# Goals: Preview DNS / Cloudflare / cert-manager

> **Feature ID**: F003 | **Status**: Complete | **Milestone**: M2 | **Spec Phase**: complete  
> **Branch**: `003-preview-dns-cloudflare` | **Completed**: 2026-01-12

---

## Problem Statement

The preview platform was using third-party wildcard DNS services (nip.io/sslip.io) together with individually-issued TLS certificates for each preview environment. This caused Let's Encrypt rate limit failures because shared third-party domains caused quota collisions with other users, and issuing a fresh certificate per pull request consumed the weekly limit quickly. Developers experienced certificate warnings and unpredictable preview URLs.

---

## Success Criteria

- Pull request preview environments are accessible via browser-trusted HTTPS within 5 minutes of the PR being opened (SC-001)
- No certificate warnings or errors appear when accessing any preview URL in any modern browser (SC-002)
- Zero certificate authority rate limit errors occur during normal operation, regardless of simultaneous preview count (SC-003)
- Exactly one certificate exists per application at all times, regardless of active pull request preview count (SC-004)
- DNS records for closed pull requests are removed within 10 minutes of PR closure (SC-005)
- Preview cleanup leaves no orphaned resources — no dangling namespaces, DNS records, or credentials (SC-006)
- Zero references to nip.io, sslip.io, or xip.io remain in code, workflows, or configuration (SC-007)
- Authenticated SWA preview users can call protected API preview endpoints with credentials intact (SC-008)
- Runbooks exist and are verified for all foreseeable failure modes (SC-009)

---

## In Scope

- Dedicated hostname scheme under `apps.ashleyhollis.com` for all environments (production, staging, PR previews)
- Automated DNS record management via ExternalDNS + Cloudflare (create on deploy, delete on cleanup)
- Single wildcard certificate per application (`*.yt-summarizer.apps.ashleyhollis.com`) via cert-manager DNS-01
- NGINX Gateway Fabric (Gateway API) replacing the existing NGINX Ingress Controller
- GitHub Actions updates for the new hostname scheme
- Auth0 BFF endpoints for authentication with SWA preview cross-origin support
- Operator runbooks for certificate, DNS, and Gateway troubleshooting
- Cleanup of all nip.io/sslip.io references

---

## Out of Scope

- Global identity provider logout (local session logout only)
- Multi-app support beyond `yt-summarizer`
- Custom domains for SWA preview environments (use `azurestaticapps.net`)
- IPv6 address record support
- Mutual TLS or client certificate authentication
- Rate limiting or WAF rules at the routing layer

---

## Constraints

- Single AKS cluster (cost-optimized, single-node)
- Cloudflare Free tier only
- Let's Encrypt rate limits must be respected (hence wildcard cert strategy)
- GitOps: all manifests in `k8s/`, synced by Argo CD — no imperative kubectl in CI
- No secrets committed to repo; credentials via Azure Key Vault + ExternalSecret

---

## Users

- **Developers** opening pull requests who need immediate, trusted HTTPS preview environments
- **Platform/DevOps team** (Parker) managing certificate lifecycle, DNS, and infrastructure observability
- **Authenticated end users** (Auth0 via SWA frontend) accessing preview API endpoints

---

## Testing Expectations

- Infrastructure validation via `kubectl` + `curl` (live cluster checks)
- E2E validation: create a real PR, verify HTTPS preview URL, close PR, verify cleanup
- No automated test suite required for Kubernetes manifests
- Runbooks validated against actual failure scenarios in the live cluster
