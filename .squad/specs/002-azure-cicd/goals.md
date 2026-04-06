# Goals: Azure CI/CD Pipelines

**Status**: Implementing
**Milestone**: M2
**Spec Phase**: execution
**Created**: 2026-01-08
**Updated**: 2026-01-09

## Problem Statement

Developers on the YT Summarizer project have no automated feedback loop when they open a pull request, no consistent way to validate changes in a real deployed environment before merging, and no automated path to get validated changes into production. Every deployment requires manual steps, increasing the risk of regressions reaching users and the time between a validated change and its availability in production.

## Success Criteria

- **SC-001**: Pull request test feedback is available within 15 minutes of PR creation or update
- **SC-002**: PR preview environments are fully deployed and accessible within 10 minutes of CI passing
- **SC-003**: Production deployments complete within 10 minutes of merge to main
- **SC-004**: 100% of merges to main automatically trigger a production deployment — no manual steps required
- **SC-005**: Zero secrets are exposed in pipeline logs, PR comments, or build artifacts at any time
- **SC-006**: The team receives a deployment success or failure notification within 2 minutes of completion
- **SC-007**: Any developer can identify which source commit is running in any environment within 30 seconds
- **SC-008**: Failed production deployments are automatically reverted to the previous healthy version within 5 minutes of failure detection
- **SC-009**: Preview environments are fully cleaned up within 5 minutes of a PR being closed or merged
- **SC-010**: All pipeline configuration is version-controlled and reviewed through the PR process

## In Scope

- Automated CI on every pull request: unit tests (shared, API, workers, frontend), linting, type checking, frontend build validation
- PR preview environments: ephemeral, isolated, HTTPS-accessible deployments created per PR after CI passes
- Automatic production deployment on merge to main using the same artifacts validated in the preview
- GitOps-based deployment via Argo CD watching Kubernetes manifests
- Infrastructure pipeline: Terraform plan/apply for infrastructure changes
- Preview TLS via shared wildcard certificate (no per-PR certificate provisioning)
- Frontend previews via Azure Static Web Apps staging slots
- Automatic preview cleanup when a PR is closed or merged
- Secret management via GitHub Secrets and Azure Key Vault (no secrets in repository)

## Out of Scope

- Long-lived staging environment (deferred; PR previews are the sole pre-production validation surface)
- Manual production approval gates
- Separate build/deploy step on merge (production deploys the same artifacts validated in preview — no rebuild)
- Local developer environment changes (Aspire + Docker continues to be used locally, unaffected)
- Per-PR TLS certificate provisioning (wildcard certificate covers all previews)
- Database seeding or test data management for preview environments
- End-to-end tests inside the CI workflow (E2E runs against deployed preview environments)

## Constraints

- Single-node AKS cluster — max 3 concurrent preview environments to protect production stability
- Production namespace protected with PodPriority
- All secrets must use GitHub Secrets or Azure Key Vault; never committed to repository
- Authentication to Azure from GitHub Actions must use OIDC federation — no static credentials
- All infrastructure changes must be applied via Terraform; no manual Azure portal changes
- Preview overlay manifests live in PR branches, not in main

## Users

- **Developers**: Create pull requests and need fast automated feedback on test results
- **Reviewers**: Need a live preview of PR changes to validate functionality before approving
- **Team lead**: Needs production deployments to happen automatically after merge without manual steps
- **DevOps engineer**: Needs infrastructure changes to flow through the same auditable pipeline as application code

## Testing Expectations

- Unit tests (pytest for Python, Vitest for TypeScript) run in the CI workflow on every PR
- Linting (ruff, eslint) and type checking run in the CI workflow on every PR
- Frontend build validation (`npm run build`) runs in CI to catch TypeScript errors
- E2E tests (Playwright) run against PR preview environments after deployment — not inside the CI workflow
- Validation tests for the pipeline itself (intentional failures, preview lifecycle, rollback) run post-merge
