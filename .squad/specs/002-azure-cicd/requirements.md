# Requirements: Azure CI/CD Pipelines

**Status**: Implementing
**Milestone**: M2
**Spec Phase**: execution
**Created**: 2026-01-08
**Updated**: 2026-01-09

---

## User Stories

### US1 — Automated Testing on Pull Request (Priority: P1)

> As a developer, I want all tests to run automatically when I create or update a pull request, so that I can catch bugs before merging to the main branch.

**Acceptance Criteria**:
- **AC-1.1**: Given a developer opens a pull request, when the PR is created or updated, then all test suites (shared library, workers, API, and frontend) run automatically without manual intervention
- **AC-1.2**: Given any test fails during the PR check, when the developer views the PR, then they see a clear failure status with a direct link to the detailed failure logs
- **AC-1.3**: Given all tests pass, when the developer views the PR, then they see a green success status confirming the PR is safe to review and merge
- **AC-1.4**: Given code quality issues exist (lint errors, type errors), when the checks run, then the PR is blocked with a clear message identifying the specific issue

---

### US2 — PR Preview Environment (Priority: P1)

> As a developer or reviewer, I want a live preview of every pull request deployed automatically so I can validate changes in a real environment before they reach production.

**Acceptance Criteria**:
- **AC-2.1**: Given a developer opens or updates a pull request and CI tests pass, when the preview pipeline runs, then a fully isolated preview environment is deployed and accessible at a unique HTTPS URL scoped to that PR number
- **AC-2.2**: Given a preview deployment is in progress, when the developer views the PR, then they see live status updates (deploying → ready / failed) and the preview URL appears as a PR comment once ready
- **AC-2.3**: Given a preview environment is ready, when a reviewer visits the preview URL, then they can interact with the complete application — frontend, API, and background workers — running the exact code from the PR branch
- **AC-2.4**: Given multiple PRs are open simultaneously, when previews are deployed, then each PR has its own isolated environment with no cross-PR interference; at most 3 concurrent preview environments exist at any time
- **AC-2.5**: Given a pull request is closed or merged, when the PR lifecycle ends, then the preview environment and all associated resources are automatically torn down within 5 minutes

---

### US3 — Automatic Production Deployment on Merge (Priority: P1)

> As a team lead, I want every merge to the main branch to automatically deploy to production, so that validated changes reach users quickly without any manual deployment steps.

**Acceptance Criteria**:
- **AC-3.1**: Given a PR is merged to main, when the merge completes and CI passes on main, then the production deployment starts automatically using the artifact versions validated in the preview — no rebuild, no manual trigger
- **AC-3.2**: Given a production deployment succeeds, when a developer or user accesses the production URL, then the application is functional and running the merged changes
- **AC-3.3**: Given a production deployment fails health checks, when the failure is detected, then the system automatically reverts to the previous healthy version within 5 minutes
- **AC-3.4**: Given a developer discovers a bad deployment in production, when they revert the merge commit, then production automatically redeploys the previous version

---

### US4 — Infrastructure Pipeline (Priority: P3)

> As a DevOps engineer, I want infrastructure definition changes to be validated and applied through the same pipeline as application code, so that infrastructure and application stay in sync and changes are auditable.

**Acceptance Criteria**:
- **AC-4.1**: Given infrastructure definition code changes in the repository, when a PR is opened, then the pipeline runs a validation (plan/dry-run) and reports any errors on the PR
- **AC-4.2**: Given an infrastructure change PR is merged to main, when the deployment pipeline runs, then infrastructure changes are applied before the application deployment
- **AC-4.3**: Given an infrastructure change fails to apply, when the pipeline runs, then the application deployment step is blocked and the failure is clearly reported

---

## Functional Requirements

### Continuous Integration (CI)

| ID | Requirement | Priority | User Story |
|----|-------------|----------|------------|
| FR-001 | The pipeline MUST run all test suites (shared library, API, workers, frontend) on every pull request automatically | P1 | US1 |
| FR-002 | The pipeline MUST block PR merge when any test or code quality check fails | P1 | US1 |
| FR-003 | The pipeline MUST display a test results summary directly on the pull request, with links to detailed logs on failure | P1 | US1 |
| FR-004 | The pipeline MUST cache build dependencies to keep total CI feedback time within the 15-minute target | P1 | US1 |
| FR-005 | The pipeline MUST run code quality checks (linting, type checking, build validation) as part of the CI process | P1 | US1 |

### Continuous Deployment — PR Preview

| ID | Requirement | Priority | User Story |
|----|-------------|----------|------------|
| FR-006 | The pipeline MUST automatically deploy a preview environment for each pull request once CI passes | P1 | US2 |
| FR-007 | The pipeline MUST build versioned, immutable application artifacts for the API service and all worker services from the PR branch | P1 | US2 |
| FR-008 | The pipeline MUST deploy each preview into a fully isolated environment scoped to its PR number, with no shared state between previews | P1 | US2 |
| FR-009 | The pipeline MUST post the preview URL and deployment status (deploying / ready / failed) as a PR comment, updating it as status changes | P1 | US2 |
| FR-010 | The pipeline MUST enforce a maximum of 3 concurrent preview environments to protect production workload stability | P1 | US2 |
| FR-011 | The pipeline MUST automatically remove all preview environment resources when a PR is closed or merged | P1 | US2 |
| FR-012 | The pipeline MUST verify preview service health after deployment before reporting the environment as ready | P1 | US2 |

### Continuous Deployment — Production

| ID | Requirement | Priority | User Story |
|----|-------------|----------|------------|
| FR-013 | The pipeline MUST automatically deploy to production on every merge to the main branch without manual intervention | P1 | US3 |
| FR-014 | The pipeline MUST deploy the exact artifact versions validated in the PR preview to production — no re-build from source on merge | P1 | US3 |
| FR-015 | The pipeline MUST record the exact artifact version identifiers in version control to trigger and track each production deployment | P1 | US3 |
| FR-016 | The pipeline MUST support rollback to any previous production version by reverting the corresponding change in version control | P1 | US3 |
| FR-017 | The pipeline MUST verify production service health after deployment and trigger automatic rollback if health checks do not pass | P1 | US3 |

### Security & Secrets

| ID | Requirement | Priority | User Story |
|----|-------------|----------|------------|
| FR-018 | All secrets MUST be stored in a secrets management system — never in repository files or pipeline logs | P1 | All |
| FR-019 | The pipeline MUST never expose secret values in log output, build artifacts, or PR comments | P1 | All |
| FR-020 | The pipeline MUST authenticate to cloud services using short-lived federated credentials — no static service account keys | P1 | All |

### Observability & Traceability

| ID | Requirement | Priority | User Story |
|----|-------------|----------|------------|
| FR-021 | The pipeline MUST notify the team of deployment success or failure via the standard PR/commit status interface | P1 | US2, US3 |
| FR-022 | The pipeline MUST provide direct links to deployment logs and sync status from the PR or commit view | P1 | US2, US3 |
| FR-023 | Every deployed artifact MUST be tagged with the source commit identifier, making it possible to trace any running version back to its source commit within 30 seconds | P1 | US3 |

### Infrastructure as Code

| ID | Requirement | Priority | User Story |
|----|-------------|----------|------------|
| FR-024 | Infrastructure definition changes MUST be validated by the pipeline before merging | P3 | US4 |
| FR-025 | Infrastructure changes merged to main MUST be applied automatically before the application deployment | P3 | US4 |

---

## Non-Functional Requirements

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-001 | CI feedback (test results available) | ≤15 minutes from PR creation/update |
| NFR-002 | Preview environment fully ready | ≤10 minutes from CI passing |
| NFR-003 | Production deployment complete | ≤10 minutes from merge to main |
| NFR-004 | Preview cleanup after PR close | ≤5 minutes |
| NFR-005 | Max concurrent preview environments | 3 |
| NFR-006 | Production rollback time | ≤5 minutes of failure detection |
| NFR-007 | Cost ceiling (infra + preview + prod) | ~$35/month fixed |

---

## Glossary

| Term | Definition |
|------|------------|
| Pipeline | Automated workflow orchestrating build, test, and deploy steps triggered by repository events |
| Preview Environment | Ephemeral, isolated deployment created per pull request; torn down automatically when the PR closes |
| Production Environment | Persistent live deployment serving end users; updated automatically on merge to main |
| Versioned Artifact | Immutable, built application component uniquely identified by a content-based version tag |
| Secret | Sensitive configuration value stored outside the repository and injected securely at runtime |
| Deployment Record | Version-controlled record of which artifact versions are deployed to each environment |
| GitOps | Practice of using Git as the single source of truth for declarative infrastructure and application state |
| Overlay | Kustomize patch set that modifies base Kubernetes manifests for a specific environment |

---

## Out of Scope

- Long-lived staging environment
- Manual production approval gates
- Per-PR TLS certificate provisioning
- Database seeding or test data management for preview environments
- Local developer environment changes (Aspire + Docker continues unaffected)
- End-to-end tests inside the CI workflow (run against preview environments post-deployment)

---

## Dependencies

- AKS single-node cluster provisioned via Terraform
- Azure Container Registry (ACR) for storing versioned image artifacts
- Azure Static Web Apps for Next.js frontend hosting and PR preview slots
- Azure Key Vault for runtime secret storage
- cert-manager + Cloudflare DNS-01 solver for wildcard TLS certificate
- Argo CD installed in the AKS cluster via bootstrap script
- GitHub Actions with OIDC federation to Azure AD
