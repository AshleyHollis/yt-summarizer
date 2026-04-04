# Feature Specification: GitHub CI/CD with PR Preview Environments

**Feature Branch**: `002-azure-cicd`  
**Created**: 2026-01-08  
**Updated**: 2026-01-09  
**Status**: ~70% Implemented — PR previews and automated testing are working; production deployment automation needs refinement

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Automated Testing on Pull Request (Priority: P1)

As a developer, I want all tests to run automatically when I create or update a pull request, so that I can catch bugs before merging to the main branch.

**Why this priority**: This is the foundation of safe deployment. Without automated testing on every change, regressions reach production undetected and deployment confidence erodes.

**Independent Test**: Create a PR with an intentional test failure; verify the pipeline blocks the merge. Fix the test and verify the pipeline passes and merge is unblocked.

**Acceptance Scenarios**:

1. **Given** a developer opens a pull request, **When** the PR is created or updated, **Then** all test suites (shared library, workers, API, and frontend) run automatically without manual intervention
2. **Given** any test fails during the PR check, **When** the developer views the PR, **Then** they see a clear failure status with a direct link to the detailed failure logs
3. **Given** all tests pass, **When** the developer views the PR, **Then** they see a green success status confirming the PR is safe to review and merge
4. **Given** code quality issues exist (lint errors, type errors), **When** the checks run, **Then** the PR is blocked with a clear message identifying the specific issue

---

### User Story 2 - PR Preview Environment (Priority: P1)

As a developer or reviewer, I want a live preview of every pull request deployed automatically so I can validate changes in a real environment before they reach production.

**Why this priority**: PR previews are the primary validation surface for this project — there is no long-lived staging environment. Every functional change must be verifiable in a real deployed environment before merge.

**Independent Test**: Open a PR; verify a unique HTTPS preview URL is posted to the PR, the application is reachable and functional at that URL, and the preview is torn down automatically when the PR is closed.

**Acceptance Scenarios**:

1. **Given** a developer opens or updates a pull request and CI tests pass, **When** the preview pipeline runs, **Then** a fully isolated preview environment is deployed and accessible at a unique HTTPS URL scoped to that PR number
2. **Given** a preview deployment is in progress, **When** the developer views the PR, **Then** they see live status updates (deploying → ready / failed) and the preview URL appears as a PR comment once the environment is ready
3. **Given** a preview environment is ready, **When** a reviewer visits the preview URL, **Then** they can interact with the complete application — frontend, API, and background workers — running the exact code from the PR branch
4. **Given** multiple PRs are open simultaneously, **When** previews are deployed, **Then** each PR has its own isolated environment with no cross-PR interference; at most 3 concurrent preview environments exist at any time
5. **Given** a pull request is closed or merged, **When** the PR lifecycle ends, **Then** the preview environment and all associated resources are automatically torn down within 5 minutes

---

### User Story 3 - Automatic Production Deployment on Merge (Priority: P1)

As a team lead, I want every merge to the main branch to automatically deploy to production, so that validated changes reach users quickly without any manual deployment steps.

**Why this priority**: The PR preview has already validated every change in a production-like environment. Requiring a separate manual deployment step adds delay without adding safety, and introduces the risk of human error.

**Independent Test**: Merge a PR; verify production automatically deploys within 10 minutes using the same artifact versions that were validated in the PR preview — without any manual trigger.

**Acceptance Scenarios**:

1. **Given** a PR is merged to main, **When** the merge completes and CI passes on main, **Then** the production deployment starts automatically using the artifact versions that were validated in the preview — no rebuild, no manual trigger
2. **Given** a production deployment succeeds, **When** a developer or user accesses the production URL, **Then** the application is functional and running the merged changes
3. **Given** a production deployment fails health checks, **When** the failure is detected, **Then** the system automatically reverts to the previous healthy version within 5 minutes
4. **Given** a developer discovers a bad deployment in production, **When** they revert the merge commit, **Then** production automatically redeploys the previous version

---

### User Story 4 - Infrastructure Pipeline (Priority: P3)

As a DevOps engineer, I want infrastructure definition changes to be validated and applied through the same pipeline as application code, so that infrastructure and application stay in sync and changes are auditable.

**Why this priority**: Infrastructure drift causes hard-to-debug environment differences. Routing infrastructure changes through the pipeline gives the same auditability, review process, and traceability as application code.

**Independent Test**: Submit a PR with an infrastructure change (e.g., increasing a resource limit); verify the pipeline validates the change and applies it automatically on merge to main.

**Acceptance Scenarios**:

1. **Given** infrastructure definition code changes in the repository, **When** a PR is opened, **Then** the pipeline runs a validation (plan/dry-run) and reports any errors on the PR
2. **Given** an infrastructure change PR is merged to main, **When** the deployment pipeline runs, **Then** infrastructure changes are applied before the application deployment
3. **Given** an infrastructure change fails to apply, **When** the pipeline runs, **Then** the application deployment step is blocked and the failure is clearly reported

---

### Edge Cases

- **Multiple PR previews in parallel**: Each PR receives its own fully isolated environment scoped by PR number — concurrent previews cannot interfere with each other
- **Resource contention**: Preview environments are resource-constrained so that the production workload is protected and remains stable even when multiple previews are active
- **Preview deployment failure**: A failed preview blocks merge for that specific PR as a required status check, but does not affect other open PRs
- **Production deployment failure**: Health checks detect the failure and the system automatically reverts to the last known-good version; developers can also manually revert the merge commit to trigger a rollback
- **Concurrent production deployments**: Only one production deployment is active at a time; if two merges happen in quick succession, they are processed sequentially
- **Secret exposure prevention**: Secrets are never written to logs, build outputs, or repository files; all authentication uses short-lived federated credentials

## Requirements *(mandatory)*

### Functional Requirements

#### Continuous Integration (CI)

- **FR-001**: The pipeline MUST run all test suites (shared library, API, workers, frontend) on every pull request automatically
- **FR-002**: The pipeline MUST block PR merge when any test or code quality check fails
- **FR-003**: The pipeline MUST display a test results summary directly on the pull request, with links to detailed logs on failure
- **FR-004**: The pipeline MUST cache build dependencies to keep total CI feedback time within the 15-minute target
- **FR-005**: The pipeline MUST run code quality checks (linting, type checking, build validation) as part of the CI process

#### Continuous Deployment — PR Preview

- **FR-006**: The pipeline MUST automatically deploy a preview environment for each pull request once CI passes
- **FR-007**: The pipeline MUST build versioned, immutable application artifacts for the API service and all worker services from the PR branch
- **FR-008**: The pipeline MUST deploy each preview into a fully isolated environment scoped to its PR number, with no shared state between previews
- **FR-009**: The pipeline MUST post the preview URL and deployment status (deploying / ready / failed) as a PR comment, updating it as status changes
- **FR-010**: The pipeline MUST enforce a maximum of 3 concurrent preview environments to protect production workload stability
- **FR-011**: The pipeline MUST automatically remove all preview environment resources when a PR is closed or merged
- **FR-012**: The pipeline MUST verify preview service health after deployment before reporting the environment as ready

#### Continuous Deployment — Production

- **FR-013**: The pipeline MUST automatically deploy to production on every merge to the main branch without manual intervention
- **FR-014**: The pipeline MUST deploy the exact artifact versions validated in the PR preview to production — no re-build from source on merge
- **FR-015**: The pipeline MUST record the exact artifact version identifiers in version control to trigger and track each production deployment
- **FR-016**: The pipeline MUST support rollback to any previous production version by reverting the corresponding change in version control
- **FR-017**: The pipeline MUST verify production service health after deployment and trigger automatic rollback if health checks do not pass

#### Security & Secrets

- **FR-018**: All secrets (API keys, connection strings, credentials) MUST be stored in a secrets management system — never in repository files or pipeline logs
- **FR-019**: The pipeline MUST never expose secret values in log output, build artifacts, or PR comments
- **FR-020**: The pipeline MUST authenticate to cloud services using short-lived federated credentials — no static service account keys stored in the repository

#### Observability & Traceability

- **FR-021**: The pipeline MUST notify the team of deployment success or failure via the standard PR/commit status interface
- **FR-022**: The pipeline MUST provide direct links to deployment logs and sync status from the PR or commit view
- **FR-023**: Every deployed artifact MUST be tagged with the source commit identifier, making it possible to trace any running version back to its exact source commit within 30 seconds

### Key Entities

- **Pipeline**: An automated workflow that orchestrates build, test, and deploy steps triggered by repository events (PR open, push to main)
- **Preview Environment**: An ephemeral, fully isolated deployment created per pull request for validation before merge; torn down automatically when the PR closes
- **Production Environment**: The persistent live deployment serving end users; updated automatically on every merge to main
- **Versioned Artifact**: An immutable, built application component (API service or worker service) uniquely identified by a content-based version tag derived from the source commit
- **Secret**: A sensitive configuration value (credential, API key, connection string) stored outside the repository and injected securely at runtime
- **Deployment Record**: A version-controlled record of which artifact versions are deployed to each environment, providing an auditable history and enabling rollback

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Pull request test feedback is available within 15 minutes of PR creation or update
- **SC-002**: PR preview environments are fully deployed and accessible within 10 minutes of CI passing
- **SC-003**: Production deployments complete within 10 minutes of merge to main
- **SC-004**: 100% of merges to main automatically trigger a production deployment — no manual steps required
- **SC-005**: Zero secrets are exposed in pipeline logs, PR comments, or build artifacts at any time
- **SC-006**: The team receives a deployment success or failure notification within 2 minutes of completion
- **SC-007**: Any developer can identify which source commit is running in any environment within 30 seconds, using only the deployment interface
- **SC-008**: Failed production deployments are automatically reverted to the previous healthy version within 5 minutes of failure detection
- **SC-009**: Preview environments are fully cleaned up within 5 minutes of a PR being closed or merged
- **SC-010**: All pipeline configuration is version-controlled and changes are reviewed through the same PR process as application code

## Assumptions

- A cloud subscription with appropriate permissions for creating container and compute resources is available
- The source repository has CI/CD pipeline capabilities enabled with the required permissions to deploy to the target cloud environment
- Application components are containerised; the API service and all worker services (transcribe, summarize, embed, relationships) each produce a deployable artifact
- A container image registry is available for storing and pulling versioned artifacts
- A single shared compute cluster hosts both production and preview workloads; resource isolation between previews and production is enforced by the platform
- A GitOps-style deployment controller watches the repository for manifest changes and applies them to the cluster automatically
- Environment-specific configuration is managed via overlay files that patch the base manifests; preview overlays live in PR branches, not in main
- The Next.js frontend is hosted on a static web hosting service with built-in PR preview (staging slot) support
- Infrastructure is provisioned via an Infrastructure-as-Code tool; state is stored remotely with locking to prevent concurrent modification
- Authentication between the pipeline and cloud services uses OpenID Connect federation — no static credentials are stored in the repository
- Database schema migrations are applied as a pre-deployment step using the existing migration tool (Alembic); all migrations must be backward-compatible
- Runtime secrets are stored in a cloud-managed key vault and synced into the cluster at runtime via the External Secrets Operator — never committed to the repository
- Local development uses a separate local orchestrator (Aspire + Docker) and is unaffected by these pipeline changes
- End-to-end tests run against PR preview environments (not inside the CI workflow) to test the fully deployed stack
- No long-lived staging environment exists; PR preview environments are the sole pre-production validation surface
- Preview URLs follow the pattern `api-pr-{number}.yt-summarizer.apps.ashleyhollis.com` using a shared wildcard TLS certificate — no per-PR certificate provisioning is required
- Preview environments for the frontend are delivered as Azure Static Web Apps staging slots with the backend URL injected at build time
