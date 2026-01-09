# Feature Specification: Azure CI/CD Pipelines

**Feature Branch**: `002-azure-cicd`  
**Created**: 2026-01-08  
**Updated**: 2026-01-09  
**Status**: Draft  
**Input**: User description: "I want to create CI/CD pipelines in GitHub to deploy to Azure."

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Automated Testing on Pull Request (Priority: P1)

As a developer, I want all tests to run automatically when I create or update a pull request, so that I can catch bugs before merging to the main branch.

**Why this priority**: This is the foundation of CI/CD. Without automated testing, deployments cannot be trusted. This prevents regressions and maintains code quality.

**Independent Test**: Can be fully tested by creating a PR with intentional test failures and verifying the pipeline fails, then fixing and verifying it passes.

**Acceptance Scenarios**:

1. **Given** a developer creates a pull request, **When** the PR is opened, **Then** all test suites (shared, workers, API, frontend, E2E) run automatically
2. **Given** a test fails during the PR check, **When** the developer views the PR, **Then** they see a clear failure status with links to detailed logs
3. **Given** all tests pass, **When** the developer views the PR, **Then** they see a green success status indicating the PR is safe to merge

---

### User Story 2 - Deploy PR Preview Environment (Priority: P1)

As a developer, I want a live preview environment deployed for each pull request, so that reviewers can validate changes in a real Azure environment before merging.

**Why this priority**: PR previews are the primary validation surface. They enable reviewers to verify functionality in a production-like environment, catching integration issues before they reach production.

**Independent Test**: Can be fully tested by opening a PR and verifying a unique preview URL is created, accessible, and shows the PR changes.

**Acceptance Scenarios**:

1. **Given** a developer opens or updates a pull request, **When** CI tests pass, **Then** a PR-scoped preview environment is deployed to AKS with a unique namespace
2. **Given** a preview deployment is in progress, **When** the developer views the PR, **Then** they see status updates (deploying/ready/failed) with a preview URL when ready
3. **Given** a preview environment is deployed, **When** a reviewer accesses the preview URL, **Then** they can interact with the full application (API, workers, frontend)
4. **Given** a pull request is closed or merged, **When** the PR lifecycle ends, **Then** the preview environment is automatically torn down and resources reclaimed

---

### User Story 3 - Automatic Production Deployment on Merge (Priority: P1)

As a team lead, I want the application to automatically deploy to production when a PR is merged to main, so that validated changes reach users quickly without manual intervention.

**Why this priority**: Automatic production deployment eliminates deployment delays and human error. The PR preview has already validated the changes, making manual approval redundant.

**Independent Test**: Can be fully tested by merging a PR and verifying the same artifacts deployed to preview are automatically promoted to production.

**Acceptance Scenarios**:

1. **Given** a PR is merged to main, **When** the merge completes, **Then** the production deployment automatically starts using the same image digests validated in the preview
2. **Given** a production deployment succeeds, **When** accessing the production URL, **Then** the application is functional and running the merged changes
3. **Given** a production deployment fails, **When** health checks do not pass, **Then** Argo CD automatically rolls back to the previous healthy version
4. **Given** a bad deployment reaches production, **When** a developer reverts the merge commit, **Then** production automatically redeploys the previous version

---

### User Story 4 - Infrastructure as Code Deployment (Priority: P3)

As a DevOps engineer, I want infrastructure changes to be deployed through the same pipeline, so that infrastructure and application code stay in sync.

**Why this priority**: Consistent infrastructure management prevents configuration drift and ensures reproducible environments.

**Independent Test**: Can be fully tested by making an infrastructure change (e.g., adding a new environment variable) and verifying it's applied through the pipeline.

**Acceptance Scenarios**:

1. **Given** infrastructure code changes in the repository, **When** merged to main, **Then** infrastructure changes are applied before application deployment
2. **Given** an infrastructure change fails, **When** the pipeline runs, **Then** the application deployment is blocked and the team is notified

---

### Edge Cases

- **Multiple PR previews in parallel**: Each PR gets its own isolated namespace in AKS; namespaces are prefixed with PR number to prevent conflicts
- **Single-node AKS resource contention**: Preview environments have resource quotas/limits enforced so production namespace remains stable; max 3 concurrent previews
- **Preview deployment failure**: A failed preview blocks merge for that PR (required status check) but does not block other PRs
- **Production deployment failure**: Health checks fail → Argo CD automatically syncs to previous healthy revision; developers can also revert the merge commit
- **Concurrent production deployments**: Argo CD serializes syncs to production; only one deployment active at a time
- **Secrets management**: All secrets stored in GitHub Secrets or Azure Key Vault, never in code or logs; workload identity used for Azure authentication

## Requirements *(mandatory)*

### Functional Requirements

#### Continuous Integration (CI)
- **FR-001**: System MUST run all test suites (shared, workers, API, frontend, E2E) on every pull request
- **FR-002**: System MUST block PR merge when any test fails
- **FR-003**: System MUST provide test results summary visible in the GitHub PR interface
- **FR-004**: System MUST cache dependencies (npm, pip, uv) to reduce pipeline execution time
- **FR-005**: System MUST run linting and code quality checks before tests

#### Continuous Deployment (CD) - PR Preview
- **FR-006**: System MUST deploy a preview environment for each pull request after CI tests pass
- **FR-007**: System MUST build Docker images: 1 API image + 1 unified Workers image (runs all 4 workers: transcribe, summarize, embed, relationships)
- **FR-008**: System MUST deploy preview to a PR-scoped namespace in AKS (e.g., `preview-pr-123`)
- **FR-009**: System MUST post preview URL and deployment status (deploying/ready/failed) as a PR comment or status check
- **FR-010**: System MUST enforce resource quotas on preview namespaces to protect production stability (max 3 concurrent previews)
- **FR-011**: System MUST automatically delete preview namespace when PR is closed or merged
- **FR-012**: System MUST perform health checks after preview deployment to verify service availability

#### Continuous Deployment (CD) - Production
- **FR-013**: System MUST automatically deploy to production when a PR is merged to main
- **FR-014**: System MUST promote the same image digests validated in the preview (no rebuild)
- **FR-015**: System MUST update Kustomize overlay with image digest and commit to trigger Argo CD sync
- **FR-016**: System MUST support rollback via Argo CD sync to previous revision or merge commit revert
- **FR-017**: System MUST perform health checks after production deployment

#### Security & Secrets
- **FR-018**: System MUST store all secrets (API keys, connection strings) in GitHub Secrets or Azure Key Vault
- **FR-019**: System MUST never expose secrets in logs or artifacts
- **FR-020**: System MUST use workload identity or managed identity for Azure authentication (prefer over service principals)

#### Notifications & Observability
- **FR-021**: System MUST notify on deployment success or failure → *Covered by GitHub Actions built-in (VS Code extension, Actions tab, email)*
- **FR-022**: System MUST provide links to Argo CD sync status and deployment logs
- **FR-023**: System MUST tag deployed resources with commit SHA for traceability

### Key Entities

- **Pipeline**: A GitHub Actions workflow that orchestrates build, test, and deploy steps
- **Preview Environment**: An ephemeral PR-scoped deployment in AKS for validation before merge
- **Production Environment**: The live deployment serving end users
- **Artifact**: Built application components (Docker images with pinned digests) ready for deployment
- **Secret**: Sensitive configuration values stored securely and injected at runtime
- **Argo CD Application**: GitOps resource that syncs Kubernetes manifests to the cluster

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Pull request test feedback is available within 15 minutes of PR creation/update
- **SC-002**: PR preview environments are deployed within 10 minutes of CI passing
- **SC-003**: Production deployments complete within 10 minutes of merge to main
- **SC-004**: 100% of merges to main automatically trigger production deployment (no manual steps)
- **SC-005**: Zero secrets are exposed in pipeline logs or build artifacts
- **SC-006**: Team is notified of deployment status within 2 minutes of completion
- **SC-007**: Developers can identify which commit is deployed to each environment within 30 seconds (commit SHA tagging)
- **SC-008**: Failed deployments trigger automatic rollback within 5 minutes
- **SC-009**: Preview environments are cleaned up within 5 minutes of PR close/merge
- **SC-010**: Pipeline configuration changes are version-controlled and reviewable through PRs

## Clarifications

### Session 2026-01-08
- Q: Which Azure hosting service should be used for the containerized API and Workers? → A: AKS single-node cluster (cost-effective for hobby project)
- Q: Where should the Next.js frontend be hosted? → A: Azure Static Web Apps (free tier)
- Q: What Infrastructure as Code (IaC) tool should provision and manage Azure resources? → A: Terraform
- Q: Where should Terraform state be stored? → A: Azure Storage Account (with state locking)

### Session 2026-01-09 (Updated Strategy)
- Q: Is a long-lived staging environment required? → A: No. PR preview environments are the primary validation surface. Staging is removed.
- Q: How should production deployments be triggered? → A: Automatically on merge to main. No manual trigger or approval gates.
- Q: How do we ensure production matches what was previewed? → A: Same Docker image digests are promoted (no rebuild). Kustomize overlay updated with pinned digests.
- Q: How should deployment failures be handled? → A: Argo CD automatically rolls back to previous healthy revision; developers can also revert the merge commit.
- Q: How should multiple PR previews be isolated? → A: Each PR gets its own Kubernetes namespace (e.g., `preview-pr-123`).
- Q: Resource constraints for single-node AKS? → A: Max 3 concurrent previews with resource quotas; production namespace protected.

## Assumptions

- Azure subscription with appropriate permissions is available for creating resources
- GitHub repository has Actions enabled and appropriate permissions configured
- Azure Container Registry (ACR) will be used for Docker image storage with digest-based tagging
- AKS single-node cluster (~$30/month) will host API, Workers, and PR preview environments
- Argo CD will be installed on AKS for GitOps-based deployments
- Kustomize overlays will manage environment-specific configurations (preview, production)
- Azure Static Web Apps (free tier) will be used for the Next.js frontend
- Terraform will provision AKS cluster and Azure infrastructure
- Local development continues using Aspire + Docker (unchanged)
- Database migrations use Alembic (existing in the project)
- Azure SQL uses serverless tier (auto-pause, ~$5/month) matching constitution cost-aware defaults
- E2E tests run in CI without Aspire (Docker Compose for CI)
- PR preview environments are ephemeral and automatically cleaned up
- No long-lived staging environment exists; PR previews serve as the validation surface
