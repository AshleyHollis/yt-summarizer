# Feature Specification: Azure CI/CD Pipelines

**Feature Branch**: `002-azure-cicd`  
**Created**: 2026-01-08  
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

### User Story 2 - Build and Deploy to Staging on Merge (Priority: P2)

As a team lead, I want the application to automatically deploy to a staging environment when code is merged to main, so that we can validate changes in an Azure-like environment before production.

**Why this priority**: Staging deployment enables validation of changes in an environment that mirrors production, catching environment-specific issues before they impact users.

**Independent Test**: Can be fully tested by merging a small change to main and verifying all services are deployed and accessible in the staging environment.

**Acceptance Scenarios**:

1. **Given** a PR is merged to main, **When** the merge completes, **Then** the pipeline builds all components (web, API, workers)
2. **Given** builds complete successfully, **When** deployment starts, **Then** all services are deployed to the Azure staging environment
3. **Given** deployment completes, **When** accessing the staging URL, **Then** the application is functional and running the latest changes

---

### User Story 3 - Manual Production Deployment with Approval (Priority: P3)

As an operations engineer, I want to manually trigger production deployments with approval gates, so that we have control over what goes to production and when.

**Why this priority**: Production deployments require human oversight to ensure business readiness, coordinate with stakeholders, and minimize risk.

**Independent Test**: Can be fully tested by triggering a production deployment and verifying the approval workflow executes before deployment proceeds.

**Acceptance Scenarios**:

1. **Given** a successful staging deployment, **When** an authorized user triggers production deployment, **Then** an approval request is created
2. **Given** an approval request exists, **When** an authorized approver approves it, **Then** the deployment proceeds to production
3. **Given** an approval request exists, **When** an authorized approver rejects it, **Then** the deployment is cancelled with a recorded reason

---

### User Story 4 - Infrastructure as Code Deployment (Priority: P4)

As a DevOps engineer, I want infrastructure changes to be deployed through the same pipeline, so that infrastructure and application code stay in sync.

**Why this priority**: Consistent infrastructure management prevents configuration drift and ensures reproducible environments.

**Independent Test**: Can be fully tested by making an infrastructure change (e.g., adding a new environment variable) and verifying it's applied through the pipeline.

**Acceptance Scenarios**:

1. **Given** infrastructure code changes in the repository, **When** merged to main, **Then** infrastructure changes are applied before application deployment
2. **Given** an infrastructure change fails, **When** the pipeline runs, **Then** the application deployment is blocked and the team is notified

---

### Edge Cases

- **Partial deployment failure**: Pipeline uses fail-fast strategy; if any service fails, remaining deployments stop and completed services automatically rollback to previous version
- **Concurrent pipeline runs**: Multiple PRs can run CI in parallel; CD deployments are serialized to prevent conflicts
- **Unhealthy staging after deployment**: Health checks fail the pipeline, triggering automatic rollback
- **Secrets management**: All secrets stored in GitHub Secrets or Azure Key Vault, never in code or logs

## Requirements *(mandatory)*

### Functional Requirements

#### Continuous Integration (CI)
- **FR-001**: System MUST run all test suites (shared, workers, API, frontend, E2E) on every pull request
- **FR-002**: System MUST block PR merge when any test fails
- **FR-003**: System MUST provide test results summary visible in the GitHub PR interface
- **FR-004**: System MUST cache dependencies (npm, pip, uv) to reduce pipeline execution time
- **FR-005**: System MUST run linting and code quality checks before tests

#### Continuous Deployment (CD) - Staging
- **FR-006**: System MUST automatically deploy to staging environment when code is merged to main
- **FR-007**: System MUST build Docker images: 1 API image + 1 unified Workers image (runs all 4 workers: transcribe, summarize, embed, relationships)
- **FR-008**: System MUST build and deploy the Next.js frontend
- **FR-009**: System MUST run database migrations as part of deployment
- **FR-009a**: System MUST use fail-fast strategy: stop remaining deployments if any service fails
- **FR-009b**: System MUST automatically rollback completed services when a deployment fails
- **FR-010**: System MUST perform health checks after deployment to verify service availability

#### Continuous Deployment (CD) - Production
- **FR-011**: System MUST require manual trigger for production deployments
- **FR-012**: System MUST require approval from designated approvers before production deployment
- **FR-013**: System MUST deploy the same artifacts that were validated in staging
- **FR-014**: System MUST support rollback to previous version if deployment fails

#### Security & Secrets
- **FR-015**: System MUST store all secrets (API keys, connection strings) in GitHub Secrets or Azure Key Vault
- **FR-016**: System MUST never expose secrets in logs or artifacts
- **FR-017**: System MUST use managed identities or service principals for Azure authentication

#### Notifications & Observability
- **FR-018**: System MUST notify on deployment success or failure → *Covered by GitHub Actions built-in (VS Code extension, Actions tab, email)*
- **FR-019**: System MUST provide links to deployment logs and Azure portal resources
- **FR-020**: System MUST tag deployed resources with commit SHA for traceability

### Key Entities

- **Pipeline**: A GitHub Actions workflow that orchestrates build, test, and deploy steps
- **Environment**: A target deployment destination (staging, production) with its own configuration
- **Artifact**: Built application components (Docker images, static assets) ready for deployment
- **Secret**: Sensitive configuration values stored securely and injected at runtime
- **Approval Gate**: A checkpoint requiring human authorization before proceeding

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Pull request test feedback is available within 15 minutes of PR creation/update
- **SC-002**: Staging deployments complete within 20 minutes of merge to main
- **SC-003**: Zero secrets are exposed in pipeline logs or build artifacts
- **SC-004**: 100% of production deployments require and receive approval before execution
- **SC-005**: Team is notified of deployment status within 2 minutes of completion
- **SC-006**: Developers can identify which commit is deployed to each environment within 30 seconds
- **SC-007**: Failed deployments can be rolled back within 10 minutes
- **SC-008**: Pipeline configuration changes are version-controlled and reviewable through PRs

## Clarifications

### Session 2026-01-08
- Q: Which Azure hosting service should be used for the containerized API and Workers? → A: ~~Azure Container Apps (ACA)~~ → Revised: AKS single-node cluster (cost-effective for hobby project)
- Q: Where should the Next.js frontend be hosted? → A: Azure Static Web Apps (free tier)
- Q: What Infrastructure as Code (IaC) tool should provision and manage Azure resources? → A: Terraform
- Q: Where should Terraform state be stored? → A: Azure Storage Account (with state locking)
- Q: How should deployment failures be handled when one service fails but others succeed? → A: Fail-fast with automatic rollback

### Session 2026-01-08 (Revision)
- Q: Cost concern - ACA could get expensive with multiple apps. Alternative? → A: AKS single-node (~$30/month fixed) with GitOps
- Q: Which GitOps tool? → A: Argo CD (better UI, easier debugging)
- Q: Which K8s manifest format? → A: Kustomize (simpler, built into kubectl)
- Q: Keep SWA for frontend? → A: Yes, free tier with CDN/SSL
- Q: Local dev approach? → A: Keep Aspire + Docker (unchanged); K8s only for Azure

## Assumptions

- Azure subscription with appropriate permissions is available for creating resources
- GitHub repository has Actions enabled and appropriate permissions configured
- Azure Container Registry will be used for Docker image storage
- AKS single-node cluster (~$30/month) will host API and Workers via GitOps
- Argo CD will be installed on AKS for GitOps-based deployments
- Kustomize will be used for Kubernetes manifest management
- Azure Static Web Apps (free tier) will be used for the Next.js frontend
- Terraform will provision AKS cluster and Azure infrastructure
- Local development continues using Aspire + Docker (unchanged)
- Database migrations use Alembic (existing in the project)
- Azure SQL uses serverless tier (auto-pause, ~$5/month) matching constitution cost-aware defaults
- E2E tests can run in CI without Aspire (Docker Compose for CI)
