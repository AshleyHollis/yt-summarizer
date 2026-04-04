# Requirements Checklist: Azure CI/CD Pipelines

**Status**: Implementing
**Milestone**: M2
**Spec Phase**: execution
**Created**: 2026-01-08
**Updated**: 2026-04-04

## Continuous Integration (CI)

- [x] FR-001: Run all test suites (shared, API, workers, frontend) on every PR — T28, T29, T30, T36
- [x] FR-002: Block PR merge when any test or quality check fails — T28, T76
- [x] FR-003: Display test results summary on PR with links to failure logs — T29, T30
- [x] FR-004: Cache build dependencies to keep CI within 15-minute target — T31
- [x] FR-005: Run code quality checks (linting, type-check, build validation) — T32, T36

## Continuous Deployment — PR Preview

- [x] FR-006: Automatically deploy preview environment for each PR after CI passes — T45, T46, T47, T48
- [x] FR-007: Build versioned, immutable application artifacts with PR-SHA tags — T47, T07, T08
- [x] FR-008: Deploy each preview into isolated environment scoped to PR number — T40, T43, T48
- [x] FR-009: Post preview URL and status as PR comment — T49, T54
- [x] FR-010: Enforce maximum 3 concurrent preview environments — T50
- [x] FR-011: Automatically remove preview resources when PR is closed or merged — T57
- [x] FR-012: Verify preview service health before reporting ready — T55, T56

## Continuous Deployment — Production

- [x] FR-013: Auto-deploy to production on every merge to main without manual intervention — T59, T60, T65
- [x] FR-014: Deploy exact artifact versions validated in preview (no rebuild) — T61
- [x] FR-015: Record artifact version identifiers in version control — T61
- [x] FR-016: Support rollback by reverting version-controlled deployment record — T80
- [ ] FR-017: Verify production health and auto-rollback on failure — T62, T79

## Security & Secrets

- [x] FR-018: All secrets in secrets management system; never in repo or logs — T14, T20, T25, T73
- [x] FR-019: Never expose secrets in logs, artifacts, or PR comments — T73
- [x] FR-020: Authenticate to cloud via short-lived OIDC credentials — T46, T74

## Observability & Traceability

- [x] FR-021: Notify team of deployment success/failure via PR/commit status — T63
- [x] FR-022: Provide direct links to deployment logs and sync status — T63, T71, T72
- [x] FR-023: Tag every artifact with source commit identifier — T47

## Infrastructure as Code

- [x] FR-024: Validate infrastructure changes on PR — T66, T67, T33
- [x] FR-025: Apply infrastructure changes automatically before app deployment on merge — T66, T68
