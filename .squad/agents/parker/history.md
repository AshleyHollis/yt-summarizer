# Parker — History

## Project Context
- **Project**: YT Summarizer — YouTube video knowledge library
- **Stack**: Terraform, AKS, ArgoCD, Azure, GitHub Actions, .NET Aspire
- **User**: Ashley Hollis

## Key Knowledge
- Auth0 PATCH /connections/{id}/clients expects array of {client_id, status: boolean} objects.
- Auth0 deprecated enabled_clients. Use GET/PATCH /api/v2/connections/{id}/clients dedicated endpoints.
- Preview hostnames: api-pr-<num>.yt-summarizer.apps.ashleyhollis.com via Cloudflare wildcard.
- Auth0 preview client needs database connection enabled via additional_database_client_ids on prod auth0 module.
- K8s migration-job can't run alembic because Docker image doesn't include alembic.ini or migration scripts.
- E2E tests use maxFailures: 5 in CI. Auth0 connection enablement step in preview.yml with continue-on-error.

## Learnings
<!-- Append learnings below -->
