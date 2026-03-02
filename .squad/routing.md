# Routing Rules

## Signal → Agent Mapping

| Signal | Agent(s) | Rationale |
|--------|----------|-----------|
| Next.js, React, frontend, UI, components, pages, CSS | Lambert | Frontend domain |
| Playwright, E2E tests, browser tests, test failures | Kane + Lambert | Testing + frontend context |
| Python, FastAPI, API routes, workers, SQLAlchemy, yt-dlp | Ripley | Backend domain |
| Terraform, AKS, Kubernetes, CI/CD, GitHub Actions, Azure, Docker, ArgoCD | Parker | Infrastructure domain |
| Architecture, scope, design decisions, code review | Dallas | Lead authority |
| Auth0, authentication, cookies, CORS, session | Ripley + Lambert | Backend auth + frontend auth |
| Library page, video detail, submit page | Lambert | Frontend pages |
| Proxy, Webshare, bandwidth, queue workers | Ripley | Backend services |
| Database, migrations, Alembic, SQL | Ripley | Data layer |
| Deploy, preview, production, pipeline | Parker | DevOps domain |
| Test strategy, quality, edge cases | Kane | Testing domain |

## Default

If ambiguous, route to Dallas for triage.
