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

| Spec, feature spec, requirements, PRD, product planning, user stories, feature planning | Spec | Specification domain |
| Human notification (blocked, error, done)         | Any      | Use `squad-human-notification` skill via Discord MCP            |

## Default

If ambiguous, route to Dallas for triage.

## Discord Notifications (Mandatory)

23. **Every agent MUST send Discord notifications** — Read the `squad-human-notification` skill before starting work. Agents must notify on: phase/task completion, errors blocking progress, questions needing input, and CI/pipeline results. Use the node.js script method (in the skill) which always works, even when Discord MCP tools aren't loaded.
24. **Coordinator sends summary notifications** — After collecting results from agent batches, the coordinator sends a Discord summary to `#yt-summarizer` with what completed and what's next. This ensures the user gets push notifications on their phone even when away from the terminal.
25. **Questions go to Discord first** — When an agent needs user input and `ask_user` isn't available (background mode), post the question to Discord and check for replies before making a default decision.
26. **Start Discord watcher on every session** — The coordinator MUST start the Discord watcher daemon (`~/.copilot/tools/discordmcp/discord-watcher.cjs --interval 10 --channel 1479062015220908154`) as a detached background process at the beginning of every session. Check `~/.copilot/tools/discordmcp/inbox.json` for new human messages after every agent batch and before calling task_complete.
27. **Process Discord inbox like user input** — When the inbox contains messages, treat them as if the user typed them in the CLI. Acknowledge on Discord, then route the work.
