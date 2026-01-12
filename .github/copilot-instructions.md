# Copilot Agent Instructions

## Available Tools & Capabilities

This repository is configured with the following tools and capabilities that AI agents can use:

### Shell & Terminal Tools
- **PowerShell** (primary shell on Windows) - use for running scripts, commands, and automation
- **Bash/Shell** - available via Git Bash or WSL
- **Git** - version control operations
- **GitHub CLI (`gh`)** - CRITICAL: Always available for GitHub operations (creating PRs, viewing runs, posting comments, managing issues)

### Development & Testing Tools
- **.NET Aspire** - primary orchestrator (see Aspire section below)
- **Playwright** - E2E testing and browser automation (MCP server configured)
- **pytest** - Python testing framework (API, Workers, Shared)
- **Vitest** - Frontend testing framework
- **Ruff** - Python linting and formatting
- **ESLint/Prettier** - JavaScript/TypeScript linting and formatting

### Build & Package Management
- **npm/pnpm** - Node.js package management
- **pip** - Python package management
- **dotnet** - .NET CLI
- **Docker/Docker Compose** - containerization

### Infrastructure & Deployment
- **Terraform** - Infrastructure as Code (see `infra/terraform/`)
- **kubectl** - Kubernetes CLI
- **Helm** - Kubernetes package manager
- **Azure CLI (`az`)** - Azure operations
- **Argo CD** - GitOps deployment

### Repository Scripts
- `scripts/run-tests.ps1` - Run all test suites (REQUIRED before marking tasks complete)
- `scripts/run-migrations.ps1` - Database migrations
- `scripts/start-workers.ps1` - Start background workers
- `scripts/smoke-test.ps1` - Quick health check
- `scripts/deploy-infra.ps1` - Deploy infrastructure
- Various CI/CD helper scripts in `scripts/ci/`

### GitHub Actions & Automation
- **IMPORTANT**: Use `gh` (GitHub CLI) for repository automation:
  - Create PRs: `gh pr create --title "..." --body "..."`
  - View runs: `gh run list`, `gh run view`
  - Post comments: `gh pr comment`
  - Manage issues: `gh issue create`, `gh issue list`
  - Check status: `gh pr status`, `gh pr checks`
- Custom reusable actions in `.github/actions/`

> **📚 Complete Tools Reference**: See [TOOLS_REFERENCE.md](TOOLS_REFERENCE.md) for comprehensive documentation of all available tools, MCP servers, and CLI utilities.

## Aspire Background Wrapper

This repository includes a wrapper script at `tools\aspire.cmd` that detaches the Aspire process into a separate window. This prevents the VS Code agent from killing long-running Aspire processes when it executes subsequent terminal commands.

### Usage Guidelines

- **Do not run long-lived servers in foreground** - they will be killed when the next terminal command runs.
- **Running `aspire run` is safe** - the repo wrapper automatically detaches the process.
- **Verify Aspire is running** by checking the log file:
  ```powershell
  Get-Content aspire.log -Tail 50
  ```
- The wrapper logs all Aspire output to `aspire.log` in the repository root.
- If you need to stop Aspire, close the detached "Aspire" command window or use Task Manager.

### How It Works

The `tools\aspire.cmd` wrapper:
1. Locates the real `aspire` executable on PATH (skipping itself)
2. Launches Aspire in a detached window using `start`
3. Redirects output to `aspire.log` for debugging
4. Returns control immediately so the agent can continue

The VS Code terminal PATH is configured to resolve `tools\` first, so `aspire` commands use the wrapper automatically.
