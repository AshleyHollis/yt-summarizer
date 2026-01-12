# Tools Reference for AI Agents

This document provides a comprehensive reference of all tools available to AI agents in this repository.

## Tool Categories

### Core Editing & Reading Tools

- **read** - Read file contents, directory listings, and repository structure
- **edit** - Modify existing files using string replacement or multi-edit operations  
- **search** - Search for files (glob) or text within files (grep)
- **execute** - Run shell commands (PowerShell on Windows, Bash on Unix)

### MCP Servers (Model Context Protocol)

#### GitHub MCP (`github/*`)

Available tools for GitHub operations:

- `github/repos_get` - Get repository information
- `github/issues_list` - List repository issues
- `github/issues_create` - Create new issues
- `github/pulls_list` - List pull requests
- `github/pulls_get` - Get pull request details
- `github/pulls_create` - Create pull requests
- `github/workflows_list` - List GitHub Actions workflows
- `github/runs_list` - List workflow runs

**Recommended**: Use GitHub CLI (`gh`) instead for most GitHub operations as it provides better error handling and authentication.

#### Playwright MCP (`playwright/*`)

Available for browser automation and E2E testing:

- `playwright/navigate` - Navigate to URLs
- `playwright/snapshot` - Capture accessibility snapshots
- `playwright/screenshot` - Take screenshots
- `playwright/click` - Click elements
- `playwright/type` - Type text into fields
- `playwright/fill_form` - Fill multiple form fields
- `playwright/wait_for` - Wait for conditions
- And many more (see Playwright MCP documentation)

#### Aspire MCP (`aspire/*`)

Available for .NET Aspire orchestration:

- `aspire/list_resources` - List all application resources
- `aspire/list_integrations` - List available Aspire integrations
- `aspire/get_integration_docs` - Get integration documentation
- `aspire/execute_resource_command` - Execute commands on resources (start, stop, restart)
- `aspire/list_console_logs` - Get console logs for resources
- `aspire/list_structured_logs` - Get structured logs for resources
- `aspire/list_traces` - List distributed traces
- `aspire/list_trace_structured_logs` - Get logs for a specific trace
- `aspire/select_apphost` - Select which AppHost to use (if multiple)
- `aspire/list_apphosts` - List all detected AppHosts

## Command-Line Tools Available

### Version Control
- **git** - All git operations
- **gh** (GitHub CLI) - **RECOMMENDED** for GitHub operations
  - `gh pr create` - Create pull requests
  - `gh pr view` - View PR details
  - `gh pr comment` - Add comments to PRs
  - `gh run list` - List workflow runs
  - `gh run view` - View run details
  - `gh issue create` - Create issues
  - `gh issue list` - List issues

### Build & Package Management
- **npm** / **pnpm** - Node.js package management
- **pip** - Python package management  
- **dotnet** - .NET CLI
- **docker** - Container operations
- **docker-compose** - Multi-container orchestration

### Infrastructure & Cloud
- **terraform** - Infrastructure as Code
- **kubectl** - Kubernetes CLI
- **helm** - Kubernetes package manager
- **az** (Azure CLI) - Azure operations
- **aspire** - .NET Aspire CLI (wrapped to run in background, see AGENTS.md)

### Testing & Quality
- **pytest** - Python testing
- **playwright** - E2E testing
- **vitest** - Frontend unit testing
- **ruff** - Python linting and formatting
- **eslint** - JavaScript/TypeScript linting
- **prettier** - Code formatting

### Repository-Specific Scripts

Located in `scripts/`:

- **run-tests.ps1** - Run all test suites (REQUIRED before marking tasks complete)
  - `-SkipE2E` - Skip E2E tests for faster iteration
  - `-Component <name>` - Run specific component tests only
- **run-migrations.ps1** - Run database migrations
- **start-workers.ps1** - Start background worker processes
- **smoke-test.ps1** - Quick health check
- **deploy-infra.ps1** - Deploy infrastructure using Terraform
- **bootstrap-argocd.ps1** - Bootstrap Argo CD on AKS cluster
- **setup-github-oidc.ps1** - Configure GitHub OIDC for Azure
- **clean-dev.ps1** - Clean development environment

## Custom GitHub Actions

Located in `.github/actions/`:

### Testing Actions
- **run-playwright-tests** - Run E2E tests with Playwright
- **run-pytest** - Run Python tests
- **run-vitest** - Run frontend unit tests

### Build & Deploy
- **docker-build-push** - Build and push Docker images
- **terraform-plan** - Run Terraform plan
- **setup-kustomize** - Install and configure Kustomize
- **kustomize-validate** - Validate Kubernetes manifests

### Verification
- **run-ruff-check** - Python linting
- **verify-azure-credentials** - Check Azure service principal
- **validate-argocd-paths** - Validate Argo CD application paths
- **wait-for-argocd-sync** - Wait for Argo CD to sync

### Utilities
- **get-aks-ingress-ip** - Get AKS ingress IP address
- **record-test-duration** - Record test execution time
- **detect-changed-components** - Detect which components changed

## Best Practices

### When to Use Each Tool

1. **GitHub Operations** - Use `gh` CLI instead of `github/*` MCP tools
   - Better authentication handling
   - More reliable error messages
   - Consistent with developer workflows

2. **File Operations** - Use `read`/`edit` tools for code changes
   - Atomic operations
   - Better tracking in conversation history
   - No risk of shell injection

3. **Testing** - Use repository scripts over raw commands
   - `scripts/run-tests.ps1` instead of direct pytest/playwright
   - Ensures correct environment setup
   - Consistent with CI/CD

4. **Aspire Operations** - Use Aspire MCP tools
   - `aspire/list_resources` to check status
   - `aspire/list_console_logs` for debugging
   - Avoid `aspire run` in scripts (use wrapper)

### Tool Selection Examples

```yaml
# Planning agents (analyze, specify, plan)
tools:
  - read
  - edit
  - search
  - execute

# Implementation agents (implement, tasks)
tools:
  - read
  - edit
  - search
  - execute
  - github/*
  - aspire/*

# Testing/Verification agents
tools:
  - read
  - search
  - execute
  - aspire/*
  - playwright/*

# GitHub automation agents
tools:
  - read
  - search
  - execute
  - github/*
```

## References

- [GitHub Copilot Custom Agents Documentation](https://docs.github.com/en/copilot/reference/custom-agents-configuration)
- [Repository Copilot Instructions](.github/copilot-instructions.md)
- [Aspire Guidance](../AGENTS.md)
