# AI Agent Skills Reference

<purpose>
Available tools, CLIs, and automation scripts for AI coding assistants working on this project.
Use these skills when appropriate instead of asking users for manual steps.
</purpose>

## Available CLIs

<clis>
### Azure CLI (az)
**Purpose**: Azure resource management
**Common commands**:
- `az acr repository show-tags --name <registry> --repository <repo>` - List container image tags
- `az aks get-credentials --resource-group <rg> --name <cluster>` - Get K8s credentials
- `az storage account show-connection-string` - Get storage connection strings
- `az keyvault secret show --name <secret> --vault-name <vault>` - Retrieve secrets
- `az group create/delete/show` - Resource group management

### kubectl
**Purpose**: Kubernetes cluster operations
**Common commands**:
- `kubectl apply -f <manifest>` - Apply K8s manifests
- `kubectl get pods/deployments/services` - List resources
- `kubectl logs <pod> -n <namespace>` - View pod logs
- `kubectl patch application <name> -n argocd` - Patch ArgoCD apps
- `kubectl describe resourcequota -n <namespace>` - Check quota usage

### Terraform
**Purpose**: Infrastructure as Code
**Common commands**:
- `terraform plan` - Preview changes
- `terraform apply` - Apply changes
- `terraform init` - Initialize backend
- `terraform validate` - Validate configuration
- `terraform fmt` - Format code

### GitHub CLI (gh)
**Purpose**: GitHub operations
**Common commands**:
- `gh pr create --title "..." --body "..."` - Create PRs
- `gh pr merge <number> --squash` - Merge PRs
- `gh issue create/list/comment` - Issue management
- `gh run list/watch` - Workflow monitoring
- `gh workflow run <name>` - Trigger workflows

### Kustomize
**Purpose**: Kubernetes manifest customization
**Common commands**:
- `kustomize build <overlay-path>` - Build manifests
- `kustomize cfg grep` - Search manifests
- `kustomize edit set image` - Update image tags

### npm / Node.js
**Purpose**: Frontend package management and scripts
**Common commands**:
- `npm install` - Install dependencies
- `npm run dev` - Start dev server
- `npm run test:run` - Run Vitest tests
- `npm run lint` - Run ESLint
- `npm run build` - Production build
- `npx playwright test` - Run E2E tests
- `npx vitest run` - Run specific tests
- `npx prettier --write .` - Format code

### uv (Python)
**Purpose**: Modern Python package management
**Common commands**:
- `uv sync` - Sync dependencies from pyproject.toml
- `uv run <command>` - Run command in venv
- `uv run pytest` - Run Python tests
- `uv run ruff check .` - Lint Python code
- `uv run ruff format .` - Format Python code
- `uv run alembic revision --autogenerate -m "desc"` - Create migration
- `uv run alembic upgrade head` - Run migrations
- `uv run uvicorn src.api.main:app --reload` - Start API server

### Python Tools
**Purpose**: Development and testing
**Common commands**:
- `pytest tests/test_file.py::test_name` - Run specific test
- `pytest tests/ -k "partial_name"` - Run tests matching pattern
- `ruff check .` - Lint code
- `ruff format .` - Format code
- `alembic revision --autogenerate -m "desc"` - DB migrations
- `python -m pre_commit run --all-files` - Run pre-commit hooks

### PowerShell
**Purpose**: Windows automation (primary scripting language)
**Common commands**:
- `./scripts/run-tests.ps1` - Run all tests
- `./scripts/run-tests.ps1 -Component api` - Component-specific tests
- `./scripts/run-migrations.ps1` - Run DB migrations
- `./scripts/start-workers.ps1` - Start worker processes
- `./scripts/deploy-infra.ps1` - Deploy infrastructure
- `./scripts/smoke-test.ps1` - Quick health check

### Shell (Bash)
**Purpose**: Cross-platform scripts in scripts/ci/
**Common commands**:
- `scripts/ci/validate-k8s-placeholders.sh` - Validate K8s patches
- `scripts/ci/generate_preview_kustomization.sh` - Generate preview configs
- `scripts/ci/lib/validate-deployment.sh` - Pre-deployment validation
- `scripts/ci/lib/argocd-utils.sh` - ArgoCD helper functions

### Aspire
**Purpose**: .NET Aspire orchestration
**Common commands**:
- `aspire run` - Start full stack
- `aspire stop` - Stop orchestration
- `Get-Content aspire.log -Tail 50` - View logs (PowerShell)

### Playwright
**Purpose**: E2E browser testing
**Common commands**:
- `npx playwright test` - Run all E2E tests
- `npx playwright test e2e/smoke.spec.ts` - Run specific test
- `npx playwright test --headed` - Run with visible browser
- `npx playwright codegen` - Generate test code

### Docker (implied)
**Purpose**: Container operations
**Note**: Used in CI/CD for building images, not typically for local dev
</clis>

## When to Use Each CLI

<usage_guide>
| Task | Primary Tool | Example |
|------|--------------|---------|
| Create PR | gh | `gh pr create --title "..." --body "..."` |
| Run tests | PowerShell | `./scripts/run-tests.ps1` |
| K8s deployment | kubectl | `kubectl apply -f k8s/` |
| Validate manifests | kustomize | `kustomize build k8s/overlays/prod` |
| DB migration | uv | `uv run alembic upgrade head` |
| Frontend dev | npm | `npm run dev` |
| Python lint | uv | `uv run ruff check .` |
| E2E testing | Playwright | `npx playwright test` |
| Azure resources | az | `az acr repository show-tags ...` |
| Infrastructure | Terraform | `terraform plan` |
| Git operations | gh | `gh pr merge 123 --squash` |
| Start full stack | Aspire | `aspire run` |
</usage_guide>

## MCP Tools Available

<mcp_tools>
**Playwright MCP**: Browser automation for UI testing and verification
- Use for E2E testing, taking screenshots, verifying UI state
- Available via Playwright MCP server

**Note**: Azure CLI, GitHub CLI, and other tools are available as system commands, not MCP servers.
</mcp_tools>

## Skill Selection Guidelines

<guidelines>
1. **Prefer automation scripts**: Use `./scripts/*.ps1` for common workflows
2. **Use gh for GitHub**: Don't ask users to manually click - use `gh` CLI
3. **Use uv for Python**: Modern replacement for pip, faster and more reliable
4. **Use npm for frontend**: Standard Node.js package management
5. **Use kubectl for K8s**: Direct cluster management
6. **Use kustomize for manifests**: Build and validate K8s configs
7. **Use az for Azure**: Resource management and queries
8. **Use terraform for infra**: Infrastructure changes and validation

**When NOT to use**:
- Don't use Docker directly (use Aspire orchestration instead)
- Don't manually edit K8s manifests (use kustomize patches)
- Don't ask users to run commands you can run yourself
</guidelines>

## Quick Reference

<quick_ref>
**Most Common Commands**:
```bash
# Testing
./scripts/run-tests.ps1
./scripts/run-tests.ps1 -Component api

# Development
aspire run
cd apps/web && npm run dev
cd services/api && uv run uvicorn src.api.main:app --reload

# GitHub
gh pr create --fill
gh pr merge <number> --squash --delete-branch

# Validation
kustomize build k8s/overlays/preview
./scripts/ci/lib/validate-deployment.sh k8s/overlays/preview preview-pr-110

# Database
cd services/shared && uv run alembic upgrade head
```
</quick_ref>
