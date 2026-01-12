# Copilot instructions

This repository is set up to use Aspire. Aspire is an orchestrator for the entire application and will take care of configuring dependencies, building, and running the application. The resources that make up the application are defined in `apphost.cs` including application code and external dependencies.

## General recommendations for working with Aspire
1. Before making any changes always run the apphost using `aspire run` and inspect the state of resources to make sure you are building from a known state.
1. Changes to the _apphost.cs_ file will require a restart of the application to take effect.
2. Make changes incrementally and run the aspire application using the `aspire run` command to validate changes.
3. Use the Aspire MCP tools to check the status of resources and debug issues.

## Running the application
To run the application run the following command:

```
aspire run
```

If there is already an instance of the application running it will prompt to stop the existing instance. You only need to restart the application if code in `apphost.cs` is changed, but if you experience problems it can be useful to reset everything to the starting state.

## Checking resources
To check the status of resources defined in the app model use the _list resources_ tool. This will show you the current state of each resource and if there are any issues. If a resource is not running as expected you can use the _execute resource command_ tool to restart it or perform other actions.

## Listing integrations
IMPORTANT! When a user asks you to add a resource to the app model you should first use the _list integrations_ tool to get a list of the current versions of all the available integrations. You should try to use the version of the integration which aligns with the version of the Aspire.AppHost.Sdk. Some integration versions may have a preview suffix. Once you have identified the correct integration you should always use the _get integration docs_ tool to fetch the latest documentation for the integration and follow the links to get additional guidance.

## Debugging issues
IMPORTANT! Aspire is designed to capture rich logs and telemetry for all resources defined in the app model. Use the following diagnostic tools when debugging issues with the application before making changes to make sure you are focusing on the right things.

1. _list structured logs_; use this tool to get details about structured logs.
2. _list console logs_; use this tool to get details about console logs.
3. _list traces_; use this tool to get details about traces.
4. _list trace structured logs_; use this tool to get logs related to a trace

## Other Aspire MCP tools

1. _select apphost_; use this tool if working with multiple app hosts within a workspace.
2. _list apphosts_; use this tool to get details about active app hosts.

## Playwright MCP server

The playwright MCP server has also been configured in this repository and you should use it to perform functional investigations of the resources defined in the app model as you work on the codebase. To get endpoints that can be used for navigation using the playwright MCP server use the list resources tool.

## Updating the app host
The user may request that you update the Aspire apphost. You can do this using the `aspire update` command. This will update the apphost to the latest version and some of the Aspire specific packages in referenced projects, however you may need to manually update other packages in the solution to ensure compatibility. You can consider using the `dotnet-outdated` with the users consent. To install the `dotnet-outdated` tool use the following command:

```
dotnet tool install --global dotnet-outdated-tool
```

## Persistent containers
IMPORTANT! Consider avoiding persistent containers early during development to avoid creating state management issues when restarting the app.

## Aspire workload
IMPORTANT! The aspire workload is obsolete. You should never attempt to install or use the Aspire workload.

## Official documentation
IMPORTANT! Always prefer official documentation when available. The following sites contain the official documentation for Aspire and related components

1. https://aspire.dev
2. https://learn.microsoft.com/dotnet/aspire
3. https://nuget.org (for specific integration package details)

## Available tools
Below is a concise list of repository-level tools and agent-facing utilities you can use when working in this repo.

- **Aspire** (primary orchestrator) — run with `aspire run`. Useful commands / MCP tools include:
  - `aspire run`, `aspire update`
  - `list resources`, `execute resource command`
  - `list integrations`, `get integration docs`
  - `list structured logs`, `list console logs`, `list traces`, `list trace structured logs`
  - `select apphost`, `list apphosts`
  - AppHost is defined in `apphost.cs` (see `services/aspire/AppHost`). The repo includes a wrapper `tools/aspire.cmd` which launches Aspire detached and writes logs to `aspire.log` in the workspace root.

- **Playwright / E2E** — frontend E2E tests live in `apps/web` and are run via `playwright test` (npm script `test:e2e`). Playwright reports are stored at `apps/web/playwright-report/`. There is also a Playwright MCP server configured for functional investigations.

- **Repository scripts** (see `scripts/`) — high-level helpers such as `scripts/run-tests.ps1` (runs all test suites and is required to be executed before marking features complete), `run-migrations.ps1`, `start-workers.ps1`, `smoke-test.ps1`, etc.

- **GitHub Actions & custom actions** — there are many reusable actions under `.github/actions/` (examples: `run-playwright-tests`, `run-pytest`, `run-ruff-check`, `docker-build-push`). Check that folder for action implementations and usage patterns.

- **CI / Docker & Terraform** — `docker-compose.ci.yml` and workflows in `.github/workflows/` are used by CI for building images and running tests. Terraform manifests live in `infra/terraform/` (providers, modules, environments). Common CI-related actions include `terraform-plan`, `validate-argocd-paths`, `verify-azure-credentials`, `record-test-duration`, and others under `.github/actions/`.

- **Kubernetes & Argo CD** — Kubernetes manifests and base overlays live under `k8s/`, `base/`, and `overlays/`. The preview deploy flow (see `.github/workflows/preview.yml`) updates a Kustomize overlay with PR-specific image tags, commits the overlay, and relies on Argo CD to pick up and apply changes.
  - K8s tooling available in actions: `setup-kustomize`, `kustomize-validate`, `get-aks-ingress-ip`, `wait-for-argocd-sync`, and `azure/aks-set-context` (used to set AKS context in workflows).
  - Helm is used in Terraform provider configuration for managing Argo CD and other charts (see `infra/terraform/providers.tf`).

- **Developer helper tools** — the repo references auxiliary tools such as `dotnet-outdated` (suggested for apphost upgrades). Install as needed, e.g. `dotnet tool install --global dotnet-outdated-tool`.

- **GitHub CLI (`gh`)** — available in the environment and recommended for repository automation and agent tasks (creating PRs, viewing runs, posting comments). AI agents and automation may safely invoke `gh` to interact with GitHub resources from this workspace.

> **Note:** This is a concise reference — for usage examples and caveats see the sections above (Aspire guidance, Playwright notes) and the specific scripts/actions referenced.

## Test Enforcement

**CRITICAL: Before marking ANY task as [X] complete, you MUST run the test script:**

```powershell
.\scripts\run-tests.ps1
```

This script runs ALL test suites (Shared, Workers, API, Frontend, E2E) and outputs a PASS/FAIL result.

### Options:
```powershell
# Run ALL tests (default - includes E2E, requires Aspire)
.\scripts\run-tests.ps1

# Skip E2E for faster development iteration
.\scripts\run-tests.ps1 -SkipE2E

# Run specific component only
.\scripts\run-tests.ps1 -Component api
```

### Rules:
1. **NEVER mark a task [X] if tests fail**
2. **NEVER rationalize skipping E2E tests** - they catch integration issues that unit tests miss
3. **If Aspire isn't running, the script will start it automatically**
4. **Unit tests alone are NOT sufficient** - E2E tests are required for completion verification

### What the tests check:
- Shared package tests (pytest)
- Worker tests (pytest, 98+ tests)
- API tests (pytest, 470+ tests)
- Frontend tests (Vitest, 246+ tests)
- E2E tests (Playwright) - **This is the integration layer that catches real bugs**

### Why this matters:
Unit tests verify individual components work in isolation. E2E tests verify the **actual user experience** with real services running. A feature is NOT complete until both pass.
