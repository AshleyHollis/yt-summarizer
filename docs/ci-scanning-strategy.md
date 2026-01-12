# Automated Code Quality & Dependency Scanning

This repository uses automated scanning tools to catch common issues early in the CI pipeline, before they reach production.

## Overview

All scanning is implemented as **composite actions** with no inline code in workflow files. This ensures:
- **Reusability**: Same scans can be run in multiple workflows
- **Maintainability**: Update scanning logic in one place
- **Testability**: Composite actions can be tested independently
- **Clarity**: Workflow files remain declarative and easy to read

## Scanning Tools by Language

### Python (API, Workers, Shared)

#### 1. **deptry** - Dependency Validator
- **What it catches**: Missing dependencies, unused dependencies
- **When**: Before running tests
- **Config**: `[tool.deptry]` in `pyproject.toml`
- **Action**: `.github/actions/validate-python-dependencies`

**Example issues caught**:
- ✅ Package imported but not in `pyproject.toml`
- ✅ Package in `pyproject.toml` but never imported
- ✅ Transitive dependencies used directly

#### 2. **pip-audit** - Security Scanner
- **What it catches**: Known vulnerabilities in dependencies
- **When**: Before running tests
- **Config**: None required (uses OSV database)
- **Action**: `.github/actions/validate-python-dependencies`

**Example issues caught**:
- ✅ CVEs in installed packages
- ✅ Outdated packages with known exploits

#### 3. **bandit** - Security Code Scanner
- **What it catches**: Common security anti-patterns
- **When**: Before running tests
- **Config**: `[tool.bandit]` in `pyproject.toml`
- **Action**: `.github/actions/scan-python-quality`

**Example issues caught**:
- ✅ Hardcoded passwords/secrets
- ✅ SQL injection vulnerabilities
- ✅ Use of insecure functions (pickle, eval, exec)
- ✅ Weak cryptography

#### 4. **ruff** - Fast Python Linter
- **What it catches**: Code style, bugs, complexity
- **When**: In lint-python job
- **Config**: `[tool.ruff]` in `pyproject.toml`
- **Action**: `.github/actions/run-ruff-check`

**Example issues caught**:
- ✅ Unused imports
- ✅ Undefined variables
- ✅ Import order violations
- ✅ Code complexity issues

#### 5. **pytest** - Unit Tests with Dependency Checks
- **What it catches**: Missing critical dependencies at import time
- **When**: In test jobs
- **Config**: `[tool.pytest]` in `pyproject.toml`
- **Tests**: `services/api/tests/test_agents.py::TestCriticalDependencies`

**Example issues caught**:
- ✅ Critical packages missing (agent-framework-ag-ui)
- ✅ Import errors at module load time

### JavaScript/TypeScript (Frontend)

#### 1. **depcheck** - Dependency Validator
- **What it catches**: Missing dependencies, unused dependencies
- **When**: Before running tests
- **Config**: Inline options in composite action
- **Action**: `.github/actions/scan-javascript-dependencies`

**Example issues caught**:
- ✅ Package imported but not in `package.json`
- ✅ Package in `package.json` but never imported

#### 2. **npm audit** - Security Scanner
- **What it catches**: Known vulnerabilities in npm packages
- **When**: Before running tests
- **Config**: `--audit-level` in composite action
- **Action**: `.github/actions/scan-javascript-dependencies`

**Example issues caught**:
- ✅ CVEs in npm packages
- ✅ Transitive dependency vulnerabilities

#### 3. **ESLint** - JavaScript/TypeScript Linter
- **What it catches**: Code quality, bugs, best practices
- **When**: In lint-frontend job
- **Config**: `eslint.config.mjs`
- **Action**: Inline in workflow (to be converted to composite action)

### Kubernetes Manifests

#### 1. **Kustomize Validation**
- **What it catches**: Invalid YAML, missing resources
- **When**: When k8s/ changes
- **Action**: `.github/actions/kustomize-validate`

## CI Pipeline Flow

```
┌─────────────────────────────────────────┐
│ 1. Checkout & Setup                     │
│    - Clone repo                          │
│    - Setup Python/Node                   │
│    - Install dependencies                │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│ 2. Dependency Validation                │
│    ✓ deptry (Python)                    │
│    ✓ depcheck (JavaScript)              │
│    ✓ pip-audit (Python security)        │
│    ✓ npm audit (JavaScript security)    │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│ 3. Code Quality Scanning                │
│    ✓ bandit (Python security)           │
│    ✓ ruff (Python linting)              │
│    ✓ ESLint (JavaScript linting)        │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│ 4. Unit Tests                           │
│    ✓ pytest (with critical dep tests)  │
│    ✓ Vitest                             │
└──────────────┬──────────────────────────┘
               │
┌──────────────▼──────────────────────────┐
│ 5. Build & Deploy                       │
│    (Only if all scans pass)             │
└─────────────────────────────────────────┘
```

## Configuration Files

| Tool | Config File | Location |
|------|------------|----------|
| deptry | `[tool.deptry]` | `services/*/pyproject.toml` |
| pip-audit | N/A (uses OSV DB) | - |
| bandit | `[tool.bandit]` | `services/*/pyproject.toml` |
| ruff | `[tool.ruff]` | `services/ruff.toml` |
| pytest | `[tool.pytest]` | `services/*/pyproject.toml` |
| depcheck | Inline args | `.github/actions/scan-javascript-dependencies/action.yml` |
| npm audit | `--audit-level` | `.github/actions/scan-javascript-dependencies/action.yml` |
| ESLint | `eslint.config.mjs` | `apps/web/eslint.config.mjs` |

## Adding New Scans

### For Python Services

1. **Add tool to composite action** (if needed):
   ```yaml
   # .github/actions/validate-python-dependencies/action.yml
   - name: Install scanning tools
     run: pip install deptry pip-audit <new-tool>
   ```

2. **Add scan step**:
   ```yaml
   - name: Run new scan
     run: <new-tool> <args>
   ```

3. **Add config** (if needed):
   ```toml
   # services/*/pyproject.toml
   [tool.newtool]
   option = "value"
   ```

4. **Use in workflow**:
   ```yaml
   # .github/workflows/ci.yml
   - name: Validate Python dependencies
     uses: ./.github/actions/validate-python-dependencies
     with:
       service-path: services/api
   ```

### For JavaScript/TypeScript

Follow the same pattern using `.github/actions/scan-javascript-dependencies`.

## Cost & Performance

All tools used are:
- ✅ **Free & Open Source**
- ✅ **Fast** (< 30 seconds per service)
- ✅ **Actively Maintained**
- ✅ **No External API Keys Required**

## Why This Approach Works

1. **Defense in Depth**: Multiple layers catch different types of issues
2. **Shift Left**: Catch issues in CI before they reach production
3. **Fast Feedback**: Scans run in parallel with tests
4. **Developer Friendly**: Clear error messages with fix suggestions
5. **Zero Configuration**: Works out of the box for new services
6. **Composable**: Mix and match scans as needed

## Real-World Impact

**Before this approach**:
- ❌ Missing dependency deployed to production (agent-framework-ag-ui)
- ❌ Tests skipped when dependencies missing
- ❌ No security scanning
- ❌ Manual code review only defense

**After this approach**:
- ✅ CI fails if critical dependencies missing
- ✅ Security vulnerabilities caught before merge
- ✅ Unused dependencies cleaned up automatically
- ✅ Multiple automated checks run on every commit

## Maintenance

### Updating Tools

Tools are pinned in composite actions. To update:

```bash
# Update in composite action
pip install --upgrade deptry pip-audit bandit

# Test locally
deptry services/api/src
pip-audit services/api
bandit -r services/api/src

# Update version in action if needed
```

### Adding Exceptions

When a scan reports a false positive:

1. **Document why it's a false positive**
2. **Add to ignore list in config**
3. **Link to tracking issue**

Example:
```toml
[tool.deptry.per_rule_ignores]
# DEP002: azure is a namespace package with many subpackages
# Tracking: https://github.com/example/repo/issues/123
DEP002 = ["azure", "opentelemetry"]
```

## Further Reading

- [deptry documentation](https://deptry.com/)
- [pip-audit documentation](https://pypi.org/project/pip-audit/)
- [bandit documentation](https://bandit.readthedocs.io/)
- [depcheck documentation](https://github.com/depcheck/depcheck)
- [npm audit documentation](https://docs.npmjs.com/cli/v8/commands/npm-audit)
