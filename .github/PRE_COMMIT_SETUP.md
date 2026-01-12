# Pre-commit Setup Guide

## Installation

### For Developers

1. **Install pre-commit** (one-time setup):
   ```powershell
   pip install pre-commit
   ```

2. **Install the git hook scripts** (in repo root):
   ```powershell
   pre-commit install
   ```

3. **Test it works**:
   ```powershell
   pre-commit run --all-files
   ```

## What It Does

The pre-commit hooks automatically run before each commit to:

- ✅ **Check YAML syntax** - Validates all YAML files (including GitHub Actions workflows)
- ✅ **Lint workflows** - Runs `actionlint` on `.github/workflows/*.yml` files
- ✅ **Check JSON syntax** - Validates JSON files
- ✅ **Fix formatting** - Removes trailing whitespace, ensures files end with newline

## Usage

### Normal Commits

Once installed, hooks run automatically:

```powershell
git add .
git commit -m "your message"
# Hooks run automatically before commit
```

If a hook fails, the commit is blocked. Fix the issues and try again.

### Skip Hooks (Emergency Only)

To bypass hooks (not recommended):

```powershell
git commit -m "your message" --no-verify
```

⚠️ **Warning**: Skipping hooks may cause CI failures.

### Manual Run

Run hooks on all files without committing:

```powershell
pre-commit run --all-files
```

Run hooks on specific files:

```powershell
pre-commit run --files .github/workflows/ci.yml
```

### Update Hooks

Update hook versions:

```powershell
pre-commit autoupdate
```

## Troubleshooting

### "command not found: actionlint"

Pre-commit will automatically download actionlint on first run. Just wait for it to complete.

### YAML validation fails on Kubernetes files

Kubernetes manifests with templates/overlays are excluded via the config. If you need to validate them separately, use:

```powershell
kubectl apply --dry-run=client -f k8s/
```

### Hook takes too long

Hooks only run on **staged files** by default. To speed up:

```powershell
git add specific-file.yml  # Only stage what you need
git commit
```

## Configuration

Edit `.pre-commit-config.yaml` to:
- Add/remove hooks
- Change validation rules
- Exclude additional files

See: https://pre-commit.com/
