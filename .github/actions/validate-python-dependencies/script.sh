#!/bin/bash

################################################################################
# Action: validate-python-dependencies / script.sh
#
# Purpose: Scan Python dependencies for missing, unused, and vulnerable
#          packages using industry-standard tools (deptry, pip-audit).
#
# Inputs (Environment Variables):
#   SERVICE_PATH        - Path to the service directory (e.g., services/api)
#   CHECK_MISSING       - Check for missing dependencies (default: true)
#   CHECK_UNUSED        - Check for unused dependencies (default: false)
#   CHECK_SECURITY      - Check for security vulnerabilities (default: true)
#   FAIL_ON_WARNINGS    - Fail if warnings are found (default: false)
#
# Outputs:
#   Exit code 0 - All checks passed
#   Exit code 1 - Validation failed
#
# Logic Flow:
#   1. Install scanning tools (deptry, pip-audit, pipdeptree)
#   2. Display dependency tree (first 50 lines)
#   3. Run deptry for missing dependencies (if enabled)
#   4. Run deptry for unused dependencies (if enabled)
#   5. Run pip-audit for security vulnerabilities (if enabled)
#   6. Report summary of checks performed
#
################################################################################

set -euo pipefail

SERVICE_PATH="${SERVICE_PATH:-.}"
CHECK_MISSING="${CHECK_MISSING:-true}"
CHECK_UNUSED="${CHECK_UNUSED:-false}"
CHECK_SECURITY="${CHECK_SECURITY:-true}"
FAIL_ON_WARNINGS="${FAIL_ON_WARNINGS:-false}"

# Install dependency scanning tools
echo "Installing dependency scanning tools..."
uv tool install deptry
uv tool install pip-audit
uv tool install pipdeptree

cd "$SERVICE_PATH"

# Display dependency tree
echo "════════════════════════════════════════════════════════════════"
echo "📦 Dependency Tree (pipdeptree - first 50 lines)"
echo "════════════════════════════════════════════════════════════════"
echo ""
pipdeptree --python "$(which python)" 2>/dev/null | head -n 50 || true
echo ""
echo "(Output truncated for readability)"
echo ""

# Check for missing dependencies with deptry
if [ "$CHECK_MISSING" = "true" ]; then
  echo "════════════════════════════════════════════════════════════════"
  echo "🔍 Scanning for Missing Dependencies (deptry)"
  echo "════════════════════════════════════════════════════════════════"
  echo ""

  # Auto-detect source directory
  if [ -d "src" ]; then
    SRC_DIR="src"
  else
    SRC_DIR="."
  fi

  echo "📁 Source directory: $SRC_DIR"
  echo ""

  # Ignore DEP003 (transitive dependencies) for editable local packages
  # Ignore DEP002 (unused deps) for dev/test/infrastructure packages
  if deptry "$SRC_DIR" --extend-exclude "test.*" --ignore DEP003,DEP002; then
    echo ""
    echo "✅ No missing dependencies detected"
  else
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo "❌ MISSING DEPENDENCIES DETECTED"
    echo "════════════════════════════════════════════════════════════════"
    echo ""
    echo "📋 Action Required:"
    echo "   Add the packages listed above to pyproject.toml"
    echo "   under [project.dependencies]"
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    if [ "$FAIL_ON_WARNINGS" = "true" ]; then
      exit 1
    fi
  fi
fi

# Check for unused dependencies with deptry
if [ "$CHECK_UNUSED" = "true" ]; then
  echo ""
  echo "🔍 Scanning for unused dependencies..."
  if deptry src --extend-exclude "test.*" --ignore-obsolete DEP004; then
    echo "✅ No unused dependencies detected"
  else
    echo "⚠️  UNUSED DEPENDENCIES DETECTED"
    echo "Consider removing unused packages from pyproject.toml"
    if [ "$FAIL_ON_WARNINGS" = "true" ]; then
      exit 1
    fi
  fi
fi

# Check for security vulnerabilities with pip-audit
if [ "$CHECK_SECURITY" = "true" ]; then
  echo ""
  echo "════════════════════════════════════════════════════════════════"
  echo "🔒 Security Vulnerability Scan (pip-audit)"
  echo "════════════════════════════════════════════════════════════════"
  echo ""

  if pip-audit --desc; then
    echo ""
    echo "✅ No security vulnerabilities detected"
  else
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo "⚠️  SECURITY VULNERABILITIES FOUND"
    echo "════════════════════════════════════════════════════════════════"
    echo ""
    echo "📋 Action Required:"
    echo "   1. Review the vulnerability report above"
    echo "   2. Update affected packages in pyproject.toml"
    echo "   3. Run 'uv sync' to update lock file"
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    if [ "$FAIL_ON_WARNINGS" = "true" ]; then
      exit 1
    fi
  fi
fi

echo ""
echo "✅ Dependency validation complete"
echo "Checks performed:"
echo "  - Missing dependencies: $CHECK_MISSING"
echo "  - Unused dependencies: $CHECK_UNUSED"
echo "  - Security vulnerabilities: $CHECK_SECURITY"
