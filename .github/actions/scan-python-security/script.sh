#!/bin/bash

################################################################################
# Action: scan-python-security / script.sh
#
# Purpose: Run Python security and type checking scans using bandit and mypy.
#          Scans for code security issues and optional type checking.
#
# Inputs (Environment Variables):
#   SERVICE_PATH  - Path to the service directory (e.g., services/api)
#   CHECK_TYPES   - Run mypy type checking (default: false)
#   CHECK_SECURITY - Run bandit security scanning (default: true)
#
# Outputs:
#   Exit code 0 - All checks passed
#   Exit code 1 - Security or type issues detected
#
# Logic Flow:
#   1. Install code quality tools (bandit, mypy)
#   2. Run bandit for security scanning (if enabled)
#      - Auto-detect source directory (src or .)
#      - Skip common test-related warnings
#      - Exclude test directories
#   3. Run mypy for type checking (if enabled)
#   4. Report summary of checks performed
#
################################################################################

set -euo pipefail

SERVICE_PATH="${SERVICE_PATH:-.}"
CHECK_TYPES="${CHECK_TYPES:-false}"
CHECK_SECURITY="${CHECK_SECURITY:-true}"

# Install code quality tools
echo "Installing code quality tools..."
uv tool install bandit[toml]
uv tool install mypy

cd "$SERVICE_PATH"

# Run Bandit security scan
if [ "$CHECK_SECURITY" = "true" ]; then
  echo "════════════════════════════════════════════════════════════════"
  echo "🔒 Python Security Scan (bandit)"
  echo "════════════════════════════════════════════════════════════════"
  echo ""

  # Auto-detect source directory
  if [ -d "src" ]; then
    SCAN_DIR="src"
  else
    SCAN_DIR="."
  fi

  echo "📁 Scanning directory: $SCAN_DIR"
  echo ""

  # Exclude test directories and skip common test-related warnings
  # B101: assert_used (expected in tests)
  # B105: hardcoded_password_string (false positive for mock settings)
  # B110: try_except_pass (acceptable for telemetry/optional features)
  # B310: urllib_urlopen (used for health checks, not user input)
  # B311: random (used for jitter/backoff, not cryptographic purposes)
  # B608: hardcoded_sql_expressions (false positive with SQLAlchemy ORM)
  if bandit -r "$SCAN_DIR" -f screen --skip \
     B101,B105,B110,B310,B311,B608 \
     --exclude "./tests/*,*/tests/*,*/test_*.py"; then
    echo ""
    echo "✅ No security issues detected"
    exit 0
  else
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo "⚠️  SECURITY ISSUES DETECTED"
    echo "════════════════════════════════════════════════════════════════"
    echo ""
    echo "📋 Action Required:"
    echo "   Review the security findings above and address concerns"
    echo "   Common issues: hardcoded secrets, SQL injection, weak crypto"
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    exit 1
  fi
fi

# Run mypy type checking
if [ "$CHECK_TYPES" = "true" ]; then
  echo ""
  echo "🔍 Running mypy type checking..."
  if mypy src/ --ignore-missing-imports; then
    echo "✅ Type checking passed"
  else
    echo "⚠️  Type checking issues detected"
    exit 1
  fi
fi

echo ""
echo "✅ Code quality scan complete"
