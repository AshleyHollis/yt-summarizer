#!/bin/bash

################################################################################
# Action: scan-javascript-dependencies / script.sh
#
# Purpose: Scan JavaScript/TypeScript for missing dependencies, unused
#          packages, and security vulnerabilities (npm audit, depcheck).
#
# Inputs (Environment Variables):
#   WORKING_DIRECTORY   - Directory containing package.json (e.g., apps/web)
#   CHECK_MISSING_DEPS  - Check for missing dependencies (default: true)
#   CHECK_SECURITY      - Run npm audit for security vulnerabilities
#   AUDIT_LEVEL         - Minimum severity level (low, moderate, high, critical)
#
# Outputs:
#   Exit code 0 - All checks passed
#   Exit code 1 - Validation failed
#
# Logic Flow:
#   1. Install depcheck tool globally
#   2. Run depcheck for missing/unused dependencies (if enabled)
#   3. Run npm audit for security vulnerabilities (if enabled)
#   4. Check peer dependencies tree
#   5. Report summary of checks performed
#
################################################################################

set -euo pipefail

WORKING_DIR="${WORKING_DIRECTORY:-.}"
CHECK_MISSING="${CHECK_MISSING_DEPS:-true}"
CHECK_SECURITY="${CHECK_SECURITY:-true}"
AUDIT_LEVEL="${AUDIT_LEVEL:-high}"

cd "$WORKING_DIR"

# Install scanning tools
echo "Installing scanning tools..."
npm install -g depcheck

# Check for missing dependencies with depcheck
if [ "$CHECK_MISSING" = "true" ]; then
  echo "════════════════════════════════════════════════════════════════"
  echo "🔍 JavaScript Dependency Scan (depcheck)"
  echo "════════════════════════════════════════════════════════════════"
  echo ""
  echo "ℹ️  Using .depcheckrc configuration file"
  echo "   See .depcheckrc.md for documentation on ignored packages"
  echo ""

  # Run depcheck (automatically uses .depcheckrc config file)
  if depcheck; then
    echo ""
    echo "✅ No dependency issues detected"
  else
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    echo "❌ DEPENDENCY ISSUES DETECTED"
    echo "════════════════════════════════════════════════════════════════"
    echo ""
    echo "📋 Action Required:"
    echo "   1. Review the packages listed above"
    echo "   2. Run 'npx depcheck' locally to verify"
    echo "   3. If genuinely unused, remove from package.json"
    echo "   4. If used but undetectable (config files, CSS), add to"
    echo "      .depcheckrc and document in .depcheckrc.md"
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    exit 1
  fi
fi

# Run npm audit for security vulnerabilities
if [ "$CHECK_SECURITY" = "true" ]; then
  echo ""
  echo "════════════════════════════════════════════════════════════════"
  echo "🔒 Security Vulnerability Scan (npm audit)"
  echo "════════════════════════════════════════════════════════════════"
  echo ""

  if npm audit --audit-level="$AUDIT_LEVEL"; then
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
    echo "   2. Run 'npm audit fix' to auto-fix where possible"
    echo "   3. For breaking changes, use 'npm audit fix --force'"
    echo "   4. Update package.json for manual updates"
    echo ""
    echo "════════════════════════════════════════════════════════════════"
    exit 1
  fi
fi

# Verify no missing peer dependencies
echo ""
echo "🔍 Checking peer dependencies..."
if npm ls --depth=0; then
  echo ""
  echo "✅ Peer dependencies are satisfied"
else
  echo ""
  echo "⚠️  Peer dependency issues detected"
  exit 1
fi

echo ""
echo "✅ JavaScript dependency scan complete"
