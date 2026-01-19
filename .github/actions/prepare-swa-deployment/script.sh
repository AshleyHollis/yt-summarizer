#!/bin/bash
# =============================================================================
# Prepare Web App for SWA Deployment
# =============================================================================
# PURPOSE:
#   Removes unnecessary files from apps/web before SWA upload to reduce size
#   and deployment time. Keeps only what's needed for Next.js hybrid rendering.
#
# WHAT WE KEEP:
#   - .next/ (built application)
#   - next.config.ts (required for SWA to detect Next.js)
#   - package.json (required for dependency info)
#   - staticwebapp.config.json (SWA configuration)
#   - public/ (static assets served directly)
#
# WHAT WE REMOVE:
#   - src/ (source code, not needed for runtime)
#   - node_modules/ (SWA doesn't need this, .next/standalone has minimal deps)
#   - e2e/, scripts/, __tests__/ (test files)
#   - *.md files (documentation)
#   - Config files not needed for runtime
#
# USAGE:
#   ./prepare-swa-deployment.sh
#
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEB_DIR="$SCRIPT_DIR/../../apps/web"

echo "🧹 Cleaning apps/web for SWA deployment..."
cd "$WEB_DIR"

# Remove source files (not needed, only .next matters)
echo "  ├─ Removing src/"
rm -rf src/

# Remove node_modules (huge, not needed - .next/standalone has minimal deps)
echo "  ├─ Removing node_modules/"
rm -rf node_modules/

# Remove test files and directories
echo "  ├─ Removing test files..."
rm -rf e2e/ __tests__/ scripts/ test-results/ coverage/ playwright-report/ blob-report/ playwright/.cache/

# Remove documentation
echo "  ├─ Removing *.md files..."
find . -maxdepth 1 -name "*.md" -delete || true

# Remove config files not needed for runtime
echo "  ├─ Removing unnecessary config files..."
rm -f tsconfig.json tailwind.config.ts postcss.config.mjs vitest.config.ts \
      playwright.config.ts eslint.config.mjs .prettierrc .prettierignore \
      .eslintignore .env.example .gitignore

# Remove cache directories
echo "  ├─ Removing cache directories..."
rm -rf .next/cache/ .next/trace/ .next/trace-build/ .turbo/ .vercel/

# Show what's left
echo "✅ Cleanup complete. Remaining structure:"
du -sh .next/ public/ 2>/dev/null | sed 's/^/  /'
ls -lah | grep -E "^(total|d|-.*\.(json|ts|js)$)" | sed 's/^/  /'

echo ""
echo "📊 Total size:"
du -sh . | sed 's/^/  /'
